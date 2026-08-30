"""Tests for common preprocessing and independent dataset adapters."""

from __future__ import annotations

import socket
import hashlib
from pathlib import Path

import dpkt
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from pydantic import ValidationError

from src.datasets.base import PreprocessedRecord
from src.datasets.registry import create_adapter
from src.label_mapping import load_class_mapping
from src.preprocess import preprocess_dataset
from src.prepare_evaluation_data import prepare_evaluation_datasets
from src.features import FeatureExtractionConfig


MAPPING_PATH = Path(__file__).resolve().parents[1] / "config" / "class_mapping.yaml"


def partial_record(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "dataset_source": "sample",
        "capture_id": None,
        "source_record_id": "row:1",
        "original_label": "BROWSING",
        "canonical_label": "web",
        "split_group_id": "sample:file",
        "excluded_leakage_columns": ["label"],
        "duration": 1.0,
    }
    values.update(updates)
    return values


def write_two_packet_capture(path: Path, pcapng: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as file:
        writer = dpkt.pcapng.Writer(file) if pcapng else dpkt.pcap.Writer(file)
        for timestamp, source, destination, source_port, destination_port in (
            (1.0, "10.0.0.1", "10.0.0.2", 5000, 443),
            (1.5, "10.0.0.2", "10.0.0.1", 443, 5000),
        ):
            udp = dpkt.udp.UDP(sport=source_port, dport=destination_port, data=b"payload")
            udp.ulen = len(udp)
            ip = dpkt.ip.IP(
                src=socket.inet_aton(source),
                dst=socket.inet_aton(destination),
                p=dpkt.ip.IP_PROTO_UDP,
                data=udp,
            )
            ip.len = len(ip)
            ethernet = dpkt.ethernet.Ethernet(
                src=b"\x00\x01\x02\x03\x04\x05",
                dst=b"\x06\x07\x08\x09\x0a\x0b",
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
            writer.writepkt(bytes(ethernet), ts=timestamp)
        writer.close()


def write_two_packet_esp_capture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as file:
        writer = dpkt.pcap.Writer(file)
        for timestamp, source, destination, spi in (
            (1.0, "10.0.0.1", "10.0.0.2", 0x11111111),
            (1.5, "10.0.0.2", "10.0.0.1", 0x22222222),
        ):
            payload = spi.to_bytes(4, "big") + b"encrypted-esp-metadata-only"
            ip = dpkt.ip.IP(
                src=socket.inet_aton(source),
                dst=socket.inet_aton(destination),
                p=dpkt.ip.IP_PROTO_ESP,
                data=payload,
            )
            ip.len = len(ip)
            ethernet = dpkt.ethernet.Ethernet(
                src=b"\x00\x01\x02\x03\x04\x05",
                dst=b"\x06\x07\x08\x09\x0a\x0b",
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
            writer.writepkt(bytes(ethernet), ts=timestamp)
        writer.close()


def test_common_record_keeps_unavailable_features_null() -> None:
    record = PreprocessedRecord.model_validate(partial_record())

    assert record.duration == 1.0
    assert record.packet_count is None
    assert record.p95_packet_size is None


@pytest.mark.parametrize(
    "updates",
    [
        {"duration": -1.0},
        {"idle_time_ratio": 1.1},
        {"canonical_label": "malware"},
        {"capture_id": None, "source_record_id": None},
    ],
)
def test_common_record_rejects_invalid_ranges_and_metadata(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        PreprocessedRecord.model_validate(partial_record(**updates))


def test_cic_vpn_csv_adapter_preserves_labels_and_nulls(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    external_root.mkdir()
    csv_path = external_root / "consolidated_traffic_data.csv"
    csv_path.write_text(
        "duration,flowPktsPerSecond,flowBytesPerSecond,mean_flowiat,std_flowiat,traffic_type\n"
        "2000000,4,800,500000,100000,BROWSING\n"
        "2000000,4,800,500000,100000,STREAMING\n",
        encoding="utf-8",
    )
    adapter = create_adapter("cic-vpn2016", external_root, load_class_mapping(MAPPING_PATH))

    records = list(adapter.iter_records())

    assert len(records) == 1
    assert records[0].original_label == "BROWSING"
    assert records[0].canonical_label == "web"
    assert records[0].duration == 2.0
    assert records[0].packet_count is None
    assert records[0].excluded_leakage_columns == ["traffic_type"]
    assert sum(adapter.skipped_reasons.values()) == 1


def test_cic_darknet_status_labels_emit_no_application_records(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    external_root.mkdir()
    pq.write_table(
        pa.Table.from_pylist([{"Label": "VPN"}, {"Label": "Tor"}]),
        external_root / "cicdarknet2020.parquet",
    )
    adapter = create_adapter("cic-darknet2020", external_root, load_class_mapping(MAPPING_PATH))

    assert list(adapter.iter_records()) == []
    assert sum(adapter.skipped_reasons.values()) == 2


def test_network_capture_adapter_uses_path_label_only_as_metadata(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    capture = external_root / "Network-Traffic-Dataset" / "Skype" / "Skype_1.pcap"
    write_two_packet_capture(capture)
    adapter = create_adapter(
        "network-traffic-dataset", external_root, load_class_mapping(MAPPING_PATH)
    )

    records = list(adapter.iter_records())

    assert len(records) == 1
    record = records[0]
    assert record.original_label == "Skype"
    assert record.canonical_label == "voip"
    assert record.capture_id == "Skype/Skype_1.pcap"
    assert record.split_group_id.endswith("Skype/Skype_1.pcap")
    assert record.packet_count == 2
    assert record.burst_count is None
    assert all("10.0.0" not in value for value in record.excluded_leakage_columns)


def test_ustc_adapter_reads_pcapng_and_ignores_malware(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    gmail = external_root / "USTC-TFC2016" / "Benign" / "Gmail.pcapng"
    write_two_packet_capture(gmail, pcapng=True)
    malware = external_root / "USTC-TFC2016" / "Malware" / "Cridex" / "Cridex.pcap"
    malware.parent.mkdir(parents=True)
    malware.write_bytes(b"not parsed because the label is IGNORE")
    adapter = create_adapter("ustc-tfc2016", external_root, load_class_mapping(MAPPING_PATH))

    records = list(adapter.iter_records())

    assert len(records) == 1
    assert records[0].original_label == "Gmail"
    assert records[0].canonical_label == "email"
    assert any("Cridex" in reason for reason in adapter.skipped_reasons)


def test_ipsec_lab_uses_metadata_label_and_only_esp_windows(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    lab = external_root / "ipsec-pcap-lab"
    capture = lab / "pcaps" / "opaque-name.pcap"
    write_two_packet_esp_capture(capture)
    checksum = hashlib.sha256(capture.read_bytes()).hexdigest()
    lab.joinpath("metadata.csv").write_text(
        "sample_id,pcap_file,traffic_class,mode,sha256\n"
        f"sample-1,opaque-name.pcap,ping,tunnel,{checksum}\n",
        encoding="utf-8",
    )
    adapter = create_adapter("ipsec-pcap-lab", external_root, load_class_mapping(MAPPING_PATH))

    records = list(adapter.iter_records())

    assert len(records) == 1
    assert records[0].original_label == "ping"
    assert records[0].canonical_label == "icmp"
    assert records[0].packet_count == 2
    assert records[0].burst_count == 2
    assert records[0].split_group_id == "ipsec-pcap-lab:sample-1"


def test_ipsec_lab_reads_nested_known_records_and_excludes_evaluation_roles(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    lab = external_root / "ipsec-pcap-lab"
    known = lab / "pcaps" / "known" / "email" / "capture.pcap"
    ood = lab / "pcaps" / "ood" / "dns.pcap"
    write_two_packet_esp_capture(known)
    write_two_packet_esp_capture(ood)
    known_hash = hashlib.sha256(known.read_bytes()).hexdigest()
    ood_hash = hashlib.sha256(ood.read_bytes()).hexdigest()
    lab.joinpath("metadata.csv").write_text(
        "sample_id,pcap_file,traffic_class,canonical_label,dataset_role,split,sha256\n"
        f"known-1,pcaps/known/email/capture.pcap,email,email,train_known,locked_test,{known_hash}\n"
        f"ood-1,pcaps/ood/dns.pcap,dns,IGNORE,ood_eval,,{ood_hash}\n",
        encoding="utf-8",
    )
    adapter = create_adapter("ipsec-pcap-lab", external_root, load_class_mapping(MAPPING_PATH))

    records = list(adapter.iter_records())

    assert len(records) == 1
    assert records[0].capture_id == "pcaps/known/email/capture.pcap"
    assert records[0].original_label == "email"
    assert records[0].canonical_label == "email"
    assert records[0].declared_split == "locked_test"
    assert any("non-supervised dataset_role" in reason for reason in adapter.skipped_reasons)


def test_ipsec_lab_rejects_path_traversal_in_manifest(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    lab = external_root / "ipsec-pcap-lab"
    lab.mkdir(parents=True)
    lab.joinpath("metadata.csv").write_text(
        "sample_id,pcap_file,traffic_class,sha256\n"
        "unsafe,pcaps/../secret.pcap,web,unused\n",
        encoding="utf-8",
    )
    adapter = create_adapter("ipsec-pcap-lab", external_root, load_class_mapping(MAPPING_PATH))

    assert list(adapter.iter_records()) == []
    assert any("unsafe pcap_file" in reason for reason in adapter.skipped_reasons)


def test_preprocess_writes_only_the_requested_dataset(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    output_dir = tmp_path / "processed"
    external_root.mkdir()
    (external_root / "consolidated_traffic_data.csv").write_text(
        "duration,flowPktsPerSecond,flowBytesPerSecond,mean_flowiat,std_flowiat,traffic_type\n"
        "1000000,2,300,400000,10000,MAIL\n",
        encoding="utf-8",
    )

    output_path = preprocess_dataset(
        "cic-vpn2016", external_root, output_dir, MAPPING_PATH
    )
    table = pq.read_table(output_path)

    assert output_path.name == "cic-vpn2016.parquet"
    assert table.num_rows == 1
    assert table.column("dataset_source").to_pylist() == ["cic-vpn2016"]
    assert table.column("canonical_label").to_pylist() == ["email"]
    assert not (output_dir / "cic-darknet2020.parquet").exists()


def test_prepares_ood_and_anomaly_evaluation_without_mixing_training(tmp_path: Path) -> None:
    dataset_root = tmp_path / "ipsec-pcap-lab"
    captures = {
        "pcaps/known/web.pcap": ("known", "web", "train_known", "locked_test", "false"),
        "pcaps/ood/dns.pcap": ("ood", "dns", "ood_eval", "", "false"),
        "pcaps/anomaly/flood.pcap": ("anomaly", "udp_flood", "anomaly_eval", "", "true"),
    }
    rows: list[str] = []
    for relative, (sample_id, label, role, split, is_anomaly) in captures.items():
        capture = dataset_root / relative
        write_two_packet_esp_capture(capture)
        checksum = hashlib.sha256(capture.read_bytes()).hexdigest()
        rows.append(
            f"{sample_id},{relative},{label},{role},{split},{checksum},{is_anomaly},flood"
        )
    dataset_root.joinpath("metadata.csv").write_text(
        "sample_id,pcap_file,traffic_class,dataset_role,split,sha256,is_anomaly,anomaly_type\n"
        + "\n".join(rows)
        + "\n",
        encoding="utf-8",
    )
    ood_output = tmp_path / "ood.parquet"
    anomaly_output = tmp_path / "anomaly.parquet"

    summary = prepare_evaluation_datasets(
        dataset_root,
        ood_output,
        anomaly_output,
        FeatureExtractionConfig(10.0, 0.1, 1.0),
    )

    assert summary == {
        "ood_records": 1,
        "anomaly_evaluation_records": 2,
        "anomaly_records": 1,
        "normal_records": 1,
        "skipped": {},
    }
    assert pq.read_table(ood_output).column("original_label").to_pylist() == ["dns"]
    assert pq.read_table(anomaly_output).column("is_anomaly").to_pylist() == [False, True]

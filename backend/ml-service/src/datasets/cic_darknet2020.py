"""Adapter for the CIC-Darknet2020-derived Parquet dataset."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pyarrow.parquet as pq

from src.datasets.base import DatasetAdapter, PreprocessedRecord, finite_float, non_negative_int


class CicDarknet2020Adapter(DatasetAdapter):
    """Convert CIC flow columns without treating Tor/VPN status as an app class."""

    cli_name = "cic-darknet2020"
    mapping_dataset_name = "cicdarknet2020.parquet"
    input_name = "cicdarknet2020.parquet"

    def _values(self, row: Mapping[str, Any], row_number: int, label: str) -> dict[str, Any]:
        upload_packets = non_negative_int(row["Total Fwd Packet"], "Total Fwd Packet")
        download_packets = non_negative_int(row["Total Bwd packets"], "Total Bwd packets")
        upload_bytes = non_negative_int(
            row["Total Length of Fwd Packet"], "Total Length of Fwd Packet"
        )
        download_bytes = non_negative_int(
            row["Total Length of Bwd Packet"], "Total Length of Bwd Packet"
        )
        return {
            "dataset_source": self.cli_name,
            "capture_id": None,
            "source_record_id": f"{self.input_path.name}:{row_number}",
            "original_label": str(row["Label"]),
            "canonical_label": label,
            # The public Parquet file has no capture/session provenance. Using
            # the source file as one conservative group prevents row leakage.
            "split_group_id": f"{self.cli_name}:{self.input_path.name}",
            "excluded_leakage_columns": ["Label", "Label.1"],
            "flow_id": None,
            "duration": finite_float(row["Flow Duration"], "Flow Duration") / 1_000_000,
            "packet_count": upload_packets + download_packets,
            "total_bytes": upload_bytes + download_bytes,
            "packets_per_second": finite_float(row["Flow Packets/s"], "Flow Packets/s"),
            "bytes_per_second": finite_float(row["Flow Bytes/s"], "Flow Bytes/s"),
            "mean_packet_size": finite_float(row["Avg Packet Size"], "Avg Packet Size"),
            "std_packet_size": finite_float(row["Packet Length Std"], "Packet Length Std"),
            "min_packet_size": finite_float(row["Packet Length Min"], "Packet Length Min"),
            "max_packet_size": finite_float(row["Packet Length Max"], "Packet Length Max"),
            "mean_interarrival_time": finite_float(row["Flow IAT Mean"], "Flow IAT Mean")
            / 1_000_000,
            "std_interarrival_time": finite_float(row["Flow IAT Std"], "Flow IAT Std")
            / 1_000_000,
            "upload_packets": upload_packets,
            "download_packets": download_packets,
            "upload_bytes": upload_bytes,
            "download_bytes": download_bytes,
            "upload_download_ratio": upload_bytes / download_bytes if download_bytes else None,
        }

    def iter_records(self) -> Iterator[PreprocessedRecord]:
        if not self.input_path.is_file():
            raise FileNotFoundError(f"Dataset not found: {self.input_path}")
        parquet_file = pq.ParquetFile(self.input_path)
        row_number = 0
        for batch in parquet_file.iter_batches(batch_size=65_536):
            for row in batch.to_pylist():
                row_number += 1
                self.total_source_records += 1
                original_label = str(row.get("Label", ""))
                canonical_label = self.canonical_label(original_label)
                if canonical_label is None:
                    continue
                try:
                    values = self._values(row, row_number, canonical_label)
                except (KeyError, TypeError, ValueError) as error:
                    self.skip(f"invalid source value: {error}")
                    continue
                record = self.validate_record(values, f"row {row_number}")
                if record is not None:
                    yield record

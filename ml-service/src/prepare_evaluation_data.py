"""Prepare held-out OOD and anomaly evaluation tables from the IPsec lab corpus.

Raw captures remain immutable. Labels and roles come only from metadata.csv;
filenames and protocol/configuration fields never become model features.
"""

from __future__ import annotations

import argparse
import csv
import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from src.datasets.base import NUMERIC_FEATURE_COLUMNS
from src.datasets.ipsec_pcap_lab import _safe_capture_path, _sha256
from src.features import FeatureExtractionConfig, extract_window_features
from src.preprocess import INTEGER_FEATURES

LOGGER = logging.getLogger(__name__)


def _schema() -> pa.Schema:
    fields = [
        pa.field("dataset_source", pa.string(), nullable=False),
        pa.field("dataset_role", pa.string(), nullable=False),
        pa.field("capture_id", pa.string(), nullable=False),
        pa.field("source_record_id", pa.string(), nullable=False),
        pa.field("original_label", pa.string(), nullable=False),
        pa.field("canonical_label", pa.string(), nullable=False),
        pa.field("split_group_id", pa.string(), nullable=False),
        pa.field("is_anomaly", pa.bool_(), nullable=False),
        pa.field("anomaly_type", pa.string()),
    ]
    fields.extend(
        pa.field(name, pa.int64() if name in INTEGER_FEATURES else pa.float64())
        for name in NUMERIC_FEATURE_COLUMNS
    )
    return pa.schema(fields)


def _representative_window(
    capture_path: Path,
    capture_id: str,
    feature_config: FeatureExtractionConfig,
) -> Mapping[str, object] | None:
    windows = list(
        extract_window_features(
            capture_path,
            capture_id,
            feature_config,
            encrypted_ipsec_only=True,
        )
    )
    if not windows:
        return None
    return max(
        windows,
        key=lambda row: (
            float(row.get("duration") or 0),
            int(row.get("packet_count") or 0),
            str(row.get("flow_id") or ""),
        ),
    )


def _write(rows: Iterable[Mapping[str, Any]], output_path: Path) -> int:
    materialized = list(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    pq.write_table(
        pa.Table.from_pylist(materialized, schema=_schema()),
        temporary,
        compression="snappy",
    )
    temporary.replace(output_path)
    return len(materialized)


def prepare_evaluation_datasets(
    dataset_root: Path,
    ood_output: Path,
    anomaly_output: Path,
    feature_config: FeatureExtractionConfig,
) -> dict[str, Any]:
    """Create balanced, one-record-per-capture evaluation datasets."""

    metadata_path = dataset_root / "metadata.csv"
    if not metadata_path.is_file():
        raise ValueError(f"Dataset metadata not found: {metadata_path}")
    feature_config.validate()
    ood_rows: list[dict[str, Any]] = []
    anomaly_rows: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    with metadata_path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"sample_id", "pcap_file", "traffic_class", "dataset_role", "sha256"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError("metadata.csv is missing: " + ", ".join(sorted(missing)))
        for row_number, row in enumerate(reader, start=2):
            role = (row.get("dataset_role") or "").strip()
            include_ood = role == "ood_eval"
            include_anomaly = role == "anomaly_eval" or (
                role == "train_known" and (row.get("split") or "").strip() == "locked_test"
            )
            if not include_ood and not include_anomaly:
                continue
            capture_path = _safe_capture_path(dataset_root, row.get("pcap_file") or "")
            if capture_path is None or not capture_path.is_file():
                skipped["unsafe or missing capture"] += 1
                continue
            expected_hash = (row.get("sha256") or "").strip().casefold()
            if expected_hash and _sha256(capture_path) != expected_hash:
                skipped["checksum mismatch"] += 1
                continue
            capture_id = capture_path.relative_to(dataset_root.resolve()).as_posix()
            try:
                features = _representative_window(capture_path, capture_id, feature_config)
            except (OSError, ValueError) as error:
                LOGGER.warning("Skipping metadata row %d: %s", row_number, error)
                skipped["capture could not be parsed"] += 1
                continue
            if features is None:
                skipped["no encrypted ESP window"] += 1
                continue
            sample_id = (row.get("sample_id") or capture_id).strip()
            record = {
                "dataset_source": "ipsec-pcap-lab",
                "dataset_role": role,
                "capture_id": capture_id,
                "source_record_id": str(features["flow_id"]),
                "original_label": (row.get("traffic_class") or "").strip(),
                "canonical_label": (
                    "IGNORE" if include_ood or role == "anomaly_eval" else
                    (row.get("canonical_label") or row.get("traffic_class") or "").strip()
                ),
                "split_group_id": f"ipsec-pcap-lab:{sample_id}",
                "is_anomaly": (row.get("is_anomaly") or "false").strip().casefold() == "true",
                "anomaly_type": (row.get("anomaly_type") or "none").strip(),
                **features,
            }
            if include_ood:
                ood_rows.append(record)
            if include_anomaly:
                anomaly_rows.append(record)

    ood_count = _write(ood_rows, ood_output)
    anomaly_count = _write(anomaly_rows, anomaly_output)
    summary = {
        "ood_records": ood_count,
        "anomaly_evaluation_records": anomaly_count,
        "anomaly_records": sum(bool(row["is_anomaly"]) for row in anomaly_rows),
        "normal_records": sum(not bool(row["is_anomaly"]) for row in anomaly_rows),
        "skipped": dict(sorted(skipped.items())),
    }
    LOGGER.info("Prepared evaluation datasets: %s", summary)
    return summary


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset-root",
        type=Path,
        default=service_root / "data" / "external" / "ipsec-pcap-lab",
    )
    parser.add_argument(
        "--ood-output",
        type=Path,
        default=service_root / "data" / "processed" / "ipsec-pcap-lab-ood.parquet",
    )
    parser.add_argument(
        "--anomaly-output",
        type=Path,
        default=service_root / "data" / "processed" / "ipsec-pcap-lab-anomaly-evaluation.parquet",
    )
    parser.add_argument("--window-seconds", type=float, default=10.0)
    parser.add_argument("--burst-gap-seconds", type=float, default=0.1)
    parser.add_argument("--idle-gap-seconds", type=float, default=1.0)
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    prepare_evaluation_datasets(
        args.dataset_root,
        args.ood_output,
        args.anomaly_output,
        FeatureExtractionConfig(
            window_duration_seconds=args.window_seconds,
            burst_gap_seconds=args.burst_gap_seconds,
            idle_gap_seconds=args.idle_gap_seconds,
        ),
    )


if __name__ == "__main__":
    main()

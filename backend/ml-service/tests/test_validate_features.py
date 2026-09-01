"""Tests for read-only processed-feature validation."""

from __future__ import annotations

import math
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from src.preprocess import common_arrow_schema
from src.validate_features import validate_processed_features, write_reports


def base_row(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "dataset_source": "dataset-a",
        "capture_id": None,
        "source_record_id": "record-1",
        "original_label": "BROWSING",
        "canonical_label": "web",
        "split_group_id": "capture-a",
        "excluded_leakage_columns": ["traffic_type"],
        "flow_id": None,
        "duration": 1.0,
        "packet_count": 10,
        "total_bytes": None,
        "packets_per_second": None,
        "bytes_per_second": 100.0,
        "mean_packet_size": 50.0,
        "std_packet_size": None,
        "min_packet_size": None,
        "max_packet_size": None,
        "p25_packet_size": None,
        "median_packet_size": None,
        "p75_packet_size": None,
        "p95_packet_size": None,
        "mean_interarrival_time": None,
        "std_interarrival_time": None,
        "upload_packets": None,
        "download_packets": None,
        "upload_bytes": None,
        "download_bytes": None,
        "upload_download_ratio": None,
        "burst_count": None,
        "mean_burst_size": None,
        "idle_time_ratio": None,
    }
    row.update(updates)
    return row


def write_parquet(path: Path, rows: list[dict[str, object]]) -> None:
    pq.write_table(pa.Table.from_pylist(rows, schema=common_arrow_schema()), path)


def test_validation_reports_quality_coverage_and_recommendations(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    processed.mkdir()
    duplicate = base_row()
    write_parquet(
        processed / "dataset-a.parquet",
        [
            duplicate,
            duplicate,
            base_row(
                source_record_id="record-3",
                original_label="VOIP",
                canonical_label="voip",
                duration=10.0,
                bytes_per_second=300.0,
                mean_packet_size=math.nan,
            ),
        ],
    )
    write_parquet(
        processed / "dataset-b.parquet",
        [
            base_row(
                dataset_source="dataset-b",
                source_record_id="record-b",
                canonical_label="web",
                duration=2.0,
                packet_count=None,
                bytes_per_second=None,
                mean_packet_size=None,
            )
        ],
    )

    report = validate_processed_features(processed, correlation_threshold=0.9)
    first = report["datasets"][0]

    assert report["processed_parquet_file_count"] == 2
    assert first["duplicate_records"]["exact_duplicate_count"] == 1
    assert first["feature_reports"]["mean_packet_size"]["nan_count"] == 1
    assert report["features_present_in_only_one_dataset"]["bytes_per_second"] == ["dataset-a"]
    assert any(
        finding["feature"] == "duration" for finding in first["suspicious_label_correlations"]
    )
    assert "dataset_source" in report["recommendations"]["drop"]
    assert "burst_count" in report["recommendations"]["usable_only_for_our_ipsec_dataset"]

    json_path, markdown_path = write_reports(report, tmp_path / "artifacts")
    assert json_path.is_file()
    assert "Processed Feature Validation" in markdown_path.read_text(encoding="utf-8")


def test_empty_processed_directory_reports_no_empirical_approval(tmp_path: Path) -> None:
    processed = tmp_path / "processed"
    processed.mkdir()

    report = validate_processed_features(processed)

    assert report["datasets"] == []
    assert report["recommendations"]["safe_across_public_datasets"] == []
    assert "No processed Parquet files" in report["recommendations"]["note"]

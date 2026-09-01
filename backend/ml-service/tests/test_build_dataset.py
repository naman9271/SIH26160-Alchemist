"""Tests for reproducible, group-safe supervised dataset construction."""

from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from src.build_dataset import (
    BuildConfig,
    DatasetBuildError,
    build_training_dataset,
    load_safe_features,
)
from src.preprocess import common_arrow_schema


def processed_row(**updates: object) -> dict[str, object]:
    row: dict[str, object] = {
        "dataset_source": "dataset-a",
        "capture_id": "capture-a.pcap",
        "source_record_id": "record-1",
        "original_label": "BROWSING",
        "canonical_label": "web",
        "split_group_id": "dataset-a:capture-a",
        "excluded_leakage_columns": ["filename", "source_ip"],
        "flow_id": "flow-1",
        "duration": 1.0,
        "packet_count": None,
        "total_bytes": None,
        "packets_per_second": None,
        "bytes_per_second": 100.0,
        "mean_packet_size": None,
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


def write_validation(path: Path, safe_features: list[str]) -> None:
    path.write_text(
        json.dumps(
            {
                "recommendations": {
                    "safe_across_public_datasets": safe_features,
                    "usable_only_for_our_ipsec_dataset": [],
                    "drop": [],
                }
            }
        ),
        encoding="utf-8",
    )


def write_processed(path: Path, rows: list[dict[str, object]]) -> None:
    pq.write_table(pa.Table.from_pylist(rows, schema=common_arrow_schema()), path)


def test_builds_group_safe_dataset_and_reports_source_contributions(tmp_path: Path) -> None:
    processed_dir = tmp_path / "processed"
    artifacts_dir = tmp_path / "artifacts"
    processed_dir.mkdir()
    artifacts_dir.mkdir()
    validation_path = artifacts_dir / "feature_validation.json"
    write_validation(validation_path, ["duration", "bytes_per_second"])
    write_processed(
        processed_dir / "dataset-a.parquet",
        [
            processed_row(source_record_id="web-1", flow_id="web-1"),
            processed_row(source_record_id="web-2", flow_id="web-2", duration=2.0),
            processed_row(
                source_record_id="voip-a",
                flow_id="voip-a",
                original_label="VOIP",
                canonical_label="voip",
                split_group_id="dataset-a:capture-voip",
            ),
            processed_row(
                source_record_id="email-1",
                flow_id="email-1",
                original_label="MAIL",
                canonical_label="email",
                split_group_id="dataset-a:capture-email",
            ),
            processed_row(
                source_record_id="ignored",
                flow_id="ignored",
                original_label="STREAMING",
                canonical_label="IGNORE",
                split_group_id="dataset-a:capture-ignore",
            ),
        ],
    )
    write_processed(
        processed_dir / "dataset-b.parquet",
        [
            processed_row(
                dataset_source="dataset-b",
                source_record_id="voip-b1",
                flow_id="voip-b1",
                original_label="Skype",
                canonical_label="voip",
                split_group_id="dataset-b:capture-voip",
            ),
            processed_row(
                dataset_source="dataset-b",
                source_record_id="voip-b2",
                flow_id="voip-b2",
                original_label="Skype",
                canonical_label="voip",
                split_group_id="dataset-b:capture-voip",
                duration=3.0,
            ),
        ],
    )
    output_path = processed_dir / "training_dataset.parquet"
    summary_path = artifacts_dir / "training_dataset_summary.json"

    summary = build_training_dataset(
        BuildConfig(
            processed_dir=processed_dir,
            feature_validation_path=validation_path,
            output_path=output_path,
            summary_path=summary_path,
            minimum_samples_per_class=2,
            test_fraction=0.4,
            split_seed="test-seed",
        )
    )
    table = pq.read_table(output_path)
    rows = table.to_pylist()

    assert table.num_rows == 5
    assert table.column_names == [
        "duration",
        "bytes_per_second",
        "canonical_label",
        "split_group_id",
        "split",
        "audit_metadata",
    ]
    assert "dataset_source" not in table.column_names
    assert {row["canonical_label"] for row in rows} == {"web", "voip"}
    group_splits: dict[str, set[str]] = {}
    for row in rows:
        group_splits.setdefault(row["split_group_id"], set()).add(row["split"])
    assert all(len(splits) == 1 for splits in group_splits.values())
    assert summary["groups_in_multiple_splits"] == []
    assert summary["classes_dropped_for_minimum_samples"] == {"email": 1}
    assert summary["skipped_rows"]["by_reason"] == {"canonical label is IGNORE": 1}
    assert summary["class_counts_per_source_dataset"] == {
        "dataset-a": {
            "email": 0,
            "file_transfer": 0,
            "icmp": 0,
            "messaging": 0,
            "video": 0,
            "voip": 1,
            "web": 2,
        },
        "dataset-b": {
            "email": 0,
            "file_transfer": 0,
            "icmp": 0,
            "messaging": 0,
            "video": 0,
            "voip": 2,
            "web": 0,
        },
    }
    assert rows[0]["audit_metadata"]["original_label"] == "BROWSING"
    assert summary_path.is_file()


def test_rejects_empty_safe_feature_decision(tmp_path: Path) -> None:
    validation_path = tmp_path / "feature_validation.json"
    write_validation(validation_path, [])

    with pytest.raises(DatasetBuildError, match="approves no public features"):
        load_safe_features(validation_path)


def test_rejects_leakage_column_marked_safe(tmp_path: Path) -> None:
    validation_path = tmp_path / "feature_validation.json"
    write_validation(validation_path, ["dataset_source"])

    with pytest.raises(DatasetBuildError, match="leakage columns"):
        load_safe_features(validation_path)


def test_preserves_declared_splits_and_caps_capture_contribution(tmp_path: Path) -> None:
    processed_dir = tmp_path / "processed"
    processed_dir.mkdir()
    validation_path = tmp_path / "feature_validation.json"
    write_validation(validation_path, ["duration"])
    write_processed(
        processed_dir / "dataset-a.parquet",
        [
            processed_row(source_record_id="train-1", declared_split="train"),
            processed_row(source_record_id="train-2", declared_split="train", duration=2.0),
            processed_row(
                source_record_id="validation",
                split_group_id="validation-group",
                declared_split="validation",
            ),
            processed_row(
                source_record_id="test",
                split_group_id="test-group",
                declared_split="locked_test",
            ),
        ],
    )
    output = processed_dir / "training_dataset.parquet"

    summary = build_training_dataset(
        BuildConfig(
            processed_dir=processed_dir,
            feature_validation_path=validation_path,
            output_path=output,
            summary_path=tmp_path / "summary.json",
            max_records_per_group=1,
        )
    )

    rows = pq.read_table(output).to_pylist()
    assert [row["split"] for row in rows] == ["train", "validation", "test"]
    assert summary["records_dropped_by_group_cap"] == 1

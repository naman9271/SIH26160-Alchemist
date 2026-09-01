"""Tests for UNKNOWN threshold calibration and persistence."""

from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from src.calibrate_unknown import calibrate_unknown, load_calibration_config
from tests.test_leakage_audit import prepare_trained_fixture


def write_config(
    path: Path,
    dataset_path: Path,
    models_dir: Path,
    training_metrics_path: Path,
    output_path: Path,
    ood_paths: list[Path],
) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "model": {
                    "training_dataset_path": str(dataset_path),
                    "models_dir": str(models_dir),
                    "training_metrics_path": str(training_metrics_path),
                },
                "unknown_detection": {
                    "method": "max_class_probability_threshold",
                    "confidence_threshold": None,
                    "candidate_thresholds": [0.3, 0.5, 0.7, 0.9],
                    "ood_dataset_paths": [str(item) for item in ood_paths],
                    "calibration_metrics_path": str(output_path),
                    "limitation": "baseline open-set method",
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_missing_model_artifacts_write_blocked_metrics(tmp_path: Path) -> None:
    config_path = tmp_path / "model.yaml"
    metrics_path = tmp_path / "unknown_calibration.json"
    write_config(
        config_path,
        tmp_path / "missing.parquet",
        tmp_path / "models",
        tmp_path / "training_metrics.json",
        metrics_path,
        [],
    )

    report = calibrate_unknown(load_calibration_config(config_path))

    assert report["status"] == "blocked"
    assert report["chosen_threshold"] is None
    assert json.loads(metrics_path.read_text(encoding="utf-8"))["status"] == "blocked"


def test_calibration_evaluates_thresholds_and_persists_choice(tmp_path: Path) -> None:
    dataset_path, models_dir, training_metrics_path = prepare_trained_fixture(tmp_path)
    ood_path = tmp_path / "held_out_traffic.parquet"
    pq.write_table(
        pa.Table.from_pylist(
            [
                {
                    "duration": 50.0 + index,
                    "mean_packet_size": 500.0 + index,
                    "canonical_label": "icmp",
                    "dataset_source": "held-out-source",
                }
                for index in range(8)
            ]
        ),
        ood_path,
    )
    config_path = tmp_path / "model.yaml"
    calibration_path = tmp_path / "unknown_calibration.json"
    write_config(
        config_path,
        dataset_path,
        models_dir,
        training_metrics_path,
        calibration_path,
        [ood_path],
    )

    report = calibrate_unknown(load_calibration_config(config_path))

    assert report["status"] == "complete"
    assert len(report["threshold_results"]) == 4
    assert report["known_samples"] > 0
    assert report["unknown_samples"] == 8
    assert {
        "known_traffic_accuracy",
        "false_unknown_rate",
        "unknown_detection_rate",
        "average_confidence_known",
        "average_confidence_unknown",
    } <= set(report["chosen_threshold_metrics"])
    saved_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved_config["unknown_detection"]["confidence_threshold"] == report["chosen_threshold"]
    metadata = json.loads((models_dir / "model_metadata.json").read_text(encoding="utf-8"))
    assert metadata["unknown_detection"]["status"] == "calibrated"
    assert metadata["unknown_detection"]["confidence_threshold"] == report["chosen_threshold"]


def test_candidate_thresholds_can_be_overridden(tmp_path: Path) -> None:
    config_path = tmp_path / "model.yaml"
    write_config(
        config_path,
        tmp_path / "dataset.parquet",
        tmp_path / "models",
        tmp_path / "metrics.json",
        tmp_path / "calibration.json",
        [],
    )

    config = load_calibration_config(config_path, threshold_override=[0.25, 0.8])

    assert config.candidate_thresholds == (0.25, 0.8)

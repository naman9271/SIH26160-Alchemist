"""Tests for the separate experimental Isolation Forest component."""

from __future__ import annotations

import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from src.anomaly.predict import (
    AnomalyDetector,
    AnomalyPredictionError,
    AnomalyStatus,
)
from src.anomaly.train import AnomalyTrainingConfig, train_anomaly_detector
from tests.test_schemas import valid_flow_features
from tests.test_train import write_training_dataset


def anomaly_config(tmp_path: Path, evaluation_path: Path | None = None) -> AnomalyTrainingConfig:
    dataset_path = tmp_path / "training_dataset.parquet"
    write_training_dataset(dataset_path)
    return AnomalyTrainingConfig(
        dataset_path=dataset_path,
        model_path=tmp_path / "models" / "isolation_forest.joblib",
        metadata_path=tmp_path / "models" / "anomaly_metadata.json",
        metrics_path=tmp_path / "artifacts" / "anomaly_metrics.json",
        evaluation_dataset_path=evaluation_path,
        contamination=0.1,
        n_estimators=40,
        random_seed=7,
        normalization_quantiles=(0.01, 0.99),
        n_jobs=1,
    )


def write_predict_config(path: Path, config: AnomalyTrainingConfig, *, enabled: bool = True) -> None:
    path.write_text(
        "\n".join(
            [
                "anomaly_detection:",
                f"  enabled: {'true' if enabled else 'false'}",
                "  method: isolation_forest",
                f"  model_path: {config.model_path}",
                f"  metadata_path: {config.metadata_path}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_training_persists_model_metadata_and_normal_metrics(tmp_path: Path) -> None:
    config = anomaly_config(tmp_path)

    metrics = train_anomaly_detector(config)
    metadata = json.loads(config.metadata_path.read_text(encoding="utf-8"))

    assert config.model_path.is_file()
    assert config.metadata_path.is_file()
    assert config.metrics_path.is_file()
    assert metrics["status"] == "complete"
    assert metrics["labeled_evaluation"] is None
    assert {
        "normal_detection_rate",
        "false_positive_rate",
        "average_anomaly_score",
    } <= set(metrics["held_out_normal"])
    assert metadata["method"] == "isolation_forest"
    assert metadata["feature_order"] == ["duration", "idle_time_ratio"]
    assert 0 <= metadata["normalized_suspicious_threshold"] <= 1
    assert metrics["normalized_suspicious_threshold"] == round(
        metadata["normalized_suspicious_threshold"], 6
    )
    assert "Neither implies the other" in metadata["separation_from_unknown"]


def test_prediction_returns_normalized_status_without_classifier_fields(tmp_path: Path) -> None:
    config = anomaly_config(tmp_path)
    train_anomaly_detector(config)
    config_path = tmp_path / "model.yaml"
    write_predict_config(config_path, config)

    result = AnomalyDetector.from_config(config_path).predict(valid_flow_features())
    payload = result.model_dump(mode="json")

    assert result.flow_id == "flow-001"
    assert 0 <= result.anomaly_score <= 1
    assert result.anomaly_status in {AnomalyStatus.NORMAL, AnomalyStatus.SUSPICIOUS}
    assert result.model_version.startswith("isolation-forest-")
    assert "predicted_class" not in payload
    assert "is_unknown" not in payload


def test_prediction_rejects_invalid_flow_features(tmp_path: Path) -> None:
    config = anomaly_config(tmp_path)
    train_anomaly_detector(config)
    config_path = tmp_path / "model.yaml"
    write_predict_config(config_path, config)
    invalid = valid_flow_features()
    invalid["duration"] = 0

    with pytest.raises(AnomalyPredictionError, match="Invalid FlowFeatures"):
        AnomalyDetector.from_config(config_path).predict(invalid)


def test_predictor_requires_explicit_enablement(tmp_path: Path) -> None:
    config = anomaly_config(tmp_path)
    train_anomaly_detector(config)
    config_path = tmp_path / "model.yaml"
    write_predict_config(config_path, config, enabled=False)

    with pytest.raises(AnomalyPredictionError, match="disabled"):
        AnomalyDetector.from_config(config_path)


def test_labeled_evaluation_reports_detection_metrics(tmp_path: Path) -> None:
    evaluation_path = tmp_path / "labeled_anomalies.parquet"
    pq.write_table(
        pa.Table.from_pylist(
            [
                {"duration": 2.0, "idle_time_ratio": 0.1, "is_anomaly": False},
                {"duration": 12.0, "idle_time_ratio": 0.2, "is_anomaly": False},
                {"duration": 150.0, "idle_time_ratio": 0.95, "is_anomaly": True},
                {"duration": 200.0, "idle_time_ratio": 0.99, "is_anomaly": True},
            ]
        ),
        evaluation_path,
    )
    config = anomaly_config(tmp_path, evaluation_path)

    labeled = train_anomaly_detector(config)["labeled_evaluation"]

    assert labeled["sample_count"] == 4
    assert labeled["anomaly_count"] == 2
    assert {
        "accuracy",
        "anomaly_precision",
        "anomaly_recall",
        "anomaly_f1",
        "confusion_matrix",
    } <= set(labeled)
    assert len(labeled["confusion_matrix"]) == 2

"""Tests for evaluation of the persisted selected classifier."""

from __future__ import annotations

import json
from pathlib import Path

from src.evaluate import evaluate_production_model
from tests.test_leakage_audit import prepare_trained_fixture


def test_blocked_evaluation_writes_frontend_safe_summary(tmp_path: Path) -> None:
    output_dir = tmp_path / "evaluation"

    report = evaluate_production_model(
        dataset_path=tmp_path / "training_dataset.parquet",
        models_dir=tmp_path / "models",
        training_metrics_path=tmp_path / "training_metrics.json",
        output_dir=output_dir,
    )
    summary = json.loads((output_dir / "model_summary.json").read_text(encoding="utf-8"))

    assert report["status"] == "blocked"
    assert summary["status"] == "blocked"
    assert summary["overall_accuracy"] is None
    assert (output_dir / "evaluation.json").is_file()


def test_evaluation_writes_metrics_plots_and_frontend_summary(tmp_path: Path) -> None:
    dataset_path, models_dir, metrics_path = prepare_trained_fixture(tmp_path)
    output_dir = tmp_path / "evaluation"

    report = evaluate_production_model(
        dataset_path=dataset_path,
        models_dir=models_dir,
        training_metrics_path=metrics_path,
        output_dir=output_dir,
        max_misclassified_samples=10,
    )
    summary = json.loads((output_dir / "model_summary.json").read_text(encoding="utf-8"))

    assert report["status"] == "complete"
    assert {"accuracy", "macro_f1", "weighted_f1", "classification_report"} <= set(report)
    assert len(report["confidence_histogram"]["counts"]) == 20
    assert set(report["per_class_confidence"]) == {"video", "voip", "web"}
    assert (output_dir / "confusion_matrix.png").is_file()
    assert (output_dir / "confidence_histogram.png").is_file()
    assert (output_dir / "per_class_confidence.png").is_file()
    assert summary["supported_classes"] == ["video", "voip", "web"]
    assert summary["training_samples"] > 0
    assert summary["test_samples"] > 0

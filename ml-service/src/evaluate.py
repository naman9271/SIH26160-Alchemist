"""Evaluate the selected persisted production classifier without retraining."""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

from src.train import TrainingConfig, TrainingError, load_training_dataset, split_group_safe

LOGGER = logging.getLogger(__name__)


def _plotting() -> tuple[Any, Any]:
    """Load the non-interactive plotting backend only when plots are needed."""

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as pyplot

    return matplotlib, pyplot


def _decode(predictions: np.ndarray, class_order: Sequence[str]) -> np.ndarray:
    decoded: list[str] = []
    for prediction in predictions:
        index = int(prediction)
        if index < 0 or index >= len(class_order):
            raise TrainingError(f"Model returned an unknown class index: {index}")
        decoded.append(class_order[index])
    return np.asarray(decoded, dtype=str)


def _audit_metadata(path: Path, expected_rows: int) -> list[dict[str, Any]]:
    table = pq.read_table(path, columns=["audit_metadata"])
    metadata = [dict(value or {}) for value in table.column("audit_metadata").to_pylist()]
    if len(metadata) != expected_rows:
        raise TrainingError("Audit metadata row count does not match the training dataset")
    return metadata


def _atomic_json(value: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary_path.replace(path)


def _save_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, classes: Sequence[str], path: Path) -> None:
    _, plt = _plotting()
    figure, axis = plt.subplots(figsize=(max(6, len(classes)), max(5, len(classes))))
    display = ConfusionMatrixDisplay(
        confusion_matrix=confusion_matrix(y_true, y_pred, labels=classes),
        display_labels=classes,
    )
    display.plot(ax=axis, colorbar=False, xticks_rotation=45)
    axis.set_title("Production classifier confusion matrix")
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)


def _save_confidence_histogram(confidences: np.ndarray, path: Path) -> None:
    _, plt = _plotting()
    figure, axis = plt.subplots(figsize=(7, 4))
    axis.hist(confidences, bins=20, range=(0, 1), color="#2563eb", edgecolor="white")
    axis.set(title="Prediction confidence", xlabel="Maximum class probability", ylabel="Test samples")
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)


def _save_per_class_confidence(
    y_true: np.ndarray, confidences: np.ndarray, classes: Sequence[str], path: Path
) -> dict[str, float | None]:
    _, plt = _plotting()
    per_class = {
        label: (round(float(np.mean(confidences[y_true == label])), 6) if np.any(y_true == label) else None)
        for label in classes
    }
    figure, axis = plt.subplots(figsize=(max(7, len(classes)), 4))
    labels = list(per_class)
    values = [per_class[label] or 0 for label in labels]
    axis.bar(labels, values, color="#059669")
    axis.set(title="Mean confidence by true class", xlabel="Class", ylabel="Mean confidence", ylim=(0, 1))
    axis.tick_params(axis="x", rotation=35)
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)
    return per_class


def _blocked_output(missing: Sequence[Path]) -> tuple[dict[str, Any], dict[str, Any]]:
    reason = "Required trained-model artifacts are unavailable; evaluation was not run."
    return (
        {
            "status": "blocked",
            "generated_at": datetime.now(UTC).isoformat(),
            "reason": reason,
            "missing_required_artifacts": [str(path) for path in missing],
        },
        {
            "status": "blocked",
            "model_version": None,
            "overall_accuracy": None,
            "macro_f1": None,
            "supported_classes": [],
            "training_samples": None,
            "test_samples": None,
            "reason": reason,
        },
    )


def evaluate_production_model(
    dataset_path: Path,
    models_dir: Path,
    training_metrics_path: Path,
    output_dir: Path,
    max_misclassified_samples: int = 50,
) -> dict[str, Any]:
    """Evaluate the selected saved classifier on its reconstructed group-safe test set."""

    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = models_dir / "model_metadata.json"
    required = [dataset_path, metadata_path, training_metrics_path]
    missing = [path for path in required if not path.is_file()]
    if missing:
        evaluation, summary = _blocked_output(missing)
        _atomic_json(evaluation, output_dir / "evaluation.json")
        _atomic_json(summary, output_dir / "model_summary.json")
        return evaluation
    if max_misclassified_samples < 1:
        raise ValueError("max_misclassified_samples must be positive")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    training_metrics = json.loads(training_metrics_path.read_text(encoding="utf-8"))
    selected = training_metrics.get("selected_model")
    model_filename = "random_forest.joblib" if selected == "random_forest" else "xgboost.joblib"
    model_path = models_dir / model_filename
    if selected not in {"random_forest", "xgboost"} or not model_path.is_file():
        evaluation, summary = _blocked_output([model_path])
        _atomic_json(evaluation, output_dir / "evaluation.json")
        _atomic_json(summary, output_dir / "model_summary.json")
        return evaluation

    data = load_training_dataset(dataset_path)
    feature_order = metadata.get("feature_order")
    class_order = metadata.get("class_order")
    if data.feature_order != feature_order:
        raise TrainingError("Training dataset feature order differs from model metadata")
    if not isinstance(class_order, list) or not all(isinstance(item, str) for item in class_order):
        raise TrainingError("Model metadata class_order is invalid")
    stored_config = metadata.get("config") or {}
    split_config = TrainingConfig(
        dataset_path=dataset_path,
        models_dir=models_dir,
        metrics_path=training_metrics_path,
        random_seed=int(stored_config.get("random_seed", 42)),
        test_fraction=float(stored_config.get("test_fraction", 0.2)),
        validation_fraction=float(stored_config.get("validation_fraction", 0.2)),
        n_jobs=int(stored_config.get("n_jobs", -1)),
    )
    splits = split_group_safe(data, split_config)
    model = joblib.load(model_path)
    x_test = data.features[splits.test]
    y_test = data.labels[splits.test]
    predictions = _decode(model.predict(x_test), class_order)
    probabilities = model.predict_proba(x_test)
    confidences = np.max(probabilities, axis=1)
    audit_metadata = _audit_metadata(dataset_path, len(data.labels))

    report = classification_report(
        y_test, predictions, labels=class_order, output_dict=True, zero_division=0
    )
    matrix = confusion_matrix(y_test, predictions, labels=class_order).tolist()
    class_distribution = dict(sorted(Counter(y_test).items()))
    per_class_confidence = _save_per_class_confidence(
        y_test, confidences, class_order, output_dir / "per_class_confidence.png"
    )
    _save_confidence_histogram(confidences, output_dir / "confidence_histogram.png")
    _save_confusion_matrix(y_test, predictions, class_order, output_dir / "confusion_matrix.png")

    errors: list[dict[str, Any]] = []
    for dataset_index, true_label, predicted_label, confidence in zip(
        splits.test, y_test, predictions, confidences
    ):
        if true_label == predicted_label:
            continue
        metadata_row = audit_metadata[int(dataset_index)]
        errors.append(
            {
                "true_class": str(true_label),
                "predicted_class": str(predicted_label),
                "confidence": round(float(confidence), 6),
                "dataset_source": metadata_row.get("dataset_source"),
                "original_label": metadata_row.get("original_label"),
                "capture_id": metadata_row.get("capture_id"),
                "source_record_id": metadata_row.get("source_record_id"),
            }
        )
        if len(errors) >= max_misclassified_samples:
            break

    evaluation = {
        "status": "complete",
        "generated_at": datetime.now(UTC).isoformat(),
        "model_version": metadata.get("model_version", "unknown"),
        "selected_model": selected,
        "feature_order": data.feature_order,
        "accuracy": round(float(accuracy_score(y_test, predictions)), 6),
        "macro_f1": round(float(f1_score(y_test, predictions, labels=class_order, average="macro", zero_division=0)), 6),
        "weighted_f1": round(float(f1_score(y_test, predictions, labels=class_order, average="weighted", zero_division=0)), 6),
        "classification_report": report,
        "confusion_matrix_labels": class_order,
        "confusion_matrix": matrix,
        "class_distribution": class_distribution,
        "confidence_histogram": {
            "bin_edges": np.histogram_bin_edges(confidences, bins=20, range=(0, 1)).round(6).tolist(),
            "counts": np.histogram(confidences, bins=20, range=(0, 1))[0].tolist(),
        },
        "per_class_confidence": per_class_confidence,
        "misclassified_sample_summary": {
            "total_misclassified": int(np.sum(y_test != predictions)),
            "samples": errors,
            "sample_limit": max_misclassified_samples,
        },
        "plots": {
            "confusion_matrix": "confusion_matrix.png",
            "confidence_histogram": "confidence_histogram.png",
            "per_class_confidence": "per_class_confidence.png",
        },
        "group_split_strategy": splits.strategy,
    }
    model_summary = {
        "model_version": evaluation["model_version"],
        "overall_accuracy": evaluation["accuracy"],
        "macro_f1": evaluation["macro_f1"],
        "supported_classes": class_order,
        "training_samples": int(len(splits.train) + len(splits.validation)),
        "test_samples": int(len(splits.test)),
    }
    _atomic_json(evaluation, output_dir / "evaluation.json")
    _atomic_json(model_summary, output_dir / "model_summary.json")
    LOGGER.info("Evaluated %s on %d group-safe test samples", selected, len(splits.test))
    return evaluation


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=service_root / "data" / "processed" / "training_dataset.parquet",
    )
    parser.add_argument("--models-dir", type=Path, default=service_root / "models")
    parser.add_argument(
        "--training-metrics",
        type=Path,
        default=service_root / "artifacts" / "training_metrics.json",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=service_root / "artifacts" / "evaluation"
    )
    parser.add_argument("--max-misclassified-samples", type=int, default=50)
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    evaluate_production_model(
        dataset_path=args.dataset,
        models_dir=args.models_dir,
        training_metrics_path=args.training_metrics,
        output_dir=args.output_dir,
        max_misclassified_samples=args.max_misclassified_samples,
    )


if __name__ == "__main__":
    main()

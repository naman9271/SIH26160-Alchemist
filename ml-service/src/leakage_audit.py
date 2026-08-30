"""Audit a trained classifier for dataset leakage and source memorization.

This module reports evidence and concrete fixes. It does not redesign the
training pipeline or modify trained models.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pyarrow.parquet as pq
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    normalized_mutual_info_score,
    precision_recall_fscore_support,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight

from src.train import (
    DatasetData,
    GroupSplits,
    TrainingConfig,
    TrainingError,
    _stratified_group_split,
    load_training_dataset,
    split_group_safe,
)

LOGGER = logging.getLogger(__name__)

IDENTIFIER_TERMS = {
    "id",
    "flow_id",
    "capture_id",
    "source_record_id",
    "filename",
    "file_name",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "timestamp",
}


def _metrics(y_true: np.ndarray, y_pred: np.ndarray, classes: Sequence[str]) -> dict[str, Any]:
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )
    _, _, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, average="macro", zero_division=0
    )
    _, _, weighted_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, average="weighted", zero_division=0
    )
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "macro_f1": round(float(macro_f1), 6),
        "weighted_f1": round(float(weighted_f1), 6),
        "per_class": {
            label: {
                "precision": round(float(precision[index]), 6),
                "recall": round(float(recall[index]), 6),
                "f1": round(float(f1[index]), 6),
                "support": int(support[index]),
            }
            for index, label in enumerate(classes)
        },
        "confusion_matrix_labels": list(classes),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
    }


def _decode_predictions(predictions: np.ndarray, classes: Sequence[str]) -> np.ndarray:
    decoded: list[str] = []
    for prediction in predictions:
        index = int(prediction)
        if index < 0 or index >= len(classes):
            raise TrainingError(f"Model returned class index outside metadata order: {index}")
        decoded.append(classes[index])
    return np.asarray(decoded, dtype=str)


def _load_sources(path: Path, expected_rows: int) -> np.ndarray:
    table = pq.read_table(path, columns=["audit_metadata"])
    sources: list[str] = []
    for row_number, metadata in enumerate(table.column("audit_metadata").to_pylist(), start=1):
        source = metadata.get("dataset_source") if isinstance(metadata, Mapping) else None
        if not isinstance(source, str) or not source:
            raise TrainingError(f"Row {row_number} has no audit dataset_source")
        sources.append(source)
    if len(sources) != expected_rows:
        raise TrainingError("Audit metadata row count does not match feature data")
    return np.asarray(sources, dtype=str)


def _feature_importance(model: Pipeline, feature_order: Sequence[str]) -> list[dict[str, Any]]:
    classifier = model.named_steps.get("classifier")
    importances = getattr(classifier, "feature_importances_", None)
    if importances is None or len(importances) != len(feature_order):
        return []
    return sorted(
        [
            {"feature": feature, "importance": round(float(importance), 8)}
            for feature, importance in zip(feature_order, importances)
        ],
        key=lambda item: item["importance"],
        reverse=True,
    )


def _eta_squared(values: np.ndarray, categories: np.ndarray) -> float:
    finite = np.isfinite(values)
    values = values[finite]
    categories = categories[finite]
    if len(values) < 2 or np.var(values) == 0 or len(set(categories)) < 2:
        return 0.0
    overall_mean = float(np.mean(values))
    total = float(np.sum((values - overall_mean) ** 2))
    between = 0.0
    for category in set(categories):
        category_values = values[categories == category]
        between += len(category_values) * (float(np.mean(category_values)) - overall_mean) ** 2
    return round(between / total, 6) if total else 0.0


def _source_associations(data: DatasetData, sources: np.ndarray) -> list[dict[str, Any]]:
    return sorted(
        [
            {
                "feature": feature,
                "source_eta_squared": _eta_squared(data.features[:, index], sources),
            }
            for index, feature in enumerate(data.feature_order)
        ],
        key=lambda item: item["source_eta_squared"],
        reverse=True,
    )


def _source_predictability(
    data: DatasetData, sources: np.ndarray, seed: int
) -> dict[str, Any]:
    if len(set(sources)) < 2:
        return {"status": "skipped", "reason": "Only one dataset source is present."}
    indices = np.arange(len(sources))
    try:
        train, test, strategy = _stratified_group_split(
            indices, sources, data.groups, desired_fraction=0.25, seed=seed
        )
    except ValueError as error:
        return {"status": "skipped", "reason": f"Source split unavailable: {error}"}
    encoder = LabelEncoder().fit(sources[train])
    if not set(sources[test]) <= set(encoder.classes_):
        return {"status": "skipped", "reason": "Held-out source absent from auxiliary training."}
    model = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=150,
                    max_depth=10,
                    class_weight="balanced_subsample",
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    model.fit(data.features[train], encoder.transform(sources[train]))
    predicted = encoder.inverse_transform(model.predict(data.features[test]).astype(int))
    majority_baseline = max(Counter(sources[test]).values()) / len(test)
    return {
        "status": "complete",
        "split_strategy": strategy,
        "accuracy": round(float(accuracy_score(sources[test], predicted)), 6),
        "majority_baseline_accuracy": round(float(majority_baseline), 6),
        "test_source_counts": dict(sorted(Counter(sources[test]).items())),
    }


def _fit_clone(model: Pipeline, x: np.ndarray, y: np.ndarray) -> Pipeline:
    fitted = clone(model)
    weights = compute_sample_weight(class_weight="balanced", y=y)
    fitted.fit(x, y, classifier__sample_weight=weights)
    return fitted


def _leave_one_source_out(
    model: Pipeline,
    data: DatasetData,
    sources: np.ndarray,
    classes: Sequence[str],
) -> dict[str, Any]:
    encoder = LabelEncoder().fit(classes)
    results: dict[str, Any] = {}
    for held_out_source in sorted(set(sources)):
        train = np.flatnonzero(sources != held_out_source)
        test_all = np.flatnonzero(sources == held_out_source)
        train_classes = set(data.labels[train])
        compatible = np.asarray(
            [index for index in test_all if data.labels[index] in train_classes], dtype=int
        )
        incompatible_classes = sorted(set(data.labels[test_all]) - train_classes)
        if len(compatible) == 0 or len(train_classes) < 2:
            results[held_out_source] = {
                "status": "skipped",
                "reason": "Fewer than two compatible training classes or no compatible test rows.",
                "incompatible_classes": incompatible_classes,
            }
            continue
        fitted = _fit_clone(model, data.features[train], encoder.transform(data.labels[train]))
        predicted = _decode_predictions(fitted.predict(data.features[compatible]), classes)
        evaluated_classes = sorted(set(data.labels[compatible]))
        results[held_out_source] = {
            "status": "complete",
            "train_sources": sorted(set(sources[train])),
            "compatible_test_rows": len(compatible),
            "excluded_incompatible_test_rows": len(test_all) - len(compatible),
            "incompatible_classes": incompatible_classes,
            "metrics": _metrics(data.labels[compatible], predicted, evaluated_classes),
        }
    return results


def _per_source_test_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    sources: np.ndarray,
    classes: Sequence[str],
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for source in sorted(set(sources)):
        indices = np.flatnonzero(sources == source)
        results[source] = _metrics(y_true[indices], y_pred[indices], classes)
    return results


def _ablation_experiment(
    model: Pipeline,
    data: DatasetData,
    splits: GroupSplits,
    classes: Sequence[str],
    suspicious_features: Sequence[str],
) -> dict[str, Any]:
    if not suspicious_features:
        return {"status": "skipped", "reason": "No suspicious high-importance features found."}
    retained = [feature for feature in data.feature_order if feature not in suspicious_features]
    if not retained:
        return {"status": "skipped", "reason": "Removing suspicious features leaves no features."}
    retained_indices = [data.feature_order.index(feature) for feature in retained]
    train_validation = np.concatenate((splits.train, splits.validation))
    encoder = LabelEncoder().fit(classes)
    fitted = _fit_clone(
        model,
        data.features[train_validation][:, retained_indices],
        encoder.transform(data.labels[train_validation]),
    )
    predictions = _decode_predictions(
        fitted.predict(data.features[splits.test][:, retained_indices]), classes
    )
    return {
        "status": "complete",
        "removed_features": list(suspicious_features),
        "retained_feature_order": retained,
        "test_metrics": _metrics(data.labels[splits.test], predictions, classes),
    }


def _blocked_report(missing: Sequence[Path]) -> dict[str, Any]:
    return {
        "status": "blocked",
        "generated_at": datetime.now(UTC).isoformat(),
        "missing_required_artifacts": [str(path) for path in missing],
        "recommendations": [
            "Generate and validate processed public datasets before building the supervised dataset.",
            "Build training_dataset.parquet only from features approved by feature_validation.json.",
            "Train both classifiers, then rerun this audit without changing the leakage thresholds.",
        ],
        "findings": [
            "No empirical leakage claim can be made because trained model artifacts are unavailable."
        ],
    }


def audit_leakage(
    dataset_path: Path,
    models_dir: Path,
    training_metrics_path: Path,
    source_association_threshold: float = 0.5,
    high_accuracy_threshold: float = 0.95,
    top_feature_count: int = 5,
) -> dict[str, Any]:
    """Run leakage experiments or return a truthful blocked report."""

    metadata_path = models_dir / "model_metadata.json"
    required = [dataset_path, metadata_path, training_metrics_path]
    missing = [path for path in required if not path.is_file()]
    if missing:
        return _blocked_report(missing)
    if not 0 <= source_association_threshold <= 1:
        raise ValueError("source_association_threshold must be within [0, 1]")
    if not 0 <= high_accuracy_threshold <= 1:
        raise ValueError("high_accuracy_threshold must be within [0, 1]")
    if top_feature_count < 1:
        raise ValueError("top_feature_count must be positive")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    training_metrics = json.loads(training_metrics_path.read_text(encoding="utf-8"))
    selected_name = training_metrics.get("selected_model")
    model_filename = "random_forest.joblib" if selected_name == "random_forest" else "xgboost.joblib"
    model_path = models_dir / model_filename
    if selected_name not in {"random_forest", "xgboost"} or not model_path.is_file():
        return _blocked_report([model_path])

    data = load_training_dataset(dataset_path)
    if data.feature_order != metadata.get("feature_order"):
        raise TrainingError("Training dataset feature order differs from model metadata")
    classes = list(metadata.get("class_order") or [])
    if not classes:
        raise TrainingError("Model metadata has no class_order")
    sources = _load_sources(dataset_path, len(data.labels))
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
    model: Pipeline = joblib.load(model_path)
    normal_predictions = _decode_predictions(model.predict(data.features[splits.test]), classes)
    normal_metrics = _metrics(data.labels[splits.test], normal_predictions, classes)
    importances = _feature_importance(model, data.feature_order)
    associations = _source_associations(data, sources)
    source_association_by_feature = {
        item["feature"]: item["source_eta_squared"] for item in associations
    }
    high_importance = {item["feature"] for item in importances[:top_feature_count]}
    identifier_like = {
        feature
        for feature in data.feature_order
        if feature.casefold() in IDENTIFIER_TERMS or feature.casefold().endswith("_id")
    }
    suspicious_features = sorted(
        identifier_like
        | {
            feature
            for feature in high_importance
            if source_association_by_feature.get(feature, 0) >= source_association_threshold
        }
    )
    if len(set(sources)) == 1 and normal_metrics["accuracy"] >= high_accuracy_threshold:
        # With one synthetic capture source, source-association statistics are
        # unidentifiable. Ablate the dominant features instead of falsely
        # treating zero eta-squared as evidence of safety.
        suspicious_features = sorted(set(suspicious_features) | high_importance)
    source_label_nmi = round(float(normalized_mutual_info_score(sources, data.labels)), 6)
    source_predictability = _source_predictability(data, sources, split_config.random_seed)
    per_source = _per_source_test_metrics(
        data.labels[splits.test], normal_predictions, sources[splits.test], classes
    )
    leave_source_out = _leave_one_source_out(model, data, sources, classes)
    ablation = _ablation_experiment(model, data, splits, classes, suspicious_features)

    findings: list[str] = []
    fixes: list[str] = []
    if normal_metrics["accuracy"] >= high_accuracy_threshold:
        findings.append("Grouped test accuracy is unusually high and requires source-level confirmation.")
        fixes.append("Repeat evaluation with held-out capture environments and independently collected IPsec traffic.")
    if source_label_nmi >= source_association_threshold:
        findings.append("Canonical labels are strongly associated with dataset source.")
        fixes.append("Collect overlapping classes from multiple sources and report source-balanced metrics.")
    if suspicious_features:
        findings.append(
            "Dominant features need artifact checks or encode measured source differences: "
            + ", ".join(suspicious_features)
        )
        fixes.append(
            "Review units and capture tooling for suspicious features; drop them only after confirming the ablation result."
        )
    if source_predictability.get("status") == "complete" and source_predictability["accuracy"] > source_predictability["majority_baseline_accuracy"]:
        findings.append("Traffic features predict dataset source above the majority baseline.")
        fixes.append("Normalize capture-generation settings and validate on source-held-out data before deployment.")
    if not findings:
        findings.append("No configured leakage alarm fired; this does not prove absence of source artifacts.")
        fixes.append("Add own IPsec captures from multiple environments and rerun the same audit.")

    return {
        "status": "complete",
        "generated_at": datetime.now(UTC).isoformat(),
        "selected_model": selected_name,
        "recommendations": fixes,
        "findings": findings,
        "normal_grouped_test": normal_metrics,
        "per_source_test_performance": per_source,
        "per_class_test_performance": normal_metrics["per_class"],
        "leave_one_source_out": leave_source_out,
        "feature_importance": importances,
        "feature_source_association": associations,
        "source_predictability": source_predictability,
        "label_source_normalized_mutual_information": source_label_nmi,
        "suspicious_high_importance_features": suspicious_features,
        "ablation_without_suspicious_features": ablation,
        "thresholds": {
            "source_association": source_association_threshold,
            "high_accuracy": high_accuracy_threshold,
            "top_feature_count": top_feature_count,
        },
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = ["# Dataset Leakage and Source Memorization Audit", "", "## Recommended fixes", ""]
    for recommendation in report["recommendations"]:
        lines.append(f"- {recommendation}")
    lines.extend(["", f"Status: **{report['status']}**", "", "## Findings", ""])
    for finding in report["findings"]:
        lines.append(f"- {finding}")
    if report["status"] == "blocked":
        lines.extend(
            [
                "",
                "## Missing artifacts",
                "",
                *[f"- `{path}`" for path in report["missing_required_artifacts"]],
                "",
                "No experiment results are reported because doing so would fabricate evidence.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "",
            "## 1. Normal grouped test evaluation",
            "",
            f"`{json.dumps(report['normal_grouped_test'], sort_keys=True)}`",
            "",
            "## 2. Leave-one-source-out evaluation",
            "",
            f"`{json.dumps(report['leave_one_source_out'], sort_keys=True)}`",
            "",
            "## 3. Feature importance and source association",
            "",
            f"Importance: `{json.dumps(report['feature_importance'], sort_keys=True)}`",
            "",
            f"Source association: `{json.dumps(report['feature_source_association'], sort_keys=True)}`",
            "",
            f"Source predictability: `{json.dumps(report['source_predictability'], sort_keys=True)}`",
            "",
            "## 4. Suspicious-feature ablation",
            "",
            f"`{json.dumps(report['ablation_without_suspicious_features'], sort_keys=True)}`",
            "",
            "## 5. Per-source and per-class performance",
            "",
            f"Per source: `{json.dumps(report['per_source_test_performance'], sort_keys=True)}`",
            "",
            f"Per class: `{json.dumps(report['per_class_test_performance'], sort_keys=True)}`",
            "",
            "## Label/source association",
            "",
            f"Normalized mutual information: {report['label_source_normalized_mutual_information']}",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: Mapping[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(report), encoding="utf-8")


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
        "--output",
        type=Path,
        default=service_root / "artifacts" / "leakage_audit.md",
    )
    parser.add_argument("--source-association-threshold", type=float, default=0.5)
    parser.add_argument("--high-accuracy-threshold", type=float, default=0.95)
    parser.add_argument("--top-feature-count", type=int, default=5)
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    report = audit_leakage(
        dataset_path=args.dataset,
        models_dir=args.models_dir,
        training_metrics_path=args.training_metrics,
        source_association_threshold=args.source_association_threshold,
        high_accuracy_threshold=args.high_accuracy_threshold,
        top_feature_count=args.top_feature_count,
    )
    write_report(report, args.output)
    LOGGER.info("Wrote leakage audit to %s", args.output)


if __name__ == "__main__":
    main()

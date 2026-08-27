"""Train and evaluate an experimental Isolation Forest anomaly baseline.

The supervised traffic classifier is not modified. The training dataset is
treated as a normal-reference population; optional labeled anomaly evaluation
data is used only for evaluation and never for fitting.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pyarrow.parquet as pq
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline

from src.train import TrainingConfig, TrainingError, load_training_dataset, split_group_safe

LOGGER = logging.getLogger(__name__)
METHOD = "isolation_forest"


class AnomalyTrainingError(ValueError):
    """Raised when safe anomaly training or evaluation is not possible."""


@dataclass(frozen=True)
class AnomalyTrainingConfig:
    dataset_path: Path
    model_path: Path
    metadata_path: Path
    metrics_path: Path
    evaluation_dataset_path: Path | None
    contamination: float
    n_estimators: int
    random_seed: int
    normalization_quantiles: tuple[float, float]
    test_fraction: float = 0.2
    validation_fraction: float = 0.2
    n_jobs: int = -1

    def validate(self) -> None:
        if not self.dataset_path.is_file():
            raise AnomalyTrainingError(f"Training dataset does not exist: {self.dataset_path}")
        if not math.isfinite(self.contamination) or not 0 < self.contamination <= 0.5:
            raise AnomalyTrainingError("contamination must be within (0, 0.5]")
        if self.n_estimators < 1:
            raise AnomalyTrainingError("n_estimators must be positive")
        if not 0 < self.test_fraction < 1 or not 0 < self.validation_fraction < 1:
            raise AnomalyTrainingError("split fractions must be within (0, 1)")
        if self.test_fraction + self.validation_fraction >= 1:
            raise AnomalyTrainingError("test and validation fractions must sum to less than 1")
        low, high = self.normalization_quantiles
        finite_quantiles = all(math.isfinite(value) for value in (low, high))
        if not finite_quantiles or not 0 <= low < high <= 1:
            raise AnomalyTrainingError("normalization_quantiles must satisfy 0 <= low < high <= 1")
        if self.evaluation_dataset_path is not None and not self.evaluation_dataset_path.is_file():
            raise AnomalyTrainingError(
                f"Labeled evaluation dataset does not exist: {self.evaluation_dataset_path}"
            )


def _resolve_path(config_path: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise AnomalyTrainingError(f"{field} must be a non-empty path")
    path = Path(value)
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def load_anomaly_training_config(config_path: Path) -> AnomalyTrainingConfig:
    """Load the independent anomaly-training configuration."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise AnomalyTrainingError(f"Could not read model config {config_path}: {error}") from error
    model = raw.get("model") if isinstance(raw, Mapping) else None
    anomaly = raw.get("anomaly_detection") if isinstance(raw, Mapping) else None
    if not isinstance(model, Mapping) or not isinstance(anomaly, Mapping):
        raise AnomalyTrainingError("Config needs model and anomaly_detection mappings")
    if anomaly.get("method") != METHOD:
        raise AnomalyTrainingError(f"anomaly_detection.method must be {METHOD!r}")
    quantiles = anomaly.get("normalization_quantiles")
    if not isinstance(quantiles, list) or len(quantiles) != 2:
        raise AnomalyTrainingError("normalization_quantiles must contain two values")
    evaluation_value = anomaly.get("evaluation_dataset_path")
    evaluation_path = (
        None
        if evaluation_value is None
        else _resolve_path(config_path, evaluation_value, "evaluation_dataset_path")
    )
    try:
        config = AnomalyTrainingConfig(
            dataset_path=_resolve_path(
                config_path, model.get("training_dataset_path"), "model.training_dataset_path"
            ),
            model_path=_resolve_path(config_path, anomaly.get("model_path"), "anomaly.model_path"),
            metadata_path=_resolve_path(
                config_path, anomaly.get("metadata_path"), "anomaly.metadata_path"
            ),
            metrics_path=_resolve_path(
                config_path, anomaly.get("metrics_path"), "anomaly.metrics_path"
            ),
            evaluation_dataset_path=evaluation_path,
            contamination=float(anomaly.get("contamination")),
            n_estimators=int(anomaly.get("n_estimators")),
            random_seed=int(anomaly.get("random_seed")),
            normalization_quantiles=(float(quantiles[0]), float(quantiles[1])),
        )
    except (TypeError, ValueError) as error:
        raise AnomalyTrainingError(f"Invalid anomaly configuration value: {error}") from error
    return config


def _atomic_json(value: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _atomic_joblib(value: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    joblib.dump(value, temporary)
    temporary.replace(path)


def _normalize(raw_scores: np.ndarray, low: float, high: float) -> np.ndarray:
    return np.clip((raw_scores - low) / (high - low), 0.0, 1.0)


def _normal_metrics(
    model: Pipeline,
    features: np.ndarray,
    normalization_low: float,
    normalization_high: float,
) -> dict[str, Any]:
    raw_scores = -np.asarray(model.score_samples(features), dtype=float)
    normalized = _normalize(raw_scores, normalization_low, normalization_high)
    suspicious = np.asarray(model.predict(features)) == -1
    return {
        "sample_count": int(len(features)),
        "normal_detection_rate": round(float(np.mean(~suspicious)), 6),
        "false_positive_rate": round(float(np.mean(suspicious)), 6),
        "suspicious_count": int(np.sum(suspicious)),
        "average_anomaly_score": round(float(np.mean(normalized)), 6),
        "p95_anomaly_score": round(float(np.quantile(normalized, 0.95)), 6),
    }


def _load_labeled_evaluation(
    path: Path, feature_order: Sequence[str]
) -> tuple[np.ndarray, np.ndarray]:
    parquet_file = pq.ParquetFile(path)
    required = {*feature_order, "is_anomaly"}
    missing = required - set(parquet_file.schema_arrow.names)
    if missing:
        raise AnomalyTrainingError(
            f"Labeled evaluation dataset missing columns: {', '.join(sorted(missing))}"
        )
    rows: list[list[float]] = []
    labels: list[bool] = []
    for batch in parquet_file.iter_batches(columns=[*feature_order, "is_anomaly"]):
        for row in batch.to_pylist():
            label = row.get("is_anomaly")
            if not isinstance(label, bool):
                raise AnomalyTrainingError("is_anomaly must contain boolean labels")
            values: list[float] = []
            for feature in feature_order:
                value = row.get(feature)
                if value is None:
                    values.append(float("nan"))
                elif isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise AnomalyTrainingError(f"Evaluation feature {feature} is not numeric")
                elif not math.isfinite(float(value)):
                    raise AnomalyTrainingError(f"Evaluation feature {feature} is NaN or infinite")
                else:
                    values.append(float(value))
            rows.append(values)
            labels.append(label)
    if not rows:
        raise AnomalyTrainingError("Labeled evaluation dataset has no rows")
    return np.asarray(rows, dtype=float), np.asarray(labels, dtype=bool)


def _labeled_metrics(model: Pipeline, features: np.ndarray, labels: np.ndarray) -> dict[str, Any]:
    predicted = np.asarray(model.predict(features)) == -1
    return {
        "sample_count": int(len(labels)),
        "anomaly_count": int(np.sum(labels)),
        "accuracy": round(float(accuracy_score(labels, predicted)), 6),
        "anomaly_precision": round(
            float(precision_score(labels, predicted, pos_label=True, zero_division=0)), 6
        ),
        "anomaly_recall": round(
            float(recall_score(labels, predicted, pos_label=True, zero_division=0)), 6
        ),
        "anomaly_f1": round(
            float(f1_score(labels, predicted, pos_label=True, zero_division=0)), 6
        ),
        "confusion_matrix_labels": ["normal", "suspicious"],
        "confusion_matrix": confusion_matrix(labels, predicted, labels=[False, True]).tolist(),
    }


def train_anomaly_detector(config: AnomalyTrainingConfig) -> dict[str, Any]:
    """Fit Isolation Forest on normal-reference groups and persist metrics."""

    config.validate()
    data = load_training_dataset(config.dataset_path)
    split_config = TrainingConfig(
        dataset_path=config.dataset_path,
        models_dir=config.model_path.parent,
        metrics_path=config.metrics_path,
        random_seed=config.random_seed,
        test_fraction=config.test_fraction,
        validation_fraction=config.validation_fraction,
        n_jobs=config.n_jobs,
    )
    splits = split_group_safe(data, split_config)
    reference_indices = np.concatenate((splits.train, splits.validation))
    entirely_missing = [
        feature
        for column, feature in enumerate(data.feature_order)
        if np.all(np.isnan(data.features[reference_indices, column]))
    ]
    if entirely_missing:
        raise AnomalyTrainingError(
            "Normal-reference data has entirely missing features: "
            + ", ".join(entirely_missing)
        )
    model = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                IsolationForest(
                    n_estimators=config.n_estimators,
                    contamination=config.contamination,
                    random_state=config.random_seed,
                    n_jobs=config.n_jobs,
                ),
            ),
        ]
    )
    model.fit(data.features[reference_indices])
    raw_reference_scores = -np.asarray(
        model.score_samples(data.features[reference_indices]), dtype=float
    )
    low_quantile, high_quantile = config.normalization_quantiles
    normalization_low = float(np.quantile(raw_reference_scores, low_quantile))
    normalization_high = float(np.quantile(raw_reference_scores, high_quantile))
    if normalization_high <= normalization_low:
        normalization_high = normalization_low + np.finfo(float).eps
    classifier = model.named_steps["classifier"]
    raw_threshold = -float(classifier.offset_)
    normalized_threshold = float(
        _normalize(
            np.asarray([raw_threshold], dtype=float), normalization_low, normalization_high
        )[0]
    )

    generated_at = datetime.now(UTC).isoformat()
    model_version = f"isolation-forest-{data.dataset_sha256[:12]}"
    metrics: dict[str, Any] = {
        "status": "complete",
        "generated_at": generated_at,
        "method": METHOD,
        "model_version": model_version,
        "reference_samples": int(len(reference_indices)),
        "normalized_suspicious_threshold": round(normalized_threshold, 6),
        "held_out_normal": _normal_metrics(
            model,
            data.features[splits.test],
            normalization_low,
            normalization_high,
        ),
        "labeled_evaluation": None,
        "reference_assumption": (
            "The supervised training dataset is treated as normal-reference traffic; "
            "application class labels are not anomaly labels."
        ),
    }
    if config.evaluation_dataset_path is not None:
        evaluation_features, evaluation_labels = _load_labeled_evaluation(
            config.evaluation_dataset_path, data.feature_order
        )
        metrics["labeled_evaluation"] = _labeled_metrics(
            model, evaluation_features, evaluation_labels
        )

    metadata = {
        "generated_at": generated_at,
        "method": METHOD,
        "model_version": model_version,
        "training_dataset_sha256": data.dataset_sha256,
        "feature_order": data.feature_order,
        "normalization": {
            "method": "clipped_quantile_min_max",
            "quantiles": list(config.normalization_quantiles),
            "raw_score_low": normalization_low,
            "raw_score_high": normalization_high,
        },
        "raw_suspicious_threshold": raw_threshold,
        "normalized_suspicious_threshold": normalized_threshold,
        "config": {
            **{
                key: value
                for key, value in asdict(config).items()
                if not isinstance(value, Path)
            },
            "dataset_path": str(config.dataset_path),
            "model_path": str(config.model_path),
            "metadata_path": str(config.metadata_path),
            "metrics_path": str(config.metrics_path),
            "evaluation_dataset_path": (
                str(config.evaluation_dataset_path)
                if config.evaluation_dataset_path is not None
                else None
            ),
        },
        "separation_from_unknown": (
            "Anomaly means statistically unusual flow behavior. UNKNOWN means the traffic "
            "classifier lacks confidence. Neither implies the other."
        ),
    }
    _atomic_joblib(model, config.model_path)
    _atomic_json(metadata, config.metadata_path)
    _atomic_json(metrics, config.metrics_path)
    LOGGER.info(
        "Trained Isolation Forest anomaly baseline on %d normal samples",
        len(reference_indices),
    )
    return metrics


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=service_root / "config" / "model.yaml")
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        train_anomaly_detector(load_anomaly_training_config(args.config))
    except (AnomalyTrainingError, TrainingError) as error:
        LOGGER.error("Anomaly training failed: %s", error)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()

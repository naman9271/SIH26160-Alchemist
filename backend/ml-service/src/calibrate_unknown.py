"""Calibrate confidence-threshold UNKNOWN rejection without retraining.

The selected persisted classifier is evaluated across configured thresholds on
its group-safe known holdout and on eligible held-out-class or unseen-source
Parquet records. Maximum-probability rejection is only a baseline open-set
method; it is not a guarantee that every novel traffic type will be detected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pyarrow.parquet as pq
import yaml

from src.train import TrainingConfig, TrainingError, load_training_dataset, split_group_safe
from src.unknown_detection import UNKNOWN_LABEL, validate_threshold

LOGGER = logging.getLogger(__name__)
METHOD = "max_class_probability_threshold"
LIMITATION = (
    "Confidence-threshold rejection is a baseline open-set method and cannot "
    "perfectly detect every unknown or out-of-distribution traffic type."
)


class CalibrationError(ValueError):
    """Raised when UNKNOWN calibration inputs are invalid or unsafe."""


@dataclass(frozen=True)
class CalibrationConfig:
    """Resolved paths and policy values loaded from ``config/model.yaml``."""

    config_path: Path
    training_dataset_path: Path
    models_dir: Path
    training_metrics_path: Path
    metrics_path: Path
    candidate_thresholds: tuple[float, ...]
    ood_dataset_paths: tuple[Path, ...]


def _resolve_path(config_path: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise CalibrationError(f"{field} must be a non-empty path")
    path = Path(value)
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def load_calibration_config(
    config_path: Path,
    *,
    extra_ood_paths: Sequence[Path] = (),
    threshold_override: Sequence[float] = (),
) -> CalibrationConfig:
    """Load and validate the model configuration."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise CalibrationError(f"Could not read model config {config_path}: {error}") from error
    if not isinstance(raw, Mapping):
        raise CalibrationError("Model configuration must be a mapping")
    model = raw.get("model")
    unknown = raw.get("unknown_detection")
    if not isinstance(model, Mapping) or not isinstance(unknown, Mapping):
        raise CalibrationError("Model configuration needs model and unknown_detection mappings")
    if unknown.get("method") != METHOD:
        raise CalibrationError(f"unknown_detection.method must be {METHOD!r}")

    raw_thresholds = list(threshold_override) or unknown.get("candidate_thresholds")
    if not isinstance(raw_thresholds, list) or len(raw_thresholds) < 2:
        raise CalibrationError("At least two candidate thresholds are required")
    try:
        thresholds = tuple(sorted({validate_threshold(float(value)) for value in raw_thresholds}))
    except (TypeError, ValueError) as error:
        raise CalibrationError(f"Invalid candidate threshold: {error}") from error
    if len(thresholds) < 2:
        raise CalibrationError("At least two distinct candidate thresholds are required")

    configured_ood = unknown.get("ood_dataset_paths", [])
    if not isinstance(configured_ood, list) or not all(isinstance(item, str) for item in configured_ood):
        raise CalibrationError("ood_dataset_paths must be a list of paths")
    ood_paths = [
        _resolve_path(config_path, value, "ood_dataset_paths") for value in configured_ood
    ]
    ood_paths.extend(path.resolve() for path in extra_ood_paths)

    return CalibrationConfig(
        config_path=config_path.resolve(),
        training_dataset_path=_resolve_path(
            config_path, model.get("training_dataset_path"), "model.training_dataset_path"
        ),
        models_dir=_resolve_path(config_path, model.get("models_dir"), "model.models_dir"),
        training_metrics_path=_resolve_path(
            config_path, model.get("training_metrics_path"), "model.training_metrics_path"
        ),
        metrics_path=_resolve_path(
            config_path,
            unknown.get("calibration_metrics_path"),
            "unknown_detection.calibration_metrics_path",
        ),
        candidate_thresholds=thresholds,
        ood_dataset_paths=tuple(dict.fromkeys(ood_paths)),
    )


def _atomic_json(value: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _atomic_yaml(value: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(yaml.safe_dump(dict(value), sort_keys=False), encoding="utf-8")
    temporary.replace(path)


def _blocked(config: CalibrationConfig, reason: str, missing: Sequence[Path] = ()) -> dict[str, Any]:
    report = {
        "status": "blocked",
        "generated_at": datetime.now(UTC).isoformat(),
        "method": METHOD,
        "chosen_threshold": None,
        "reason": reason,
        "missing_required_artifacts": [str(path) for path in missing],
        "limitation": LIMITATION,
    }
    _atomic_json(report, config.metrics_path)
    return report


def _selected_model_path(models_dir: Path, training_metrics_path: Path) -> tuple[str, Path]:
    try:
        metrics = json.loads(training_metrics_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CalibrationError(f"Could not read training metrics: {error}") from error
    selected = metrics.get("selected_model")
    filenames = {
        "random_forest": "random_forest.joblib",
        "xgboost": "xgboost.joblib",
    }
    if selected not in filenames:
        raise CalibrationError("Training metrics do not identify a supported selected_model")
    return str(selected), models_dir / filenames[str(selected)]


def _training_sources(dataset_path: Path) -> set[str]:
    table = pq.read_table(dataset_path, columns=["audit_metadata"])
    sources: set[str] = set()
    for value in table.column("audit_metadata").to_pylist():
        if isinstance(value, Mapping) and isinstance(value.get("dataset_source"), str):
            sources.add(str(value["dataset_source"]))
    return sources


def _feature_row(row: Mapping[str, Any], feature_order: Sequence[str], source: Path) -> list[float]:
    values: list[float] = []
    for feature in feature_order:
        value = row.get(feature)
        if value is None:
            values.append(float("nan"))
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CalibrationError(f"{source} feature {feature} is not numeric")
        elif not math.isfinite(float(value)):
            raise CalibrationError(f"{source} feature {feature} is NaN or infinite")
        else:
            values.append(float(value))
    return values


def load_ood_features(
    paths: Sequence[Path],
    feature_order: Sequence[str],
    fitted_classes: set[str],
    training_sources: set[str],
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Load and group-split OOD records into calibration and final evaluation."""

    calibration_rows: list[list[float]] = []
    evaluation_rows: list[list[float]] = []
    per_path: dict[str, dict[str, Any]] = {}
    basis_counts: Counter[str] = Counter()
    for path in paths:
        if not path.is_file():
            raise CalibrationError(f"OOD dataset does not exist: {path}")
        parquet_file = pq.ParquetFile(path)
        columns = set(parquet_file.schema_arrow.names)
        missing_features = set(feature_order) - columns
        if missing_features:
            raise CalibrationError(
                f"{path} lacks fitted features: {', '.join(sorted(missing_features))}"
            )
        available_metadata = [column for column in (
            "canonical_label", "dataset_source", "split_group_id", "capture_id"
        ) if column in columns]
        if not available_metadata:
            raise CalibrationError(
                f"{path} needs canonical_label or dataset_source to establish OOD eligibility"
            )
        selected = 0
        skipped = 0
        if not ({"split_group_id", "capture_id"} & columns):
            raise CalibrationError(
                f"{path} needs split_group_id or capture_id for independent OOD partitions"
            )
        read_columns = [*feature_order, *available_metadata]
        for batch in parquet_file.iter_batches(columns=read_columns, batch_size=65_536):
            for row in batch.to_pylist():
                label = row.get("canonical_label")
                source = row.get("dataset_source")
                basis: str | None = None
                if isinstance(label, str) and label not in fitted_classes:
                    basis = "class_absent_from_fitted_model"
                elif isinstance(source, str) and source not in training_sources:
                    basis = "dataset_source_absent_from_training"
                if basis is None:
                    skipped += 1
                    continue
                group = row.get("split_group_id") or row.get("capture_id")
                if not isinstance(group, str) or not group:
                    raise CalibrationError(f"{path} contains an OOD record without a group identity")
                feature_row = _feature_row(row, feature_order, path)
                # A stable group assignment prevents records from one capture
                # appearing in both threshold selection and final OOD metrics.
                bucket = int(hashlib.sha256(group.encode("utf-8")).hexdigest()[:8], 16) % 5
                if bucket == 0:
                    evaluation_rows.append(feature_row)
                else:
                    calibration_rows.append(feature_row)
                basis_counts[basis] += 1
                selected += 1
        per_path[str(path)] = {"selected_ood_records": selected, "skipped_records": skipped}
    if not calibration_rows or not evaluation_rows:
        raise CalibrationError("OOD data needs enough independent groups for calibration and final evaluation")
    return np.asarray(calibration_rows, dtype=float), np.asarray(evaluation_rows, dtype=float), {
        "sample_count": len(calibration_rows) + len(evaluation_rows),
        "calibration_sample_count": len(calibration_rows),
        "final_evaluation_sample_count": len(evaluation_rows),
		"partition_method": "sha256_group_mod_5",
        "selection_basis_counts": dict(sorted(basis_counts.items())),
        "datasets": per_path,
    }


def _probabilities(model: Any, features: np.ndarray, expected_classes: int) -> np.ndarray:
    probabilities = np.asarray(model.predict_proba(features), dtype=float)
    if probabilities.ndim != 2 or probabilities.shape != (len(features), expected_classes):
        raise CalibrationError("Model probability output does not match model class metadata")
    if not np.all(np.isfinite(probabilities)):
        raise CalibrationError("Model returned NaN or infinite probabilities")
    return probabilities


def _threshold_metrics(
    thresholds: Sequence[float],
    known_labels: np.ndarray,
    known_probabilities: np.ndarray,
    unknown_probabilities: np.ndarray,
    class_order: Sequence[str],
) -> list[dict[str, Any]]:
    known_confidence = np.max(known_probabilities, axis=1)
    unknown_confidence = np.max(unknown_probabilities, axis=1)
    known_predictions = np.asarray(class_order, dtype=str)[np.argmax(known_probabilities, axis=1)]
    outcomes: list[dict[str, Any]] = []
    for threshold in thresholds:
        known_rejected = known_confidence < threshold
        unknown_rejected = unknown_confidence < threshold
        known_correct = (~known_rejected) & (known_predictions == known_labels)
        known_accuracy = float(np.mean(known_correct))
        false_unknown_rate = float(np.mean(known_rejected))
        unknown_detection_rate = float(np.mean(unknown_rejected))
        outcomes.append(
            {
                "threshold": threshold,
                "known_traffic_accuracy": round(known_accuracy, 6),
                "known_closed_set_accuracy": round(
                    float(np.mean(known_predictions == known_labels)), 6
                ),
                "false_unknown_rate": round(false_unknown_rate, 6),
                "unknown_detection_rate": round(unknown_detection_rate, 6),
                "average_confidence_known": round(float(np.mean(known_confidence)), 6),
                "average_confidence_unknown": round(float(np.mean(unknown_confidence)), 6),
                "balanced_open_set_score": round(
                    (known_accuracy + unknown_detection_rate) / 2, 6
                ),
            }
        )
    return outcomes


def _persist_threshold(
    config: CalibrationConfig,
    metadata_path: Path,
    threshold: float,
    report: Mapping[str, Any],
) -> None:
    raw_config = yaml.safe_load(config.config_path.read_text(encoding="utf-8"))
    raw_config["unknown_detection"]["confidence_threshold"] = threshold
    _atomic_yaml(raw_config, config.config_path)

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["unknown_detection"] = {
        "status": "calibrated",
        "method": METHOD,
        "confidence_threshold": threshold,
        "calibrated_at": report["generated_at"],
        "calibration_metrics": str(config.metrics_path),
        "limitation": LIMITATION,
    }
    _atomic_json(metadata, metadata_path)


def calibrate_unknown(config: CalibrationConfig) -> dict[str, Any]:
    """Choose and persist a threshold from held-out known and OOD probabilities."""

    metadata_path = config.models_dir / "model_metadata.json"
    required = [config.training_dataset_path, metadata_path, config.training_metrics_path]
    missing = [path for path in required if not path.is_file()]
    if missing:
        return _blocked(
            config,
            "Required trained-model artifacts are unavailable; UNKNOWN calibration was not run.",
            missing,
        )
    if not config.ood_dataset_paths:
        return _blocked(
            config,
            "No OOD datasets are configured. Add held-out classes or unseen dataset sources before calibration.",
        )

    selected_model, model_path = _selected_model_path(
        config.models_dir, config.training_metrics_path
    )
    if not model_path.is_file():
        return _blocked(config, "The selected persisted classifier is unavailable.", [model_path])

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    class_order = metadata.get("class_order")
    feature_order = metadata.get("feature_order")
    if not isinstance(class_order, list) or not all(isinstance(item, str) for item in class_order):
        raise CalibrationError("Model metadata class_order is invalid")
    if not isinstance(feature_order, list) or not all(isinstance(item, str) for item in feature_order):
        raise CalibrationError("Model metadata feature_order is invalid")

    data = load_training_dataset(config.training_dataset_path)
    if data.feature_order != feature_order:
        raise CalibrationError("Training dataset feature order differs from model metadata")
    stored_config = metadata.get("config") or {}
    split_config = TrainingConfig(
        dataset_path=config.training_dataset_path,
        models_dir=config.models_dir,
        metrics_path=config.training_metrics_path,
        random_seed=int(stored_config.get("random_seed", 42)),
        test_fraction=float(stored_config.get("test_fraction", 0.2)),
        validation_fraction=float(stored_config.get("validation_fraction", 0.2)),
        n_jobs=int(stored_config.get("n_jobs", -1)),
    )
    splits = split_group_safe(data, split_config)
    ood_calibration_features, ood_evaluation_features, ood_summary = load_ood_features(
        config.ood_dataset_paths,
        feature_order,
        set(class_order),
        _training_sources(config.training_dataset_path),
    )
    if not len(ood_calibration_features):
        return _blocked(
            config,
            "Configured datasets contain no eligible held-out-class or unseen-source OOD records.",
        )

    model = joblib.load(model_path)
    # Threshold selection is a tuning operation. Use the validation partition
    # so the locked test partition remains untouched for final evaluation.
    known_indices = splits.validation
    known_probabilities = _probabilities(model, data.features[known_indices], len(class_order))
    unknown_probabilities = _probabilities(model, ood_calibration_features, len(class_order))
    threshold_results = _threshold_metrics(
        config.candidate_thresholds,
        data.labels[known_indices],
        known_probabilities,
        unknown_probabilities,
        class_order,
    )
    chosen = max(
        threshold_results,
        key=lambda item: (
            item["balanced_open_set_score"],
            item["known_traffic_accuracy"],
            item["unknown_detection_rate"],
            -item["threshold"],
        ),
    )
    final_ood_probabilities = _probabilities(
        model, ood_evaluation_features, len(class_order)
    )
    final_ood_rejection_rate = float(
        np.mean(np.max(final_ood_probabilities, axis=1) < float(chosen["threshold"]))
    )
    report = {
        "status": "complete",
        "generated_at": datetime.now(UTC).isoformat(),
        "method": METHOD,
        "selected_model": selected_model,
        "model_version": metadata.get("model_version", "unknown"),
        "selection_metric": "balanced_open_set_score",
        "chosen_threshold": chosen["threshold"],
        "chosen_threshold_metrics": chosen,
        "threshold_results": threshold_results,
        "known_samples": int(len(known_indices)),
        "known_calibration_partition": "validation",
        "locked_test_samples_untouched": int(len(splits.test)),
        "unknown_samples": int(len(ood_calibration_features)),
		"final_ood_samples": int(len(ood_evaluation_features)),
		"final_ood_rejection_rate": round(final_ood_rejection_rate, 6),
        "known_split_strategy": splits.strategy,
        "ood_summary": ood_summary,
        "limitation": LIMITATION,
    }
    _atomic_json(report, config.metrics_path)
    _persist_threshold(config, metadata_path, float(chosen["threshold"]), report)
    LOGGER.info(
        "Selected UNKNOWN confidence threshold %.3f from %d candidates",
        chosen["threshold"],
        len(threshold_results),
    )
    return report


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=service_root / "config" / "model.yaml")
    parser.add_argument(
        "--ood-dataset",
        type=Path,
        action="append",
        default=[],
        help="Additional preprocessed OOD Parquet path; may be repeated.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        action="append",
        default=[],
        help="Override candidate threshold; provide at least two values.",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        config = load_calibration_config(
            args.config,
            extra_ood_paths=args.ood_dataset,
            threshold_override=args.threshold,
        )
        calibrate_unknown(config)
    except (CalibrationError, TrainingError) as error:
        LOGGER.error("UNKNOWN calibration failed: %s", error)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()

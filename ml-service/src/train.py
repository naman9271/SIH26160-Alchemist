"""Train group-safe Random Forest and XGBoost traffic classifiers.

The input is ``data/processed/training_dataset.parquet`` created by
``src.build_dataset``. UNKNOWN threshold calibration remains a separate step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import joblib
import numpy as np
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from src.datasets.base import CANONICAL_LABELS

LOGGER = logging.getLogger(__name__)

TARGET_COLUMN = "canonical_label"
GROUP_COLUMN = "split_group_id"
SPLIT_COLUMN = "split"
AUDIT_COLUMN = "audit_metadata"
NON_FEATURE_COLUMNS = {TARGET_COLUMN, GROUP_COLUMN, SPLIT_COLUMN, AUDIT_COLUMN}
FORBIDDEN_FEATURE_NAMES = {
    "dataset_source",
    "original_label",
    "capture_id",
    "source_record_id",
    "flow_id",
    "filename",
    "file_name",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "timestamp",
}


class TrainingError(ValueError):
    """Raised when a group-safe supervised training run is not possible."""


@dataclass(frozen=True)
class TrainingConfig:
    dataset_path: Path
    models_dir: Path
    metrics_path: Path
    random_seed: int = 42
    test_fraction: float = 0.2
    validation_fraction: float = 0.2
    n_jobs: int = -1

    def validate(self) -> None:
        if not self.dataset_path.is_file():
            raise TrainingError(f"Training dataset does not exist: {self.dataset_path}")
        if not 0 < self.test_fraction < 1:
            raise TrainingError("test_fraction must be within (0, 1)")
        if not 0 < self.validation_fraction < 1:
            raise TrainingError("validation_fraction must be within (0, 1)")
        if self.test_fraction + self.validation_fraction >= 1:
            raise TrainingError("test_fraction + validation_fraction must be below 1")


@dataclass(frozen=True)
class DatasetData:
    features: np.ndarray
    labels: np.ndarray
    groups: np.ndarray
    feature_order: list[str]
    dataset_sha256: str


@dataclass(frozen=True)
class GroupSplits:
    train: np.ndarray
    validation: np.ndarray
    test: np.ndarray
    strategy: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_training_dataset(path: Path) -> DatasetData:
    """Load only top-level numeric model features; audit metadata never enters X."""

    parquet_file = pq.ParquetFile(path)
    columns = parquet_file.schema_arrow.names
    required = {TARGET_COLUMN, GROUP_COLUMN, AUDIT_COLUMN}
    missing = required - set(columns)
    if missing:
        raise TrainingError(f"Training dataset missing columns: {', '.join(sorted(missing))}")
    feature_order = [column for column in columns if column not in NON_FEATURE_COLUMNS]
    if not feature_order:
        raise TrainingError("Training dataset has no model feature columns")
    unexpected = [
        column
        for column in feature_order
        if column.casefold() in FORBIDDEN_FEATURE_NAMES
        or column.casefold().endswith("_id")
        or "label" in column.casefold()
        or "timestamp" in column.casefold()
    ]
    if unexpected:
        raise TrainingError(f"Potential metadata leaked into feature columns: {', '.join(unexpected)}")

    table = pq.read_table(path, columns=[*feature_order, TARGET_COLUMN, GROUP_COLUMN])
    records = table.to_pylist()
    if not records:
        raise TrainingError("Training dataset has no rows")

    labels: list[str] = []
    groups: list[str] = []
    rows: list[list[float]] = []
    for row_number, row in enumerate(records, start=1):
        label = row.get(TARGET_COLUMN)
        group = row.get(GROUP_COLUMN)
        if label not in CANONICAL_LABELS:
            raise TrainingError(f"Row {row_number} has an unsupported canonical label: {label!r}")
        if not isinstance(group, str) or not group:
            raise TrainingError(f"Row {row_number} has no split_group_id")
        feature_row: list[float] = []
        for feature in feature_order:
            value = row.get(feature)
            if value is None:
                feature_row.append(float("nan"))
            elif isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TrainingError(f"Row {row_number} feature {feature} is not numeric")
            elif not math.isfinite(float(value)):
                raise TrainingError(f"Row {row_number} feature {feature} is NaN or infinite")
            else:
                feature_row.append(float(value))
        labels.append(label)
        groups.append(group)
        rows.append(feature_row)
    return DatasetData(
        features=np.asarray(rows, dtype=float),
        labels=np.asarray(labels, dtype=str),
        groups=np.asarray(groups, dtype=str),
        feature_order=feature_order,
        dataset_sha256=_sha256(path),
    )


def _group_class_counts(labels: np.ndarray, groups: np.ndarray) -> Counter[str]:
    groups_per_class: dict[str, set[str]] = {}
    for label, group in zip(labels, groups):
        groups_per_class.setdefault(str(label), set()).add(str(group))
    return Counter({label: len(values) for label, values in groups_per_class.items()})


def _stratified_group_split(
    indices: np.ndarray,
    labels: np.ndarray,
    groups: np.ndarray,
    desired_fraction: float,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, str]:
    """Split indices by group, preferring stratification when class groups permit it."""

    scoped_labels = labels[indices]
    scoped_groups = groups[indices]
    group_counts = _group_class_counts(scoped_labels, scoped_groups)
    preferred_splits = max(2, round(1 / desired_fraction))
    maximum_splits = min(len(set(scoped_groups)), min(group_counts.values(), default=0))
    if maximum_splits >= 2:
        n_splits = min(preferred_splits, maximum_splits)
        splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
        train_relative, held_out_relative = next(
            splitter.split(np.zeros(len(indices)), scoped_labels, scoped_groups)
        )
        return indices[train_relative], indices[held_out_relative], "StratifiedGroupKFold"

    splitter = GroupShuffleSplit(n_splits=1, test_size=desired_fraction, random_state=seed)
    train_relative, held_out_relative = next(
        splitter.split(np.zeros(len(indices)), scoped_labels, scoped_groups)
    )
    return indices[train_relative], indices[held_out_relative], "GroupShuffleSplit (stratification unavailable)"


def _assert_group_separation(groups: np.ndarray, splits: GroupSplits) -> None:
    split_groups = [set(groups[index]) for index in (splits.train, splits.validation, splits.test)]
    if any(left & right for position, left in enumerate(split_groups) for right in split_groups[position + 1 :]):
        raise TrainingError("A split_group_id appears in more than one split")


def split_group_safe(data: DatasetData, config: TrainingConfig) -> GroupSplits:
    """Create train/validation/test partitions without ever splitting a group."""

    if len(set(data.groups)) < 3:
        raise TrainingError("At least three distinct split_group_id values are required")
    all_indices = np.arange(len(data.labels))
    train_validation, test, outer_strategy = _stratified_group_split(
        all_indices, data.labels, data.groups, config.test_fraction, config.random_seed
    )
    validation_share = config.validation_fraction / (1 - config.test_fraction)
    train, validation, inner_strategy = _stratified_group_split(
        train_validation,
        data.labels,
        data.groups,
        validation_share,
        config.random_seed + 1,
    )
    splits = GroupSplits(
        train=train,
        validation=validation,
        test=test,
        strategy=f"test: {outer_strategy}; validation: {inner_strategy}",
    )
    _assert_group_separation(data.groups, splits)
    missing_train_classes = sorted(set(data.labels) - set(data.labels[splits.train]))
    if missing_train_classes:
        raise TrainingError(
            "Group-safe split left classes absent from training: " + ", ".join(missing_train_classes)
        )
    if len(set(data.labels[splits.train])) < 2:
        raise TrainingError("Training split needs at least two classes")
    return splits


def _metrics(y_true: np.ndarray, y_pred: np.ndarray, classes: Sequence[str]) -> dict[str, Any]:
    """Compute requested aggregate, per-class, and confusion-matrix metrics."""

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )
    macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, average="macro", zero_division=0
    )
    _, _, weighted_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, average="weighted", zero_division=0
    )
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "macro_precision": round(float(macro_precision), 6),
        "macro_recall": round(float(macro_recall), 6),
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


def _random_forest_candidates(seed: int, n_jobs: int) -> list[tuple[str, Pipeline]]:
    return [
        (
            "baseline",
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    (
                        "classifier",
                        RandomForestClassifier(
                            n_estimators=200,
                            max_depth=None,
                            min_samples_leaf=1,
                            class_weight="balanced_subsample",
                            random_state=seed,
                            n_jobs=n_jobs,
                        ),
                    ),
                ]
            ),
        ),
        (
            "regularized",
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    (
                        "classifier",
                        RandomForestClassifier(
                            n_estimators=300,
                            max_depth=16,
                            min_samples_leaf=2,
                            class_weight="balanced_subsample",
                            random_state=seed,
                            n_jobs=n_jobs,
                        ),
                    ),
                ]
            ),
        ),
    ]


def _xgboost_candidates(seed: int, n_jobs: int, num_classes: int) -> list[tuple[str, Pipeline]]:
    common = {
        "objective": "multi:softprob",
        "num_class": num_classes,
        "eval_metric": "mlogloss",
        "random_state": seed,
        "n_jobs": n_jobs,
        "tree_method": "hist",
    }
    return [
        (
            "baseline",
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    (
                        "classifier",
                        XGBClassifier(
                            n_estimators=150,
                            max_depth=6,
                            learning_rate=0.1,
                            subsample=0.9,
                            colsample_bytree=0.9,
                            **common,
                        ),
                    ),
                ]
            ),
        ),
        (
            "regularized",
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    (
                        "classifier",
                        XGBClassifier(
                            n_estimators=250,
                            max_depth=4,
                            learning_rate=0.05,
                            subsample=0.9,
                            colsample_bytree=0.8,
                            min_child_weight=2,
                            reg_lambda=1.5,
                            **common,
                        ),
                    ),
                ]
            ),
        ),
    ]


def _fit_best_candidate(
    candidates: Sequence[tuple[str, Pipeline]],
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_validation: np.ndarray,
    y_validation: np.ndarray,
    classes: Sequence[str],
    xgb_weighting: bool,
) -> tuple[str, Pipeline, list[dict[str, Any]]]:
    outcomes: list[dict[str, Any]] = []
    best_name: str | None = None
    best_model: Pipeline | None = None
    best_score = -1.0
    sample_weight = compute_sample_weight(class_weight="balanced", y=y_train)
    for name, model in candidates:
        fit_arguments: dict[str, Any] = {}
        if xgb_weighting:
            fit_arguments["classifier__sample_weight"] = sample_weight
        model.fit(x_train, y_train, **fit_arguments)
        validation_metrics = _metrics(y_validation, model.predict(x_validation), classes)
        outcomes.append({"name": name, "validation_metrics": validation_metrics})
        score = float(validation_metrics["macro_f1"])
        if score > best_score:
            best_name, best_model, best_score = name, model, score
    assert best_name is not None and best_model is not None
    return best_name, best_model, outcomes


def _refit_and_evaluate(
    model: Pipeline,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_validation: np.ndarray,
    y_validation: np.ndarray,
    x_test: np.ndarray,
    y_test: np.ndarray,
    classes: Sequence[str],
    xgb_weighting: bool,
) -> tuple[Pipeline, dict[str, Any]]:
    x_train_validation = np.concatenate((x_train, x_validation))
    y_train_validation = np.concatenate((y_train, y_validation))
    fit_arguments: dict[str, Any] = {}
    if xgb_weighting:
        fit_arguments["classifier__sample_weight"] = compute_sample_weight(
            class_weight="balanced", y=y_train_validation
        )
    model.fit(x_train_validation, y_train_validation, **fit_arguments)
    return model, _metrics(y_test, model.predict(x_test), classes)


def _atomic_joblib_dump(value: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    joblib.dump(value, temporary_path)
    temporary_path.replace(path)


def _atomic_json_dump(value: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary_path.replace(path)


def train_models(config: TrainingConfig) -> dict[str, Any]:
    """Select and persist the better of two small model families by macro F1."""

    config.validate()
    data = load_training_dataset(config.dataset_path)
    splits = split_group_safe(data, config)
    label_encoder = LabelEncoder().fit(data.labels[splits.train])
    classes = list(label_encoder.classes_)
    encoded_labels = label_encoder.transform(data.labels)

    x_train, y_train = data.features[splits.train], encoded_labels[splits.train]
    x_validation, y_validation = data.features[splits.validation], encoded_labels[splits.validation]
    x_test, y_test = data.features[splits.test], encoded_labels[splits.test]
    class_names = list(label_encoder.inverse_transform(np.arange(len(classes))))

    rf_name, rf_model, rf_candidates = _fit_best_candidate(
        _random_forest_candidates(config.random_seed, config.n_jobs),
        x_train,
        y_train,
        x_validation,
        y_validation,
        list(range(len(classes))),
        xgb_weighting=False,
    )
    xgb_name, xgb_model, xgb_candidates = _fit_best_candidate(
        _xgboost_candidates(config.random_seed, config.n_jobs, len(classes)),
        x_train,
        y_train,
        x_validation,
        y_validation,
        list(range(len(classes))),
        xgb_weighting=True,
    )
    rf_final, rf_test_metrics = _refit_and_evaluate(
        rf_model,
        x_train,
        y_train,
        x_validation,
        y_validation,
        x_test,
        y_test,
        list(range(len(classes))),
        xgb_weighting=False,
    )
    xgb_final, xgb_test_metrics = _refit_and_evaluate(
        xgb_model,
        x_train,
        y_train,
        x_validation,
        y_validation,
        x_test,
        y_test,
        list(range(len(classes))),
        xgb_weighting=True,
    )

    # Convert numeric metric labels back to canonical class strings.
    for metrics in (rf_test_metrics, xgb_test_metrics):
        metrics["per_class"] = {
            class_names[int(label)]: value for label, value in metrics["per_class"].items()
        }
        metrics["confusion_matrix_labels"] = class_names
    for candidates in (rf_candidates, xgb_candidates):
        for candidate in candidates:
            validation_metrics = candidate["validation_metrics"]
            validation_metrics["per_class"] = {
                class_names[int(label)]: value
                for label, value in validation_metrics["per_class"].items()
            }
            validation_metrics["confusion_matrix_labels"] = class_names

    better_model = (
        "random_forest"
        if rf_test_metrics["macro_f1"] >= xgb_test_metrics["macro_f1"]
        else "xgboost"
    )
    rf_path = config.models_dir / "random_forest.joblib"
    xgb_path = config.models_dir / "xgboost.joblib"
    _atomic_joblib_dump(rf_final, rf_path)
    _atomic_joblib_dump(xgb_final, xgb_path)

    split_counts = {
        name: dict(sorted(Counter(data.labels[indices]).items()))
        for name, indices in (
            ("train", splits.train),
            ("validation", splits.validation),
            ("test", splits.test),
        )
    }
    metrics = {
        "generated_at": datetime.now(UTC).isoformat(),
        "selection_metric": "macro_f1",
        "selected_model": better_model,
        "models": {
            "random_forest": {
                "selected_candidate": rf_name,
                "candidates": rf_candidates,
                "test_metrics": rf_test_metrics,
            },
            "xgboost": {
                "selected_candidate": xgb_name,
                "candidates": xgb_candidates,
                "test_metrics": xgb_test_metrics,
            },
        },
        "split_class_counts": split_counts,
    }
    metadata = {
        "generated_at": metrics["generated_at"],
        "model_version": f"traffic-classifier-{data.dataset_sha256[:12]}",
        "training_dataset": str(config.dataset_path),
        "training_dataset_sha256": data.dataset_sha256,
        "feature_order": data.feature_order,
        "class_order": class_names,
        "group_split_strategy": splits.strategy,
        "config": {
            **{
                key: value
                for key, value in asdict(config).items()
                if not isinstance(value, Path)
            },
            "dataset_path": str(config.dataset_path),
            "models_dir": str(config.models_dir),
            "metrics_path": str(config.metrics_path),
        },
        "artifacts": {
            "random_forest": str(rf_path),
            "xgboost": str(xgb_path),
            "metrics": str(config.metrics_path),
        },
        "unknown_detection": {
            "status": "not_calibrated",
            "method": "max_class_probability_threshold",
            "confidence_threshold": None,
        },
        "metadata_excluded_from_features": sorted(NON_FEATURE_COLUMNS),
    }
    _atomic_json_dump(metrics, config.metrics_path)
    _atomic_json_dump(metadata, config.models_dir / "model_metadata.json")
    LOGGER.info("Selected %s by test macro F1", better_model)
    return metrics


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
        "--metrics", type=Path, default=service_root / "artifacts" / "training_metrics.json"
    )
    parser.add_argument("--random-seed", type=int, default=42)
    parser.add_argument("--test-fraction", type=float, default=0.2)
    parser.add_argument("--validation-fraction", type=float, default=0.2)
    parser.add_argument("--n-jobs", type=int, default=-1)
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        train_models(
            TrainingConfig(
                dataset_path=args.dataset,
                models_dir=args.models_dir,
                metrics_path=args.metrics,
                random_seed=args.random_seed,
                test_fraction=args.test_fraction,
                validation_fraction=args.validation_fraction,
                n_jobs=args.n_jobs,
            )
        )
    except TrainingError as error:
        LOGGER.error("Training was not run: %s", error)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()

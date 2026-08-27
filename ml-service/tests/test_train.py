"""Tests for reproducible group-safe model training."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

pytest.importorskip("xgboost")

from src.train import (
    DatasetData,
    TrainingConfig,
    TrainingError,
    load_training_dataset,
    split_group_safe,
    train_models,
)


def training_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    class_offsets = {"web": 1.0, "video": 10.0, "voip": 20.0}
    for label, offset in class_offsets.items():
        for group_number in range(4):
            group = f"{label}-capture-{group_number}"
            for record_number in range(2):
                rows.append(
                    {
                        "duration": offset + group_number + record_number / 10,
                        "idle_time_ratio": 0.1 * group_number,
                        "canonical_label": label,
                        "split_group_id": group,
                        "split": "train",
                        "audit_metadata": {
                            "dataset_source": "fixture",
                            "original_label": label.upper(),
                            "capture_id": f"{group}.pcap",
                            "source_record_id": f"{group}-{record_number}",
                            "flow_id": f"flow-{group}-{record_number}",
                            "excluded_leakage_columns": ["flow_id"],
                            "input_file": "fixture.parquet",
                        },
                    }
                )
    return rows


def write_training_dataset(path: Path) -> None:
    table = pa.Table.from_pylist(training_rows())
    pq.write_table(table, path)


def test_group_split_has_no_overlap_and_keeps_all_classes_in_train(tmp_path: Path) -> None:
    dataset_path = tmp_path / "training_dataset.parquet"
    write_training_dataset(dataset_path)
    data = load_training_dataset(dataset_path)
    config = TrainingConfig(
        dataset_path=dataset_path,
        models_dir=tmp_path / "models",
        metrics_path=tmp_path / "metrics.json",
        random_seed=7,
    )

    splits = split_group_safe(data, config)
    train_groups = set(data.groups[splits.train])
    validation_groups = set(data.groups[splits.validation])
    test_groups = set(data.groups[splits.test])

    assert not train_groups & validation_groups
    assert not train_groups & test_groups
    assert not validation_groups & test_groups
    assert set(data.labels) == set(data.labels[splits.train])
    assert "StratifiedGroupKFold" in splits.strategy


def test_train_models_persists_models_metrics_and_feature_order(tmp_path: Path) -> None:
    dataset_path = tmp_path / "training_dataset.parquet"
    models_dir = tmp_path / "models"
    metrics_path = tmp_path / "artifacts" / "training_metrics.json"
    write_training_dataset(dataset_path)

    metrics = train_models(
        TrainingConfig(
            dataset_path=dataset_path,
            models_dir=models_dir,
            metrics_path=metrics_path,
            random_seed=7,
            n_jobs=1,
        )
    )
    metadata = json.loads((models_dir / "model_metadata.json").read_text(encoding="utf-8"))

    assert (models_dir / "random_forest.joblib").is_file()
    assert (models_dir / "xgboost.joblib").is_file()
    assert metrics_path.is_file()
    assert metadata["feature_order"] == ["duration", "idle_time_ratio"]
    assert metadata["unknown_detection"] == "not implemented"
    assert metrics["selection_metric"] == "macro_f1"
    for model in metrics["models"].values():
        test_metrics = model["test_metrics"]
        assert {"accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1"} <= set(
            test_metrics
        )
        assert set(test_metrics["per_class"]) == {"video", "voip", "web"}


def test_rejects_feature_metadata_column(tmp_path: Path) -> None:
    dataset_path = tmp_path / "training_dataset.parquet"
    table = pa.Table.from_pylist(
        [
            {
                "dataset_source": "leak",
                "canonical_label": "web",
                "split_group_id": "group",
                "audit_metadata": {"dataset_source": "leak"},
            }
        ]
    )
    pq.write_table(table, dataset_path)

    with pytest.raises(TrainingError, match="Potential metadata"):
        load_training_dataset(dataset_path)


def test_group_split_rejects_class_without_train_group(tmp_path: Path) -> None:
    data = DatasetData(
        features=np.asarray([[1.0], [2.0], [3.0], [4.0]]),
        labels=np.asarray(["web", "web", "video", "video"]),
        groups=np.asarray(["web-group", "web-group", "video-group", "video-group"]),
        feature_order=["duration"],
        dataset_sha256="fixture",
    )
    config = TrainingConfig(
        dataset_path=tmp_path / "unused.parquet",
        models_dir=tmp_path / "models",
        metrics_path=tmp_path / "metrics.json",
    )

    with pytest.raises(TrainingError):
        split_group_safe(data, config)

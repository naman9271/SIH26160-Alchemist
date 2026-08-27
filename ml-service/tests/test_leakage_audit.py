"""Tests for leakage and source-memorization experiments."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pyarrow as pa
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from src.build_dataset import training_arrow_schema
from src.leakage_audit import audit_leakage, write_report
from src.train import TrainingConfig, load_training_dataset, split_group_safe


def write_leaky_training_fixture(path: Path) -> None:
    rows: list[dict[str, object]] = []
    offsets = {"web": 1.0, "video": 10.0, "voip": 20.0}
    for label, class_offset in offsets.items():
        for group_number in range(4):
            source = "source-a" if group_number % 2 == 0 else "source-b"
            group = f"{source}:{label}:{group_number}"
            for record_number in range(2):
                rows.append(
                    {
                        "duration": class_offset + record_number / 10,
                        # Deliberately source-specific so the audit has a known signal.
                        "mean_packet_size": 100.0 if source == "source-a" else 1000.0,
                        "canonical_label": label,
                        "split_group_id": group,
                        "split": "train",
                        "audit_metadata": {
                            "dataset_source": source,
                            "original_label": label.upper(),
                            "capture_id": f"{group}.pcap",
                            "source_record_id": f"{group}:{record_number}",
                            "flow_id": f"flow:{group}:{record_number}",
                            "excluded_leakage_columns": ["capture_id"],
                            "input_file": f"{source}.parquet",
                        },
                    }
                )
    pq.write_table(
        pa.Table.from_pylist(rows, schema=training_arrow_schema(["duration", "mean_packet_size"])),
        path,
    )


def prepare_trained_fixture(root: Path) -> tuple[Path, Path, Path]:
    dataset_path = root / "training_dataset.parquet"
    models_dir = root / "models"
    metrics_path = root / "training_metrics.json"
    models_dir.mkdir()
    write_leaky_training_fixture(dataset_path)
    data = load_training_dataset(dataset_path)
    config = TrainingConfig(
        dataset_path=dataset_path,
        models_dir=models_dir,
        metrics_path=metrics_path,
        random_seed=11,
        n_jobs=1,
    )
    splits = split_group_safe(data, config)
    train_validation = list(splits.train) + list(splits.validation)
    encoder = LabelEncoder().fit(data.labels[splits.train])
    model = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=80,
                    random_state=11,
                    class_weight="balanced_subsample",
                    n_jobs=1,
                ),
            ),
        ]
    )
    model.fit(data.features[train_validation], encoder.transform(data.labels[train_validation]))
    joblib.dump(model, models_dir / "random_forest.joblib")
    (models_dir / "model_metadata.json").write_text(
        json.dumps(
            {
                "feature_order": data.feature_order,
                "class_order": list(encoder.classes_),
                "config": {
                    "random_seed": 11,
                    "test_fraction": 0.2,
                    "validation_fraction": 0.2,
                    "n_jobs": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    metrics_path.write_text(json.dumps({"selected_model": "random_forest"}), encoding="utf-8")
    return dataset_path, models_dir, metrics_path


def test_blocked_audit_reports_missing_artifacts_and_concrete_fixes(tmp_path: Path) -> None:
    report = audit_leakage(
        dataset_path=tmp_path / "training_dataset.parquet",
        models_dir=tmp_path / "models",
        training_metrics_path=tmp_path / "training_metrics.json",
    )

    assert report["status"] == "blocked"
    assert len(report["missing_required_artifacts"]) == 3
    assert report["recommendations"]


def test_audit_runs_source_holdout_importance_and_ablation(tmp_path: Path) -> None:
    dataset_path, models_dir, metrics_path = prepare_trained_fixture(tmp_path)

    report = audit_leakage(
        dataset_path=dataset_path,
        models_dir=models_dir,
        training_metrics_path=metrics_path,
        source_association_threshold=0.5,
        top_feature_count=2,
    )

    assert report["status"] == "complete"
    assert report["normal_grouped_test"]["macro_f1"] >= 0
    assert set(report["leave_one_source_out"]) == {"source-a", "source-b"}
    assert all(item["status"] == "complete" for item in report["leave_one_source_out"].values())
    assert report["feature_importance"][0]["feature"] in {"duration", "mean_packet_size"}
    assert report["feature_source_association"][0] == {
        "feature": "mean_packet_size",
        "source_eta_squared": 1.0,
    }
    assert "mean_packet_size" in report["suspicious_high_importance_features"]
    assert report["ablation_without_suspicious_features"]["status"] == "complete"
    assert set(report["per_source_test_performance"]) <= {"source-a", "source-b"}

    output = tmp_path / "leakage_audit.md"
    write_report(report, output)
    text = output.read_text(encoding="utf-8")
    assert text.index("## Recommended fixes") < text.index("## 1. Normal grouped test evaluation")

"""Build a reproducible supervised dataset from validated public outputs.

The builder consumes only features explicitly approved by
``artifacts/feature_validation.json``. It does not train a model, balance
classes by duplication, or expose audit metadata as model features.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from src.datasets.base import CANONICAL_LABELS, MODEL_FEATURE_COLUMNS
from src.preprocess import INTEGER_FEATURES

LOGGER = logging.getLogger(__name__)

TRAINING_DATASET_NAME = "training_dataset.parquet"
AUDIT_METADATA_FIELDS = (
    "dataset_source",
    "original_label",
    "capture_id",
    "source_record_id",
    "flow_id",
    "excluded_leakage_columns",
    "input_file",
    "declared_split",
)
FORBIDDEN_MODEL_COLUMNS = {
    "dataset_source",
    "original_label",
    "canonical_label",
    "capture_id",
    "source_record_id",
    "flow_id",
    "split_group_id",
    "split",
    "excluded_leakage_columns",
    "filename",
    "file_name",
    "source_ip",
    "destination_ip",
    "src_ip",
    "dst_ip",
    "timestamp",
}


class DatasetBuildError(ValueError):
    """Raised when validated inputs cannot produce a safe supervised dataset."""


@dataclass(frozen=True)
class BuildConfig:
    processed_dir: Path
    feature_validation_path: Path
    output_path: Path
    summary_path: Path
    minimum_samples_per_class: int = 1
    test_fraction: float = 0.2
    split_seed: str = "sih-ipsec-v1"
    feature_recommendation: str = "safe_across_public_datasets"
    excluded_features: tuple[str, ...] = ()
    max_records_per_group: int | None = None

    def validate(self) -> None:
        if self.minimum_samples_per_class < 1:
            raise DatasetBuildError("minimum_samples_per_class must be at least 1")
        if not 0 < self.test_fraction < 1:
            raise DatasetBuildError("test_fraction must be within (0, 1)")
        if not self.split_seed:
            raise DatasetBuildError("split_seed must not be empty")
        if self.feature_recommendation not in {
            "safe_across_public_datasets",
            "usable_only_for_our_ipsec_dataset",
        }:
            raise DatasetBuildError("unsupported feature recommendation scope")
        if self.max_records_per_group is not None and self.max_records_per_group < 1:
            raise DatasetBuildError("max_records_per_group must be positive")


@dataclass(frozen=True)
class CandidateRecord:
    features: Mapping[str, int | float | None]
    canonical_label: str
    split_group_id: str
    declared_split: str | None
    audit_metadata: Mapping[str, Any]


def _complete_class_counts(counts: Mapping[str, int]) -> dict[str, int]:
    """Return an explicit seven-class matrix row, including zero contributions."""

    return {label: int(counts.get(label, 0)) for label in sorted(CANONICAL_LABELS)}


def load_safe_features(
    validation_path: Path,
    recommendation: str = "safe_across_public_datasets",
    excluded_features: Sequence[str] = (),
) -> list[str]:
    """Load the machine-readable validation decision and reject unsafe names."""

    try:
        report = json.loads(validation_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DatasetBuildError(f"Could not read feature validation {validation_path}: {error}") from error

    recommendations = report.get("recommendations")
    if not isinstance(recommendations, Mapping):
        raise DatasetBuildError("Feature validation has no recommendations object")
    raw_features = recommendations.get(recommendation)
    if not isinstance(raw_features, list) or not all(isinstance(item, str) for item in raw_features):
        raise DatasetBuildError(f"{recommendation} must be a list of feature names")

    safe_features = [
        feature for feature in dict.fromkeys(raw_features) if feature not in set(excluded_features)
    ]
    forbidden = sorted(set(safe_features) & FORBIDDEN_MODEL_COLUMNS)
    if forbidden:
        raise DatasetBuildError(f"Feature validation marked leakage columns safe: {', '.join(forbidden)}")
    unknown = sorted(
        set(safe_features) - set(MODEL_FEATURE_COLUMNS) - FORBIDDEN_MODEL_COLUMNS
    )
    if unknown:
        raise DatasetBuildError(f"Feature validation contains unknown features: {', '.join(unknown)}")
    if not safe_features:
        raise DatasetBuildError(
            "Feature validation approves no public features or usable scoped features after exclusions; "
            "generate processed datasets and rerun "
            "python -m src.validate_features before building"
        )
    return safe_features


def source_parquet_paths(processed_dir: Path, output_path: Path) -> list[Path]:
    """Select independent adapter outputs while excluding the builder's own output."""

    if not processed_dir.is_dir():
        raise DatasetBuildError(f"Processed directory does not exist: {processed_dir}")
    output_resolved = output_path.resolve()
    paths = sorted(
        path
        for path in processed_dir.glob("*.parquet")
        if path.resolve() != output_resolved
        and path.name != TRAINING_DATASET_NAME
        and not path.stem.endswith(("-ood", "-anomaly-evaluation"))
    )
    if not paths:
        raise DatasetBuildError(f"No processed source Parquet files found in {processed_dir}")
    return paths


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_from_row(
    row: Mapping[str, Any], safe_features: Sequence[str], input_file: str
) -> tuple[CandidateRecord | None, str | None]:
    label = row.get("canonical_label")
    if label == "IGNORE":
        return None, "canonical label is IGNORE"
    if label not in CANONICAL_LABELS:
        return None, "canonical label is unsupported or missing"

    split_group_id = row.get("split_group_id")
    if not isinstance(split_group_id, str) or not split_group_id.strip():
        return None, "split_group_id is missing"
    dataset_source = row.get("dataset_source")
    if not isinstance(dataset_source, str) or not dataset_source.strip():
        return None, "dataset_source audit metadata is missing"

    features: dict[str, int | float | None] = {}
    non_null_features = 0
    for feature in safe_features:
        value = row.get(feature)
        if value is None:
            features[feature] = None
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, f"safe feature {feature} is not numeric"
        if isinstance(value, float) and not math.isfinite(value):
            return None, f"safe feature {feature} is NaN or infinite"
        features[feature] = value
        non_null_features += 1
    if not non_null_features:
        return None, "all approved features are missing"

    metadata = {
        "dataset_source": dataset_source,
        "original_label": row.get("original_label"),
        "capture_id": row.get("capture_id"),
        "source_record_id": row.get("source_record_id"),
        "flow_id": row.get("flow_id"),
        "excluded_leakage_columns": row.get("excluded_leakage_columns") or [],
        "input_file": input_file,
        "declared_split": row.get("declared_split"),
        "locked_test_generation": row.get("locked_test_generation"),
    }
    declared_split = row.get("declared_split")
    if declared_split not in {None, "train", "validation", "locked_test"}:
        return None, "declared_split is invalid"
    return (
        CandidateRecord(
            features=features,
            canonical_label=str(label),
            split_group_id=split_group_id,
            declared_split=declared_split,
            audit_metadata=metadata,
        ),
        None,
    )


def iter_candidates(
    paths: Sequence[Path],
    safe_features: Sequence[str],
    skipped_reasons: Counter[str] | None = None,
) -> Iterator[CandidateRecord]:
    """Stream validated candidates; labels are never inferred from features."""

    required_columns = {
        "dataset_source",
        "original_label",
        "canonical_label",
        "capture_id",
        "source_record_id",
        "flow_id",
        "split_group_id",
        "excluded_leakage_columns",
        "declared_split",
        "locked_test_generation",
        *safe_features,
    }
    for path in paths:
        parquet_file = pq.ParquetFile(path)
        missing_columns = required_columns - set(parquet_file.schema_arrow.names)
        if missing_columns:
            raise DatasetBuildError(
                f"{path} is missing required columns: {', '.join(sorted(missing_columns))}"
            )
        for batch in parquet_file.iter_batches(columns=sorted(required_columns), batch_size=65_536):
            for row in batch.to_pylist():
                candidate, reason = _candidate_from_row(row, safe_features, path.name)
                if candidate is None:
                    if skipped_reasons is not None and reason is not None:
                        skipped_reasons[reason] += 1
                    continue
                yield candidate


def split_for_group(group_id: str, test_fraction: float, seed: str) -> str:
    """Assign a whole group deterministically to one split."""

    digest = hashlib.sha256(f"{seed}\0{group_id}".encode("utf-8")).digest()
    fraction = int.from_bytes(digest[:8], "big") / 2**64
    return "test" if fraction < test_fraction else "train"


def training_arrow_schema(safe_features: Sequence[str]) -> pa.Schema:
    """Keep model features top-level and provenance inside one audit struct."""

    fields = [
        pa.field(feature, pa.int64() if feature in INTEGER_FEATURES else pa.float64())
        for feature in safe_features
    ]
    fields.extend(
        [
            pa.field("canonical_label", pa.string(), nullable=False),
            pa.field("split_group_id", pa.string(), nullable=False),
            pa.field("split", pa.string(), nullable=False),
            pa.field(
                "audit_metadata",
                pa.struct(
                    [
                        pa.field("dataset_source", pa.string(), nullable=False),
                        pa.field("original_label", pa.string()),
                        pa.field("capture_id", pa.string()),
                        pa.field("source_record_id", pa.string()),
                        pa.field("flow_id", pa.string()),
                        pa.field("excluded_leakage_columns", pa.list_(pa.string())),
                        pa.field("input_file", pa.string(), nullable=False),
                        pa.field("declared_split", pa.string()),
                        pa.field("locked_test_generation", pa.string()),
                    ]
                ),
                nullable=False,
            ),
        ]
    )
    return pa.schema(fields)


def _output_row(candidate: CandidateRecord, split: str) -> dict[str, Any]:
    return {
        **candidate.features,
        "canonical_label": candidate.canonical_label,
        "split_group_id": candidate.split_group_id,
        "split": split,
        "audit_metadata": dict(candidate.audit_metadata),
    }


def _write_training_data(
    candidates: Iterable[CandidateRecord],
    eligible_classes: set[str],
    safe_features: Sequence[str],
    config: BuildConfig,
) -> tuple[int, dict[str, Any]]:
    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = config.output_path.with_name(f".{config.output_path.name}.tmp")
    schema = training_arrow_schema(safe_features)
    writer: pq.ParquetWriter | None = None
    batch: list[dict[str, Any]] = []
    total = 0
    class_counts: Counter[str] = Counter()
    split_counts: dict[str, Counter[str]] = defaultdict(Counter)
    contributions: dict[str, Counter[str]] = defaultdict(Counter)
    group_splits: dict[str, str] = {}
    records_per_group: Counter[str] = Counter()
    capped_records = 0

    def flush() -> None:
        nonlocal writer, total
        if not batch:
            return
        table = pa.Table.from_pylist(batch, schema=schema)
        writer = writer or pq.ParquetWriter(temporary_path, schema=schema, compression="snappy")
        writer.write_table(table)
        total += len(batch)
        batch.clear()

    try:
        for candidate in candidates:
            if candidate.canonical_label not in eligible_classes:
                continue
            if (
                config.max_records_per_group is not None
                and records_per_group[candidate.split_group_id] >= config.max_records_per_group
            ):
                capped_records += 1
                continue
            records_per_group[candidate.split_group_id] += 1
            split = (
                "test"
                if candidate.declared_split == "locked_test"
                else candidate.declared_split
            ) or split_for_group(candidate.split_group_id, config.test_fraction, config.split_seed)
            previous_split = group_splits.setdefault(candidate.split_group_id, split)
            if previous_split != split:
                raise DatasetBuildError(
                    f"split group {candidate.split_group_id!r} appears in multiple splits"
                )
            batch.append(_output_row(candidate, split))
            class_counts[candidate.canonical_label] += 1
            split_counts[split][candidate.canonical_label] += 1
            contributions[str(candidate.audit_metadata["dataset_source"])][
                candidate.canonical_label
            ] += 1
            if len(batch) >= 10_000:
                flush()
        flush()
        if writer is None:
            raise DatasetBuildError("No records remain after applying minimum class counts")
        writer.close()
        writer = None
        temporary_path.replace(config.output_path)
    except Exception:
        if writer is not None:
            writer.close()
        temporary_path.unlink(missing_ok=True)
        raise

    return total, {
        "class_counts": _complete_class_counts(class_counts),
        "split_class_counts": {
            split: _complete_class_counts(counts) for split, counts in sorted(split_counts.items())
        },
        "class_counts_per_source_dataset": {
            source: _complete_class_counts(counts) for source, counts in sorted(contributions.items())
        },
        "group_count": len(group_splits),
        "groups_in_multiple_splits": [],
        "records_dropped_by_group_cap": capped_records,
    }


def _write_summary(summary: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary_path.replace(path)


def build_training_dataset(config: BuildConfig) -> dict[str, Any]:
    """Build one supervised dataset from independently validated source files."""

    config.validate()
    safe_features = load_safe_features(
        config.feature_validation_path,
        config.feature_recommendation,
        config.excluded_features,
    )
    paths = source_parquet_paths(config.processed_dir, config.output_path)
    skipped_reasons: Counter[str] = Counter()
    pre_minimum_counts: Counter[str] = Counter()
    pre_minimum_contributions: dict[str, Counter[str]] = defaultdict(Counter)

    for candidate in iter_candidates(paths, safe_features, skipped_reasons):
        pre_minimum_counts[candidate.canonical_label] += 1
        pre_minimum_contributions[str(candidate.audit_metadata["dataset_source"])][
            candidate.canonical_label
        ] += 1

    eligible_classes = {
        label
        for label, count in pre_minimum_counts.items()
        if count >= config.minimum_samples_per_class
    }
    dropped_for_minimum = {
        label: count
        for label, count in sorted(pre_minimum_counts.items())
        if label not in eligible_classes
    }
    if not eligible_classes:
        raise DatasetBuildError(
            "No canonical class meets the configured minimum sample count of "
            f"{config.minimum_samples_per_class}"
        )

    total, output_stats = _write_training_data(
        iter_candidates(paths, safe_features), eligible_classes, safe_features, config
    )
    summary = {
        "status": "complete",
        "generated_at": datetime.now(UTC).isoformat(),
        "output_path": str(config.output_path),
        "row_count": total,
        "safe_model_features": safe_features,
        "feature_recommendation": config.feature_recommendation,
        "excluded_features": list(config.excluded_features),
        "max_records_per_group": config.max_records_per_group,
        "target_column": "canonical_label",
        "group_column": "split_group_id",
        "split_column": "split",
        "audit_metadata_column": "audit_metadata",
        "audit_metadata_fields": list(AUDIT_METADATA_FIELDS),
        "minimum_samples_per_class": config.minimum_samples_per_class,
        "test_fraction": config.test_fraction,
        "split_seed": config.split_seed,
        "eligible_classes": sorted(eligible_classes),
        "pre_minimum_class_counts": _complete_class_counts(pre_minimum_counts),
        "pre_minimum_class_counts_per_source_dataset": {
            source: _complete_class_counts(counts)
            for source, counts in sorted(pre_minimum_contributions.items())
        },
        "classes_absent_from_inputs": sorted(CANONICAL_LABELS - set(pre_minimum_counts)),
        "classes_dropped_for_minimum_samples": dropped_for_minimum,
        "skipped_rows": {
            "total": sum(skipped_reasons.values()),
            "by_reason": dict(sorted(skipped_reasons.items())),
        },
        "input_manifest": [
            {
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
            for path in paths
        ],
        "balancing": "No rows were duplicated or synthetically balanced.",
        "leakage_controls": [
            f"Only feature_validation {config.feature_recommendation} fields are model features.",
            "Source labels, dataset identity, filenames, IDs, and adapter leakage flags are nested "
            "inside audit_metadata.",
            "Source-declared train/validation/locked_test partitions are preserved when present; "
            "otherwise each split_group_id is assigned deterministically.",
        ],
        **output_stats,
    }
    _write_summary(summary, config.summary_path)
    LOGGER.info("Wrote %d supervised rows to %s", total, config.output_path)
    return summary


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    processed_dir = Path(
        os.environ.get("ML_PROCESSED_DATA_DIR", service_root / "data" / "processed")
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed-dir", type=Path, default=processed_dir)
    parser.add_argument(
        "--feature-validation",
        type=Path,
        default=Path(
            os.environ.get(
                "ML_FEATURE_VALIDATION_PATH",
                service_root / "artifacts" / "feature_validation.json",
            )
        ),
    )
    parser.add_argument(
        "--feature-recommendation",
        choices=("safe_across_public_datasets", "usable_only_for_our_ipsec_dataset"),
        default=os.environ.get("ML_FEATURE_RECOMMENDATION", "safe_across_public_datasets"),
    )
    parser.add_argument("--exclude-feature", action="append", default=[])
    parser.add_argument("--max-records-per-group", type=int)
    parser.add_argument(
        "--output",
        type=Path,
        default=processed_dir / TRAINING_DATASET_NAME,
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=service_root / "artifacts" / "training_dataset_summary.json",
    )
    parser.add_argument(
        "--minimum-samples-per-class",
        type=int,
        default=int(os.environ.get("ML_MINIMUM_SAMPLES_PER_CLASS", "1")),
    )
    parser.add_argument(
        "--test-fraction",
        type=float,
        default=float(os.environ.get("ML_TEST_FRACTION", "0.2")),
    )
    parser.add_argument(
        "--split-seed",
        default=os.environ.get("ML_SPLIT_SEED", "sih-ipsec-v1"),
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        build_training_dataset(
            BuildConfig(
                processed_dir=args.processed_dir,
                feature_validation_path=args.feature_validation,
                output_path=args.output,
                summary_path=args.summary,
                minimum_samples_per_class=args.minimum_samples_per_class,
                test_fraction=args.test_fraction,
                split_seed=args.split_seed,
                feature_recommendation=args.feature_recommendation,
                excluded_features=tuple(args.exclude_feature),
                max_records_per_group=args.max_records_per_group,
            )
        )
    except DatasetBuildError as error:
        LOGGER.error("Training dataset was not built: %s", error)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()

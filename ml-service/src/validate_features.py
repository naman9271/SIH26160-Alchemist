"""Validate independently generated processed Parquet datasets.

Run with ``python -m src.validate_features``. This audit never trains a model
and does not modify the input Parquet files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from src.datasets.base import MODEL_FEATURE_COLUMNS, NUMERIC_FEATURE_COLUMNS

LOGGER = logging.getLogger(__name__)

METADATA_COLUMNS = {
    "dataset_source",
    "capture_id",
    "source_record_id",
    "original_label",
    "canonical_label",
    "split_group_id",
    "excluded_leakage_columns",
    "flow_id",
}

FEATURE_UNITS = {
    "duration": "seconds",
    "packet_count": "packets",
    "total_bytes": "bytes",
    "packets_per_second": "packets/second",
    "bytes_per_second": "bytes/second",
    "mean_packet_size": "bytes",
    "std_packet_size": "bytes",
    "min_packet_size": "bytes",
    "max_packet_size": "bytes",
    "p25_packet_size": "bytes",
    "median_packet_size": "bytes",
    "p75_packet_size": "bytes",
    "p95_packet_size": "bytes",
    "mean_interarrival_time": "seconds",
    "std_interarrival_time": "seconds",
    "upload_packets": "packets",
    "download_packets": "packets",
    "upload_bytes": "bytes",
    "download_bytes": "bytes",
    "upload_download_ratio": "ratio",
    "burst_count": "bursts",
    "mean_burst_size": "packets/burst",
    "idle_time_ratio": "ratio",
}

IPSEC_ONLY_CANDIDATES = {
    "burst_count",
    "mean_burst_size",
    "idle_time_ratio",
}


class NumericSummary:
    """Streaming numeric summary, including one-vs-rest class correlation data."""

    def __init__(self) -> None:
        self.non_missing = 0
        self.missing = 0
        self.nan = 0
        self.infinity = 0
        self.minimum: float | None = None
        self.maximum: float | None = None
        self.first_value: float | None = None
        self.is_constant = True
        self.sum_value = 0.0
        self.sum_squared = 0.0
        self.by_class: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0, 0.0])

    def add(self, value: Any, label: str | None) -> None:
        if value is None:
            self.missing += 1
            return
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            self.missing += 1
            return
        if math.isnan(numeric):
            self.nan += 1
            return
        if math.isinf(numeric):
            self.infinity += 1
            return

        self.non_missing += 1
        self.sum_value += numeric
        self.sum_squared += numeric * numeric
        self.minimum = numeric if self.minimum is None else min(self.minimum, numeric)
        self.maximum = numeric if self.maximum is None else max(self.maximum, numeric)
        if self.first_value is None:
            self.first_value = numeric
        elif numeric != self.first_value:
            self.is_constant = False
        if label:
            values = self.by_class[label]
            values[0] += 1
            values[1] += numeric
            values[2] += numeric * numeric

    def as_dict(self, row_count: int, threshold: float) -> dict[str, Any]:
        missing_count = self.missing + self.nan + self.infinity
        correlations = self._correlations()
        suspicious = [
            {"class": label, "correlation": correlation}
            for label, correlation in correlations.items()
            if abs(correlation) >= threshold
        ]
        return {
            "non_missing_count": self.non_missing,
            "missing_count": missing_count,
            "missing_percentage": _percentage(missing_count, row_count),
            "nan_count": self.nan,
            "infinity_count": self.infinity,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "constant": self.non_missing > 0 and self.is_constant,
            "one_vs_rest_label_correlations": correlations,
            "suspicious_label_correlations": suspicious,
        }

    def _correlations(self) -> dict[str, float]:
        if self.non_missing < 2:
            return {}
        mean_x = self.sum_value / self.non_missing
        variance_x = self.sum_squared / self.non_missing - mean_x * mean_x
        if variance_x <= 0:
            return {}
        correlations: dict[str, float] = {}
        for label, (class_count, class_sum, _) in self.by_class.items():
            probability = class_count / self.non_missing
            if probability in {0.0, 1.0}:
                continue
            mean_xy = class_sum / self.non_missing
            covariance = mean_xy - mean_x * probability
            correlation = covariance / math.sqrt(variance_x * probability * (1 - probability))
            correlations[label] = round(correlation, 6)
        return dict(sorted(correlations.items()))


def _percentage(numerator: int, denominator: int) -> float:
    return round(100 * numerator / denominator, 4) if denominator else 0.0


def _stable_hash(value: Mapping[str, Any]) -> str:
    rendered = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _feature_record(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "canonical_label": row.get("canonical_label"),
        **{feature: row.get(feature) for feature in MODEL_FEATURE_COLUMNS},
    }


def _file_report(path: Path, correlation_threshold: float) -> dict[str, Any]:
    parquet_file = pq.ParquetFile(path)
    schema = parquet_file.schema_arrow
    columns = set(schema.names)
    summaries = {feature: NumericSummary() for feature in NUMERIC_FEATURE_COLUMNS}
    class_distribution: Counter[str] = Counter()
    dataset_source_distribution: Counter[str] = Counter()
    leakage_flags: Counter[str] = Counter()
    exact_hashes: set[str] = set()
    feature_hashes: set[str] = set()
    exact_duplicates = 0
    feature_duplicates = 0
    row_count = 0

    for batch in parquet_file.iter_batches(batch_size=65_536):
        for row in batch.to_pylist():
            row_count += 1
            label = row.get("canonical_label")
            if label is not None:
                class_distribution[str(label)] += 1
            source = row.get("dataset_source")
            if source is not None:
                dataset_source_distribution[str(source)] += 1
            for value in row.get("excluded_leakage_columns") or []:
                leakage_flags[str(value)] += 1
            for feature, summary in summaries.items():
                summary.add(row.get(feature), str(label) if label is not None else None)

            exact_hash = _stable_hash(row)
            if exact_hash in exact_hashes:
                exact_duplicates += 1
            else:
                exact_hashes.add(exact_hash)
            feature_hash = _stable_hash(_feature_record(row))
            if feature_hash in feature_hashes:
                feature_duplicates += 1
            else:
                feature_hashes.add(feature_hash)

    feature_reports = {
        feature: {
            "available": feature in columns,
            "arrow_type": str(schema.field(feature).type) if feature in columns else None,
            **summaries[feature].as_dict(row_count, correlation_threshold),
        }
        for feature in NUMERIC_FEATURE_COLUMNS
    }
    suspicious = [
        {
            "feature": feature,
            **finding,
        }
        for feature, summary in feature_reports.items()
        for finding in summary["suspicious_label_correlations"]
    ]
    unexpected_columns = sorted(columns - METADATA_COLUMNS - set(NUMERIC_FEATURE_COLUMNS))
    present_metadata = sorted(columns & METADATA_COLUMNS)
    leakage_findings = [
        "Metadata columns are excluded from model features: " + ", ".join(present_metadata)
    ]
    if leakage_flags:
        leakage_findings.append(
            "Adapters flagged possible source leakage: " + ", ".join(sorted(leakage_flags))
        )
    if unexpected_columns:
        leakage_findings.append(
            "Unexpected, unvetted columns must not be model features: "
            + ", ".join(unexpected_columns)
        )
    if suspicious:
        leakage_findings.append(
            "High feature/label correlations require provenance review before model use."
        )

    return {
        "file": str(path),
        "row_count": row_count,
        "columns": schema.names,
        "feature_reports": feature_reports,
        "class_distribution": dict(sorted(class_distribution.items())),
        "dataset_source_distribution": dict(sorted(dataset_source_distribution.items())),
        "duplicate_records": {
            "exact_duplicate_count": exact_duplicates,
            "feature_and_label_duplicate_count": feature_duplicates,
        },
        "suspicious_label_correlations": suspicious,
        "potential_data_leakage": leakage_findings,
        "flagged_source_leakage_columns": dict(sorted(leakage_flags.items())),
        "unexpected_columns": unexpected_columns,
        "mixed_dataset_sources": len(dataset_source_distribution) > 1,
    }


def _aggregate_features(dataset_reports: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    aggregate: dict[str, dict[str, Any]] = {
        feature: {
            "datasets_with_non_null_values": [],
            "datasets_with_schema_column": [],
            "constant_in": [],
            "has_nan_or_inf_in": [],
            "suspicious_correlation_in": [],
        }
        for feature in NUMERIC_FEATURE_COLUMNS
    }
    for report in dataset_reports:
        dataset_name = Path(str(report["file"])).stem
        for feature, feature_report in report["feature_reports"].items():
            if feature_report["available"]:
                aggregate[feature]["datasets_with_schema_column"].append(dataset_name)
            if feature_report["non_missing_count"]:
                aggregate[feature]["datasets_with_non_null_values"].append(dataset_name)
            if feature_report["constant"]:
                aggregate[feature]["constant_in"].append(dataset_name)
            if feature_report["nan_count"] or feature_report["infinity_count"]:
                aggregate[feature]["has_nan_or_inf_in"].append(dataset_name)
            if feature_report["suspicious_label_correlations"]:
                aggregate[feature]["suspicious_correlation_in"].append(dataset_name)
    return aggregate


def _unit_compatibility(feature_aggregate: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    report: dict[str, dict[str, Any]] = {}
    for feature, unit in FEATURE_UNITS.items():
        datasets = feature_aggregate[feature]["datasets_with_non_null_values"]
        if len(datasets) >= 2:
            status = "common-schema unit; review source conversion provenance before combining"
        elif len(datasets) == 1:
            status = "only one processed dataset has values; cross-dataset compatibility untested"
        else:
            status = "no processed values available for unit validation"
        report[feature] = {
            "expected_unit": unit,
            "datasets_with_values": datasets,
            "compatibility": status,
        }
    return report


def _recommendations(
    dataset_reports: list[Mapping[str, Any]], feature_aggregate: Mapping[str, Mapping[str, Any]]
) -> dict[str, list[str] | str]:
    if not dataset_reports:
        return {
            "safe_across_public_datasets": [],
            "usable_only_for_our_ipsec_dataset": sorted(IPSEC_ONLY_CANDIDATES),
            "drop": sorted(METADATA_COLUMNS),
            "note": "No processed Parquet files were found; no numeric feature is empirically approved.",
        }

    safe: list[str] = []
    own_ipsec: list[str] = []
    drop: set[str] = set(METADATA_COLUMNS)
    for feature, summary in feature_aggregate.items():
        value_datasets = summary["datasets_with_non_null_values"]
        if (
            len(value_datasets) >= 2
            and not summary["constant_in"]
            and not summary["has_nan_or_inf_in"]
            and not summary["suspicious_correlation_in"]
        ):
            safe.append(feature)
        elif feature in IPSEC_ONLY_CANDIDATES or not value_datasets:
            own_ipsec.append(feature)
        if summary["constant_in"] or summary["has_nan_or_inf_in"]:
            drop.add(feature)
    return {
        "safe_across_public_datasets": sorted(safe),
        "usable_only_for_our_ipsec_dataset": sorted(own_ipsec),
        "drop": sorted(drop),
        "note": (
            "Recommendations are audit gates, not training results. Apply group-aware splits and "
            "confirm source-unit provenance before combining any future datasets."
        ),
    }


def validate_processed_features(
    processed_dir: Path, correlation_threshold: float = 0.95
) -> dict[str, Any]:
    """Inspect all immediate ``*.parquet`` files without altering them."""

    if not 0 < correlation_threshold <= 1:
        raise ValueError("correlation_threshold must be within (0, 1]")
    paths = sorted(processed_dir.glob("*.parquet")) if processed_dir.is_dir() else []
    dataset_reports = [_file_report(path, correlation_threshold) for path in paths]
    aggregate = _aggregate_features(dataset_reports)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "processed_directory": str(processed_dir),
        "processed_parquet_file_count": len(paths),
        "correlation_threshold": correlation_threshold,
        "datasets": dataset_reports,
        "features_present_in_only_one_dataset": {
            feature: summary["datasets_with_non_null_values"]
            for feature, summary in aggregate.items()
            if len(summary["datasets_with_non_null_values"]) == 1
        },
        "feature_availability": aggregate,
        "unit_compatibility": _unit_compatibility(aggregate),
        "recommendations": _recommendations(dataset_reports, aggregate),
    }


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render a concise human-readable companion to the machine JSON report."""

    lines = [
        "# Processed Feature Validation",
        "",
        f"Generated: {report['generated_at']}",
        "",
        f"Processed Parquet files inspected: {report['processed_parquet_file_count']}",
        "",
    ]
    if not report["datasets"]:
        lines.extend(
            [
                "No processed Parquet files are currently present. Numeric feature recommendations are "
                "therefore not empirically validated.",
                "",
            ]
        )
    for dataset in report["datasets"]:
        lines.extend(
            [
                f"## {Path(dataset['file']).name}",
                "",
                f"- Rows: {dataset['row_count']}",
                f"- Class distribution: `{json.dumps(dataset['class_distribution'], sort_keys=True)}`",
                "- Dataset-source distribution: "
                f"`{json.dumps(dataset['dataset_source_distribution'], sort_keys=True)}`",
                f"- Duplicates: `{json.dumps(dataset['duplicate_records'], sort_keys=True)}`",
                "- Potential leakage: " + "; ".join(dataset["potential_data_leakage"]),
                "",
                "### Feature checks",
                "",
                "| Feature | Type | Missing % | Range | Constant | NaN/Inf |",
                "| --- | --- | ---: | --- | --- | --- |",
            ]
        )
        for feature, details in dataset["feature_reports"].items():
            value_range = f"{details['minimum']} to {details['maximum']}"
            lines.append(
                f"| {feature} | {details['arrow_type']} | {details['missing_percentage']} | "
                f"{value_range} | {details['constant']} | "
                f"{details['nan_count']}/{details['infinity_count']} |"
            )
        if dataset["suspicious_label_correlations"]:
            lines.extend(
                [
                    "",
                    "### Suspicious feature/label correlations",
                    "",
                    f"`{json.dumps(dataset['suspicious_label_correlations'], sort_keys=True)}`",
                ]
            )
        lines.append("")

    lines.extend(["## Cross-dataset checks", ""])
    only_one = report["features_present_in_only_one_dataset"]
    lines.append(
        "- Features with non-null values in only one dataset: "
        + (json.dumps(only_one, sort_keys=True) if only_one else "none")
    )
    lines.extend(["", "### Unit compatibility"])
    for feature, details in report["unit_compatibility"].items():
        lines.append(
            f"- `{feature}` ({details['expected_unit']}): {details['compatibility']}"
        )

    recommendations = report["recommendations"]
    lines.extend(
        [
            "",
            "## Recommendations",
            "",
            "1. Safe across public datasets: "
            + (", ".join(recommendations["safe_across_public_datasets"]) or "none"),
            "2. Usable only for our own IPsec dataset: "
            + (", ".join(recommendations["usable_only_for_our_ipsec_dataset"]) or "none"),
            "3. Drop: " + ", ".join(recommendations["drop"]),
            "",
            str(recommendations["note"]),
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(report: Mapping[str, Any], artifacts_dir: Path) -> tuple[Path, Path]:
    """Write the requested validation artifacts without touching processed data."""

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    json_path = artifacts_dir / "feature_validation.json"
    markdown_path = artifacts_dir / "feature_validation.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=Path(os.environ.get("ML_PROCESSED_DATA_DIR", service_root / "data" / "processed")),
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path(os.environ.get("ML_AUDIT_ARTIFACTS_DIR", service_root / "artifacts")),
    )
    parser.add_argument(
        "--suspicious-correlation-threshold",
        type=float,
        default=float(os.environ.get("ML_SUSPICIOUS_CORRELATION_THRESHOLD", "0.95")),
        help="Absolute one-vs-rest correlation threshold for review (default: 0.95).",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    report = validate_processed_features(
        args.processed_dir, correlation_threshold=args.suspicious_correlation_threshold
    )
    json_path, markdown_path = write_reports(report, args.artifacts_dir)
    LOGGER.info("Wrote feature validation reports: %s, %s", json_path, markdown_path)


if __name__ == "__main__":
    main()

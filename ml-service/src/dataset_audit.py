"""Audit public traffic datasets without modifying or combining them.

Run from the ML service directory:

    python -m src.dataset_audit

The command reads each top-level entry below ``data/external`` as an independent
dataset and writes JSON and Markdown reports to ``artifacts``. It never writes
to the dataset directory.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)

TARGET_CLASSES = (
    "web",
    "video",
    "voip",
    "email",
    "file_transfer",
    "messaging",
    "icmp",
)

LABEL_COLUMN_NAMES = {
    "label",
    "labels",
    "class",
    "classes",
    "target",
    "category",
    "traffic_type",
    "traffictype",
    "application",
    "app",
    "service",
}

FLOW_FEATURE_ALIASES: Mapping[str, set[str]] = {
    "flow_id": {"flowid", "flow_id"},
    "duration": {"duration", "flowduration", "flow_duration"},
    "packet_count": {"packetcount", "packet_count", "totalpackets", "total_packets"},
    "total_bytes": {"totalbytes", "total_bytes", "flowbytes", "flow_bytes"},
    "packets_per_second": {
        "packetsperssecond",
        "packets_per_second",
        "flowpktsperssecond",
        "flow_pkts_per_second",
    },
    "bytes_per_second": {
        "bytespersecond",
        "bytes_per_second",
        "flowbytespersecond",
        "flow_bytes_per_second",
    },
    "mean_packet_size": {"meanpacketsize", "mean_packet_size", "avgpacketsize"},
    "std_packet_size": {"stdpacketsize", "std_packet_size"},
    "min_packet_size": {"minpacketsize", "min_packet_size"},
    "max_packet_size": {"maxpacketsize", "max_packet_size"},
    "p25_packet_size": {"p25packetsize", "p25_packet_size"},
    "median_packet_size": {"medianpacketsize", "median_packet_size"},
    "p75_packet_size": {"p75packetsize", "p75_packet_size"},
    "p95_packet_size": {"p95packetsize", "p95_packet_size"},
    "mean_interarrival_time": {
        "meaninterarrivaltime",
        "mean_interarrival_time",
        "meanflowiat",
        "mean_flow_iat",
    },
    "std_interarrival_time": {
        "stdinterarrivaltime",
        "std_interarrival_time",
        "stdflowiat",
        "std_flow_iat",
    },
    "upload_packets": {"uploadpackets", "upload_packets", "fwdpackets", "fwd_packets"},
    "download_packets": {"downloadpackets", "download_packets", "bwdpackets", "bwd_packets"},
    "upload_bytes": {"uploadbytes", "upload_bytes", "fwdbytes", "fwd_bytes"},
    "download_bytes": {"downloadbytes", "download_bytes", "bwdbytes", "bwd_bytes"},
    "upload_download_ratio": {"uploaddownloadratio", "upload_download_ratio"},
    "burst_count": {"burstcount", "burst_count"},
    "mean_burst_size": {"meanburstsize", "mean_burst_size"},
    "idle_time_ratio": {"idletimeratio", "idle_time_ratio"},
}

LEAKAGE_TERMS = (
    "filename",
    "file_name",
    "filepath",
    "file_path",
    "pcap",
    "flowid",
    "flow_id",
    "srcip",
    "sourceip",
    "dstip",
    "destinationip",
    "timestamp",
    "time",
    "date",
)

DIRECT_TARGET_MAPPINGS: Mapping[str, str] = {
    "browsing": "web",
    "web": "web",
    "chat": "messaging",
    "amazonprimevideo": "video",
    "video": "video",
    "skype": "voip",
    "facetime": "voip",
    "zoom": "voip",
    "microsoftteams": "voip",
    "gmail": "email",
    "outlook": "email",
    "email": "email",
    "mail": "email",
    "ft": "file_transfer",
    "ftp": "file_transfer",
    "smb": "file_transfer",
    "dropbox": "file_transfer",
    "filetransfer": "file_transfer",
    "whatsapp": "messaging",
    "telegram": "messaging",
    "slack": "messaging",
    "messaging": "messaging",
    "voip": "voip",
    "icmp": "icmp",
}

DO_NOT_MAP_TOKENS = {
    "vpn",
    "cyberghost",
    "hotspotshield",
    "protonvpn",
    "tunnelbear",
    "ultrasurf",
    "tor",
    "nontor",
    "malware",
    "benign",
    "bittorrent",
    "torrent",
    "p2p",
    "spotify",
    "deezer",
    "tunein",
    "itunes",
    "steam",
    "epicgames",
    "worldofwarcraft",
    "mysql",
    "soulseekqt",
}


@dataclass
class TabularFileAudit:
    """Summary collected from one CSV or Parquet file."""

    path: str
    format: str
    row_count: int
    columns: list[str]
    label_columns: list[str]
    unique_labels: dict[str, list[str]]
    class_counts: dict[str, dict[str, int]]
    missing_values: dict[str, int]


@dataclass
class DatasetAudit:
    """Report for one dataset root; data from different roots is never merged."""

    dataset_name: str
    relative_path: str
    file_formats_found: list[str]
    number_of_files: int
    approximate_dataset_size_bytes: int
    approximate_dataset_size_human: str
    raw_pcap_or_pcapng_present: bool
    tabular_files: list[TabularFileAudit]
    csv_or_parquet_column_names: list[str]
    available_label_columns: list[str]
    unique_labels: dict[str, list[str]]
    class_counts: dict[str, dict[str, int]]
    missing_values: dict[str, int]
    inferred_dataset_types: list[str]
    target_class_mappings: list[dict[str, str]]
    unresolved_labels: list[str]
    labels_not_to_map: list[str]
    flow_features_overlap: dict[str, list[str]]
    possible_leakage_columns: list[str]
    notes: list[str] = field(default_factory=list)


def normalized_name(value: str) -> str:
    """Normalize a filename or column name for conservative comparisons."""

    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def is_missing(value: Any) -> bool:
    """Treat nulls, NaN, and blank strings as missing without coercing values."""

    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    return isinstance(value, float) and math.isnan(value)


def human_size(size_bytes: int) -> str:
    """Render a byte count using binary units."""

    value = float(size_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def visible_files(dataset_path: Path) -> Iterator[Path]:
    """Yield non-hidden regular files so Finder metadata is not counted as data."""

    for path in dataset_path.rglob("*"):
        if path.is_file() and not any(part.startswith(".") for part in path.relative_to(dataset_path).parts):
            yield path


def find_label_columns(columns: Sequence[str]) -> list[str]:
    return [column for column in columns if normalized_name(column) in LABEL_COLUMN_NAMES]


def _audit_rows(
    *,
    path: Path,
    format_name: str,
    columns: list[str],
    rows: Iterable[Mapping[str, Any]],
) -> TabularFileAudit:
    label_columns = find_label_columns(columns)
    missing_values = Counter({column: 0 for column in columns})
    label_counts: dict[str, Counter[str]] = {column: Counter() for column in label_columns}
    row_count = 0

    for row in rows:
        row_count += 1
        for column in columns:
            value = row.get(column)
            if is_missing(value):
                missing_values[column] += 1
            elif column in label_counts:
                label_counts[column][str(value)] += 1

    return TabularFileAudit(
        path=str(path),
        format=format_name,
        row_count=row_count,
        columns=columns,
        label_columns=label_columns,
        unique_labels={column: sorted(counts) for column, counts in label_counts.items()},
        class_counts={
            column: dict(sorted(counts.items())) for column, counts in label_counts.items()
        },
        missing_values=dict(missing_values),
    )


def audit_csv(path: Path) -> TabularFileAudit:
    """Stream a CSV file once, preserving columns and categorical labels."""

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as file:
        reader = csv.DictReader(file)
        columns = reader.fieldnames or []
        return _audit_rows(path=path, format_name="csv", columns=columns, rows=reader)


def audit_parquet(path: Path) -> TabularFileAudit:
    """Read Parquet in record batches to avoid loading a whole dataset at once."""

    try:
        import pyarrow.parquet as pq
    except ImportError as error:  # pragma: no cover - exercised by installation guidance
        raise RuntimeError("Parquet auditing requires pyarrow; install requirements.txt") from error

    parquet_file = pq.ParquetFile(path)
    columns = parquet_file.schema_arrow.names

    def rows() -> Iterator[Mapping[str, Any]]:
        for batch in parquet_file.iter_batches(batch_size=65_536):
            yield from batch.to_pylist()

    return _audit_rows(path=path, format_name="parquet", columns=columns, rows=rows())


def classify_dataset_type(text_values: Iterable[str]) -> list[str]:
    normalized_values = [normalized_name(value) for value in text_values]
    normalized = " ".join(normalized_values)
    categories: list[str] = []
    if any(token in normalized for token in ("vpn", "cyberghost", "hotspotshield", "tunnelbear", "ultrasurf")):
        categories.append("VPN")
    if any(value in {"tor", "nontor"} or "tortraffic" in value for value in normalized_values):
        categories.append("Tor")
    if "malware" in normalized:
        categories.append("malware")
    if "benign" in normalized:
        categories.append("benign")
    if any(
        token in normalized
        for token in set(DIRECT_TARGET_MAPPINGS) | {"discord", "spotify", "steam", "facebook", "weibo"}
    ):
        categories.append("application traffic")
    return categories or ["unresolved"]


def labels_from_paths(dataset_path: Path, files: Iterable[Path]) -> set[str]:
    """Collect path components as provenance labels for non-tabular captures."""

    labels: set[str] = set()
    for path in files:
        if path.suffix.casefold() not in {".pcap", ".pcapng"}:
            continue
        components = [
            component
            for component in path.relative_to(dataset_path).parts[:-1]
            if component and component.casefold() not in {"benign", "malware"}
        ]
        labels.update(components)
        stem = re.sub(r"[_-]?\d+$", "", path.stem)
        if stem and normalized_name(stem) not in {normalized_name(item) for item in components}:
            labels.add(stem)
    return labels


def map_labels(labels: Iterable[str]) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Map only explicit labels; ambiguous labels are deliberately unresolved."""

    mappings: list[dict[str, str]] = []
    unresolved: list[str] = []
    do_not_map: list[str] = []
    for label in sorted(set(labels), key=str.casefold):
        key = normalized_name(label)
        vpn_target_key = key.removeprefix("vpn") if key.startswith("vpn") else ""
        if vpn_target_key in DIRECT_TARGET_MAPPINGS:
            mappings.append(
                {
                    "source_label": label,
                    "target_class": DIRECT_TARGET_MAPPINGS[vpn_target_key],
                    "basis": "explicit traffic label with a VPN transport prefix",
                }
            )
        elif vpn_target_key:
            unresolved.append(label)
        elif key in DIRECT_TARGET_MAPPINGS:
            mappings.append(
                {
                    "source_label": label,
                    "target_class": DIRECT_TARGET_MAPPINGS[key],
                    "basis": "explicit dataset label or filename",
                }
            )
        elif key in DO_NOT_MAP_TOKENS or any(token in key for token in DO_NOT_MAP_TOKENS):
            do_not_map.append(label)
        else:
            unresolved.append(label)
    return mappings, unresolved, do_not_map


def feature_overlap(columns: Iterable[str]) -> dict[str, list[str]]:
    """Return only names with an explicit alias to a FlowFeatures field."""

    overlap: dict[str, list[str]] = {}
    for feature, aliases in FLOW_FEATURE_ALIASES.items():
        matches = sorted(column for column in columns if normalized_name(column) in aliases)
        if matches:
            overlap[feature] = matches
    return overlap


def leakage_columns(columns: Iterable[str], has_path_labels: bool) -> list[str]:
    candidates: list[str] = []
    for column in columns:
        key = normalized_name(column)
        if key in LABEL_COLUMN_NAMES or any(term in key for term in LEAKAGE_TERMS):
            candidates.append(column)
    if has_path_labels:
        candidates.append("filename/path-derived labels (capture provenance; never use as a feature)")
    return sorted(set(candidates), key=str.casefold)


def merge_tabular_metadata(
    tabular_files: Iterable[TabularFileAudit],
) -> tuple[list[str], list[str], dict[str, list[str]], dict[str, dict[str, int]], dict[str, int]]:
    columns: set[str] = set()
    label_columns: set[str] = set()
    labels: dict[str, set[str]] = defaultdict(set)
    class_counts: dict[str, Counter[str]] = defaultdict(Counter)
    missing: Counter[str] = Counter()

    for audit in tabular_files:
        columns.update(audit.columns)
        label_columns.update(audit.label_columns)
        for column, values in audit.unique_labels.items():
            labels[column].update(values)
        for column, counts in audit.class_counts.items():
            class_counts[column].update(counts)
        missing.update(audit.missing_values)

    return (
        sorted(columns),
        sorted(label_columns),
        {column: sorted(values) for column, values in sorted(labels.items())},
        {column: dict(sorted(counts.items())) for column, counts in sorted(class_counts.items())},
        dict(sorted(missing.items())),
    )


def audit_dataset(dataset_path: Path, external_root: Path) -> DatasetAudit:
    """Audit one top-level dataset entry without changing it."""

    files = list(visible_files(dataset_path)) if dataset_path.is_dir() else [dataset_path]
    tabular_files: list[TabularFileAudit] = []
    for file_path in files:
        suffix = file_path.suffix.casefold()
        if suffix == ".csv":
            tabular_files.append(audit_csv(file_path))
        elif suffix == ".parquet":
            tabular_files.append(audit_parquet(file_path))

    (
        columns,
        label_columns,
        unique_labels,
        class_counts,
        missing_values,
    ) = merge_tabular_metadata(tabular_files)

    path_labels = labels_from_paths(dataset_path, files) if dataset_path.is_dir() else set()
    tabular_labels = {
        label for labels in unique_labels.values() for label in labels
    }
    mappings, unresolved_labels, labels_not_to_map = map_labels(path_labels | tabular_labels)
    formats = sorted(
        {file_path.suffix.casefold().lstrip(".") or "no_extension" for file_path in files}
    )
    file_text = [dataset_path.name, *(str(path.relative_to(dataset_path)) for path in files)]
    return DatasetAudit(
        dataset_name=dataset_path.name,
        relative_path=str(dataset_path.relative_to(external_root)),
        file_formats_found=formats,
        number_of_files=len(files),
        approximate_dataset_size_bytes=sum(path.stat().st_size for path in files),
        approximate_dataset_size_human=human_size(sum(path.stat().st_size for path in files)),
        raw_pcap_or_pcapng_present=any(
            path.suffix.casefold() in {".pcap", ".pcapng"} for path in files
        ),
        tabular_files=tabular_files,
        csv_or_parquet_column_names=columns,
        available_label_columns=label_columns,
        unique_labels=unique_labels,
        class_counts=class_counts,
        missing_values=missing_values,
        inferred_dataset_types=classify_dataset_type(file_text + list(tabular_labels)),
        target_class_mappings=mappings,
        unresolved_labels=unresolved_labels,
        labels_not_to_map=labels_not_to_map,
        flow_features_overlap=feature_overlap(columns),
        possible_leakage_columns=leakage_columns(columns, bool(path_labels)),
        notes=[
            "No files were modified, and this report does not combine datasets.",
            "Filename/path-derived labels are provenance only and must not become model features.",
        ],
    )


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render a readable companion report without hiding unresolved mappings."""

    lines = [
        "# Dataset Audit",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "Each top-level entry is reported independently. No datasets were combined or modified.",
    ]
    for dataset in report["datasets"]:
        lines.extend(
            [
                "",
                f"## {dataset['dataset_name']}",
                "",
                f"- Files: {dataset['number_of_files']} ({dataset['approximate_dataset_size_human']})",
                f"- Formats: {', '.join(dataset['file_formats_found']) or 'none'}",
                f"- Raw PCAP/PCAPNG present: {dataset['raw_pcap_or_pcapng_present']}",
                f"- Inferred type(s): {', '.join(dataset['inferred_dataset_types'])}",
                f"- Label columns: {', '.join(dataset['available_label_columns']) or 'none'}",
                f"- FlowFeatures overlap: {json.dumps(dataset['flow_features_overlap'], sort_keys=True)}",
                f"- Possible leakage: {', '.join(dataset['possible_leakage_columns']) or 'none'}",
            ]
        )
        lines.extend(["", "### Target-class mappings"])
        if dataset["target_class_mappings"]:
            for mapping in dataset["target_class_mappings"]:
                lines.append(
                    f"- `{mapping['source_label']}` → `{mapping['target_class']}` ({mapping['basis']})"
                )
        else:
            lines.append("- None")
        lines.extend(
            [
                "",
                "### Unresolved labels",
                "",
                ", ".join(dataset["unresolved_labels"]) or "None",
                "",
                "### Labels not to map",
                "",
                ", ".join(dataset["labels_not_to_map"]) or "None",
            ]
        )
        if dataset["tabular_files"]:
            lines.extend(["", "### Tabular details"])
            for table in dataset["tabular_files"]:
                lines.extend(
                    [
                        "",
                        f"#### `{table['path']}`",
                        "",
                        f"- Rows: {table['row_count']}",
                        f"- Columns: {', '.join(table['columns'])}",
                        f"- Unique labels: `{json.dumps(table['unique_labels'], sort_keys=True)}`",
                        f"- Class counts: `{json.dumps(table['class_counts'], sort_keys=True)}`",
                        f"- Missing values: `{json.dumps(table['missing_values'], sort_keys=True)}`",
                    ]
                )
    return "\n".join(lines) + "\n"


def audit_external_datasets(external_root: Path) -> dict[str, Any]:
    """Audit every visible top-level dataset in an external data root."""

    if not external_root.is_dir():
        raise FileNotFoundError(f"External dataset directory does not exist: {external_root}")
    dataset_paths = sorted(
        (path for path in external_root.iterdir() if not path.name.startswith(".")),
        key=lambda path: path.name.casefold(),
    )
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "external_data_root": str(external_root),
        "datasets": [asdict(audit_dataset(path, external_root)) for path in dataset_paths],
    }


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path(os.environ.get("ML_EXTERNAL_DATA_DIR", service_root / "data" / "external")),
        help="External dataset directory (or set ML_EXTERNAL_DATA_DIR).",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path(os.environ.get("ML_AUDIT_ARTIFACTS_DIR", service_root / "artifacts")),
        help="Directory for dataset_audit.json and dataset_audit.md.",
    )
    return parser.parse_args()


def main() -> None:
    """Run the audit CLI and write both report formats."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    report = audit_external_datasets(args.data_root)
    args.artifacts_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.artifacts_dir / "dataset_audit.json"
    markdown_path = args.artifacts_dir / "dataset_audit.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    LOGGER.info("Wrote audit for %d datasets to %s", len(report["datasets"]), args.artifacts_dir)


if __name__ == "__main__":
    main()

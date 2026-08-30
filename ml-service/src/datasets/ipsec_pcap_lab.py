"""Adapter for the project's metadata-labelled encrypted IPsec capture lab."""

from __future__ import annotations

import csv
import hashlib
import logging
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from src.datasets.base import DatasetAdapter, PreprocessedRecord
from src.features import (
    DEFAULT_BURST_GAP_SECONDS,
    DEFAULT_IDLE_GAP_SECONDS,
    DEFAULT_WINDOW_DURATION_SECONDS,
    FeatureExtractionConfig,
    extract_window_features,
)

LOGGER = logging.getLogger(__name__)

REQUIRED_METADATA_COLUMNS = frozenset(
    {"sample_id", "pcap_file", "traffic_class", "sha256"}
)
SUPERVISED_DATASET_ROLE = "train_known"


class IpsecPcapLabAdapter(DatasetAdapter):
    """Read ground truth from metadata.csv, never from capture filenames."""

    cli_name = "ipsec-pcap-lab"
    mapping_dataset_name = "ipsec-pcap-lab"
    input_name = "ipsec-pcap-lab"

    def iter_records(self) -> Iterator[PreprocessedRecord]:
        metadata_path = self.input_path / "metadata.csv"
        if not metadata_path.is_file():
            raise FileNotFoundError(f"Dataset metadata not found: {metadata_path}")
        config = FeatureExtractionConfig(
            window_duration_seconds=DEFAULT_WINDOW_DURATION_SECONDS,
            burst_gap_seconds=DEFAULT_BURST_GAP_SECONDS,
            idle_gap_seconds=DEFAULT_IDLE_GAP_SECONDS,
        )
        with metadata_path.open(encoding="utf-8-sig", newline="") as metadata_file:
            reader = csv.DictReader(metadata_file)
            missing = REQUIRED_METADATA_COLUMNS - set(reader.fieldnames or ())
            if missing:
                raise ValueError(
                    f"ipsec-pcap-lab metadata is missing columns: {', '.join(sorted(missing))}"
                )
            for row_number, row in enumerate(reader, start=2):
                dataset_role = (row.get("dataset_role") or SUPERVISED_DATASET_ROLE).strip()
                if dataset_role != SUPERVISED_DATASET_ROLE:
                    self.total_source_records += 1
                    self.skip(
                        f"metadata row {row_number} has non-supervised dataset_role "
                        f"{dataset_role!r}"
                    )
                    continue
                original_label = (row.get("traffic_class") or "").strip()
                canonical_label = self.canonical_label(original_label)
                if canonical_label is None:
                    self.total_source_records += 1
                    continue
                declared_canonical_label = (row.get("canonical_label") or "").strip()
                if declared_canonical_label and declared_canonical_label != canonical_label:
                    self.total_source_records += 1
                    self.skip(
                        f"metadata row {row_number} canonical_label does not match "
                        "the configured dataset-specific mapping"
                    )
                    continue
                declared_split = (row.get("split") or "").strip() or None
                if declared_split not in {None, "train", "validation", "locked_test"}:
                    self.total_source_records += 1
                    self.skip(
                        f"metadata row {row_number} has invalid supervised split "
                        f"{declared_split!r}"
                    )
                    continue
                capture_path = _safe_capture_path(self.input_path, row.get("pcap_file") or "")
                if capture_path is None:
                    self.total_source_records += 1
                    self.skip(f"metadata row {row_number} has an unsafe pcap_file")
                    continue
                if not capture_path.is_file():
                    self.total_source_records += 1
                    self.skip(f"metadata row {row_number} capture is missing")
                    continue
                expected_hash = (row.get("sha256") or "").strip().casefold()
                if expected_hash and _sha256(capture_path) != expected_hash:
                    self.total_source_records += 1
                    self.skip(f"metadata row {row_number} SHA-256 does not match")
                    continue

                capture_id = capture_path.relative_to(self.input_path.resolve()).as_posix()
                extracted = False
                try:
                    windows = extract_window_features(
                        capture_path,
                        capture_id,
                        config,
                        encrypted_ipsec_only=True,
                    )
                    for features in windows:
                        extracted = True
                        self.total_source_records += 1
                        flow_id = str(features["flow_id"])
                        values = {
                            "dataset_source": self.cli_name,
                            "capture_id": capture_id,
                            "source_record_id": flow_id,
                            "original_label": original_label,
                            "canonical_label": canonical_label,
                            "split_group_id": f"{self.cli_name}:{row.get('sample_id') or capture_id}",
                            "declared_split": declared_split,
                            "excluded_leakage_columns": [
                                "sample_id and capture filename",
                                "traffic_class label",
                                "IPsec/IKE configuration ground truth",
                                "outer source/destination addresses",
                                "traffic generator name",
                                "capture checksum",
                                "flow_id",
                            ],
                            **features,
                        }
                        record = self.validate_record(values, flow_id)
                        if record is not None:
                            yield record
                except (OSError, ValueError) as error:
                    self.total_source_records += 1
                    self.skip(f"capture {capture_id!r} could not be read: {error}")
                    LOGGER.warning("Skipping capture %s: %s", capture_path, error)
                if not extracted:
                    self.total_source_records += 1
                    self.skip(f"capture {capture_id!r} produced no valid encrypted ESP windows")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture_file:
        for block in iter(lambda: capture_file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_capture_path(dataset_root: Path, raw_path: str) -> Path | None:
    """Return a PCAP path confined to ``pcaps/`` without flattening its layout.

    Older manifests used a filename such as ``web_p01.pcap``. Current manifests
    use an explicit relative path such as ``pcaps/known/web/web_p01_R02.pcap``.
    Both forms are accepted; absolute paths, traversal, and non-capture files
    are rejected before touching the filesystem.
    """

    value = raw_path.strip()
    if not value:
        return None
    declared = PurePosixPath(value)
    if declared.is_absolute() or ".." in declared.parts or declared.name in {"", "."}:
        return None
    if declared.suffix.casefold() not in {".pcap", ".pcapng"}:
        return None

    root = dataset_root.resolve()
    capture_root = (root / "pcaps").resolve()
    relative = Path(*declared.parts)
    candidate = (root / relative) if declared.parts[0] == "pcaps" else (capture_root / relative)
    try:
        candidate.resolve().relative_to(capture_root)
    except ValueError:
        return None
    return candidate

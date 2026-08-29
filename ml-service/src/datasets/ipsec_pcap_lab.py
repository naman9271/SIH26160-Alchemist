"""Adapter for the project's metadata-labelled encrypted IPsec capture lab."""

from __future__ import annotations

import csv
import hashlib
import logging
from collections.abc import Iterator
from pathlib import Path

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
                original_label = (row.get("traffic_class") or "").strip()
                canonical_label = self.canonical_label(original_label)
                if canonical_label is None:
                    self.total_source_records += 1
                    continue
                filename = Path((row.get("pcap_file") or "").strip())
                if not filename.name or filename.name != filename.as_posix():
                    self.total_source_records += 1
                    self.skip(f"metadata row {row_number} has an unsafe pcap_file")
                    continue
                capture_path = self.input_path / "pcaps" / filename.name
                if not capture_path.is_file():
                    self.total_source_records += 1
                    self.skip(f"metadata row {row_number} capture is missing")
                    continue
                expected_hash = (row.get("sha256") or "").strip().casefold()
                if expected_hash and _sha256(capture_path) != expected_hash:
                    self.total_source_records += 1
                    self.skip(f"metadata row {row_number} SHA-256 does not match")
                    continue

                capture_id = f"pcaps/{filename.name}"
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

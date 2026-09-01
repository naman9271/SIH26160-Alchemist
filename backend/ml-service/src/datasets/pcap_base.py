"""Shared packet reading for dataset-specific capture adapters."""

from __future__ import annotations

import logging
from abc import abstractmethod
from collections.abc import Iterator
from pathlib import Path

from src.datasets.base import DatasetAdapter, PreprocessedRecord
from src.features import extract_flow_features

LOGGER = logging.getLogger(__name__)


class PcapDatasetAdapter(DatasetAdapter):
    """Base for PCAP datasets; subclasses own path-label interpretation."""

    @abstractmethod
    def original_label_for_capture(self, capture_path: Path) -> str:
        """Return the audited provenance label for one capture."""

    def capture_paths(self) -> list[Path]:
        if not self.input_path.is_dir():
            raise FileNotFoundError(f"Dataset not found: {self.input_path}")
        return sorted(
            path
            for path in self.input_path.rglob("*")
            if path.is_file() and path.suffix.casefold() in {".pcap", ".pcapng"}
        )

    def iter_records(self) -> Iterator[PreprocessedRecord]:
        for capture_path in self.capture_paths():
            capture_id = capture_path.relative_to(self.input_path).as_posix()
            original_label = self.original_label_for_capture(capture_path)
            canonical_label = self.canonical_label(original_label)
            if canonical_label is None:
                self.total_source_records += 1
                continue
            try:
                extracted_any = False
                for features in extract_flow_features(capture_path, capture_id):
                    extracted_any = True
                    self.total_source_records += 1
                    flow_id = str(features["flow_id"])
                    values = {
                        "dataset_source": self.cli_name,
                        "capture_id": capture_id,
                        "source_record_id": flow_id,
                        "original_label": original_label,
                        "canonical_label": canonical_label,
                        "split_group_id": f"{self.cli_name}:{capture_id}",
                        "excluded_leakage_columns": [
                            "capture filename/path label",
                            "flow_id",
                            "source/destination IP and port (used only for grouping; not emitted)",
                        ],
                        **features,
                    }
                    record = self.validate_record(values, flow_id)
                    if record is not None:
                        yield record
                if not extracted_any:
                    self.total_source_records += 1
                    self.skip(f"capture {capture_id!r} produced no valid multi-packet flows")
            except (OSError, ValueError) as error:
                self.total_source_records += 1
                self.skip(f"capture {capture_id!r} could not be read: {error}")
                LOGGER.warning("Skipping capture %s: %s", capture_path, error)

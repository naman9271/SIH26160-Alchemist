"""Adapter for the consolidated CIC-VPN2016-style CSV dataset."""

from __future__ import annotations

import csv
from collections.abc import Iterator, Mapping
from typing import Any

from src.datasets.base import DatasetAdapter, PreprocessedRecord, finite_float


class CicVpn2016Adapter(DatasetAdapter):
    """Convert the audited CSV's available timing/rate columns."""

    cli_name = "cic-vpn2016"
    mapping_dataset_name = "consolidated_traffic_data.csv"
    input_name = "consolidated_traffic_data.csv"

    def _values(self, row: Mapping[str, Any], row_number: int, label: str) -> dict[str, Any]:
        return {
            "dataset_source": self.cli_name,
            "capture_id": None,
            "source_record_id": f"{self.input_path.name}:{row_number}",
            "original_label": str(row["traffic_type"]),
            "canonical_label": label,
            # No capture/session identifier is present in this source file.
            "split_group_id": f"{self.cli_name}:{self.input_path.name}",
            "excluded_leakage_columns": ["traffic_type"],
            "flow_id": None,
            "duration": finite_float(row["duration"], "duration") / 1_000_000,
            "packets_per_second": finite_float(
                row["flowPktsPerSecond"], "flowPktsPerSecond"
            ),
            "bytes_per_second": finite_float(
                row["flowBytesPerSecond"], "flowBytesPerSecond"
            ),
            "mean_interarrival_time": finite_float(row["mean_flowiat"], "mean_flowiat")
            / 1_000_000,
            "std_interarrival_time": finite_float(row["std_flowiat"], "std_flowiat")
            / 1_000_000,
        }

    def iter_records(self) -> Iterator[PreprocessedRecord]:
        if not self.input_path.is_file():
            raise FileNotFoundError(f"Dataset not found: {self.input_path}")
        with self.input_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as file:
            for row_number, row in enumerate(csv.DictReader(file), start=1):
                self.total_source_records += 1
                original_label = str(row.get("traffic_type", ""))
                canonical_label = self.canonical_label(original_label)
                if canonical_label is None:
                    continue
                try:
                    values = self._values(row, row_number, canonical_label)
                except (KeyError, TypeError, ValueError) as error:
                    self.skip(f"invalid source value: {error}")
                    continue
                record = self.validate_record(values, f"row {row_number}")
                if record is not None:
                    yield record

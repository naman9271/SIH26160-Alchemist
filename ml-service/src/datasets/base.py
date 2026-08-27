"""Shared contracts for independent public-dataset adapters."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterator, Mapping
from math import isfinite
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from src.label_mapping import ClassMappingConfig, IGNORE

LOGGER = logging.getLogger(__name__)

CANONICAL_LABELS = frozenset(
    {"web", "video", "voip", "email", "file_transfer", "messaging", "icmp"}
)

NUMERIC_FEATURE_COLUMNS = (
    "duration",
    "packet_count",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "p25_packet_size",
    "median_packet_size",
    "p75_packet_size",
    "p95_packet_size",
    "mean_interarrival_time",
    "std_interarrival_time",
    "upload_packets",
    "download_packets",
    "upload_bytes",
    "download_bytes",
    "upload_download_ratio",
    "burst_count",
    "mean_burst_size",
    "idle_time_ratio",
)

MODEL_FEATURE_COLUMNS = NUMERIC_FEATURE_COLUMNS


class PreprocessedRecord(BaseModel):
    """Common nullable record emitted by every preprocessing adapter.

    Identifiers, labels, dataset provenance, and leakage flags are metadata and
    must not be included in ``MODEL_FEATURE_COLUMNS``.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    dataset_source: str = Field(min_length=1)
    capture_id: str | None = None
    source_record_id: str | None = None
    original_label: str = Field(min_length=1)
    canonical_label: str = Field(min_length=1)
    split_group_id: str = Field(min_length=1)
    excluded_leakage_columns: list[str] = Field(default_factory=list)
    flow_id: str | None = None

    duration: float | None = Field(default=None, gt=0)
    packet_count: int | None = Field(default=None, ge=1)
    total_bytes: int | None = Field(default=None, ge=0)
    packets_per_second: float | None = Field(default=None, ge=0)
    bytes_per_second: float | None = Field(default=None, ge=0)
    mean_packet_size: float | None = Field(default=None, ge=0)
    std_packet_size: float | None = Field(default=None, ge=0)
    min_packet_size: float | None = Field(default=None, ge=0)
    max_packet_size: float | None = Field(default=None, ge=0)
    p25_packet_size: float | None = Field(default=None, ge=0)
    median_packet_size: float | None = Field(default=None, ge=0)
    p75_packet_size: float | None = Field(default=None, ge=0)
    p95_packet_size: float | None = Field(default=None, ge=0)
    mean_interarrival_time: float | None = Field(default=None, ge=0)
    std_interarrival_time: float | None = Field(default=None, ge=0)
    upload_packets: int | None = Field(default=None, ge=0)
    download_packets: int | None = Field(default=None, ge=0)
    upload_bytes: int | None = Field(default=None, ge=0)
    download_bytes: int | None = Field(default=None, ge=0)
    upload_download_ratio: float | None = Field(default=None, ge=0)
    burst_count: int | None = Field(default=None, ge=0)
    mean_burst_size: float | None = Field(default=None, ge=0)
    idle_time_ratio: float | None = Field(default=None, ge=0, le=1)

    @field_validator("*")
    @classmethod
    def finite_numbers_only(cls, value: object) -> object:
        if isinstance(value, float) and not isfinite(value):
            raise ValueError("numeric values must be finite")
        return value

    @model_validator(mode="after")
    def validate_record(self) -> "PreprocessedRecord":
        if self.capture_id is None and self.source_record_id is None:
            raise ValueError("capture_id or source_record_id is required")
        if self.canonical_label not in CANONICAL_LABELS:
            raise ValueError("canonical_label must be a supported application class")

        if all(
            value is not None
            for value in (self.packet_count, self.upload_packets, self.download_packets)
        ) and self.upload_packets + self.download_packets != self.packet_count:
            raise ValueError("directional packet counts must equal packet_count")
        if all(
            value is not None
            for value in (self.total_bytes, self.upload_bytes, self.download_bytes)
        ) and self.upload_bytes + self.download_bytes != self.total_bytes:
            raise ValueError("directional byte counts must equal total_bytes")

        percentiles = (
            self.min_packet_size,
            self.p25_packet_size,
            self.median_packet_size,
            self.p75_packet_size,
            self.p95_packet_size,
            self.max_packet_size,
        )
        available = [value for value in percentiles if value is not None]
        if available != sorted(available):
            raise ValueError("available packet-size percentiles must be ordered")
        return self


class DatasetAdapter(ABC):
    """Base class that tracks skips without combining dataset records."""

    cli_name: str
    mapping_dataset_name: str
    input_name: str

    def __init__(self, external_root: Path, class_mappings: ClassMappingConfig) -> None:
        self.input_path = external_root / self.input_name
        self.class_mappings = class_mappings
        self.total_source_records = 0
        self.emitted_records = 0
        self.skipped_reasons: Counter[str] = Counter()

    @abstractmethod
    def iter_records(self) -> Iterator[PreprocessedRecord]:
        """Yield validated records from this adapter's dataset only."""

    def canonical_label(self, original_label: str) -> str | None:
        mapping = self.class_mappings.map_label(self.mapping_dataset_name, original_label)
        if mapping.canonical_label == IGNORE:
            self.skip(f"label {original_label!r} maps to IGNORE")
            return None
        return mapping.canonical_label

    def validate_record(self, values: Mapping[str, Any], source_id: str) -> PreprocessedRecord | None:
        try:
            record = PreprocessedRecord.model_validate(values)
        except ValidationError as error:
            message = error.errors()[0]["msg"]
            LOGGER.debug("%s rejected %s: %s", self.cli_name, source_id, message)
            self.skip(f"invalid numeric or schema values: {message}")
            return None
        self.emitted_records += 1
        return record

    def skip(self, reason: str) -> None:
        self.skipped_reasons[reason] += 1
        LOGGER.debug("%s skipped source record: %s", self.cli_name, reason)

    def log_summary(self) -> None:
        LOGGER.info(
            "%s preprocessing: %d source records, %d emitted, %d skipped",
            self.cli_name,
            self.total_source_records,
            self.emitted_records,
            sum(self.skipped_reasons.values()),
        )
        for reason, count in self.skipped_reasons.most_common():
            LOGGER.info("%s skipped %d: %s", self.cli_name, count, reason)


def finite_float(value: Any, field_name: str) -> float:
    """Parse a finite float or raise a row-local validation error."""

    parsed = float(value)
    if not isfinite(parsed):
        raise ValueError(f"{field_name} is not finite")
    return parsed


def non_negative_int(value: Any, field_name: str) -> int:
    """Parse an integer-valued, non-negative source field."""

    parsed_float = finite_float(value, field_name)
    if parsed_float < 0 or not parsed_float.is_integer():
        raise ValueError(f"{field_name} must be a non-negative integer")
    return int(parsed_float)

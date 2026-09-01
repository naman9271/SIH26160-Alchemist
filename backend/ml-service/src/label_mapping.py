"""Load and validate dataset-specific application label mappings.

This module only defines mapping contracts. It does not read datasets,
preprocess records, or train models.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

LOGGER = logging.getLogger(__name__)

CANONICAL_CLASSES = frozenset(
    {"web", "video", "voip", "email", "file_transfer", "messaging", "icmp"}
)
IGNORE = "IGNORE"


class MappingValidationError(ValueError):
    """Raised when a class-mapping configuration is incomplete or unsafe."""


@dataclass(frozen=True)
class LabelMappingResult:
    """One mapping decision, retaining the source label for future provenance."""

    dataset_name: str
    original_label: str
    canonical_label: str
    is_configured: bool

    @property
    def is_ignored(self) -> bool:
        """Whether this source label must be excluded from canonical training data."""

        return self.canonical_label == IGNORE


@dataclass(frozen=True)
class DatasetClassMapping:
    """Mappings belonging to one dataset's independent label namespace."""

    label_source: str
    labels: Mapping[str, str]


@dataclass(frozen=True)
class ClassMappingConfig:
    """Validated, fail-closed class mappings keyed by dataset name."""

    datasets: Mapping[str, DatasetClassMapping]

    def map_label(self, dataset_name: str, original_label: str) -> LabelMappingResult:
        """Return a configured mapping or IGNORE for unknown datasets and labels.

        Returning ``IGNORE`` for unconfigured input prevents accidental label
        guessing during future preprocessing. The original label is always
        retained in the result for traceability.
        """

        dataset = self.datasets.get(dataset_name)
        if dataset is None:
            LOGGER.warning("No label mapping configured for dataset %s", dataset_name)
            return LabelMappingResult(dataset_name, original_label, IGNORE, False)
        canonical_label = dataset.labels.get(original_label)
        if canonical_label is None:
            LOGGER.warning(
                "No label mapping configured for label %r in dataset %s",
                original_label,
                dataset_name,
            )
            return LabelMappingResult(dataset_name, original_label, IGNORE, False)
        return LabelMappingResult(dataset_name, original_label, canonical_label, True)


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MappingValidationError(f"{path} must be a mapping")
    return value


def _require_non_empty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MappingValidationError(f"{path} must be a non-empty string")
    return value


def _validate_canonical_classes(raw_config: Mapping[str, Any]) -> None:
    values = raw_config.get("canonical_classes")
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise MappingValidationError("canonical_classes must be a list of strings")
    if set(values) != CANONICAL_CLASSES or len(values) != len(CANONICAL_CLASSES):
        raise MappingValidationError(
            "canonical_classes must contain each supported canonical class exactly once"
        )
    if raw_config.get("ignore_label") != IGNORE:
        raise MappingValidationError(f"ignore_label must be {IGNORE!r}")


def _parse_dataset_mappings(raw_config: Mapping[str, Any]) -> dict[str, DatasetClassMapping]:
    raw_datasets = _require_mapping(raw_config.get("datasets"), "datasets")
    if not raw_datasets:
        raise MappingValidationError("datasets must not be empty")

    datasets: dict[str, DatasetClassMapping] = {}
    for dataset_name, raw_dataset in raw_datasets.items():
        name = _require_non_empty_string(dataset_name, "datasets key")
        dataset = _require_mapping(raw_dataset, f"datasets.{name}")
        label_source = _require_non_empty_string(
            dataset.get("label_source"), f"datasets.{name}.label_source"
        )
        raw_labels = _require_mapping(dataset.get("labels"), f"datasets.{name}.labels")
        if not raw_labels:
            raise MappingValidationError(f"datasets.{name}.labels must not be empty")

        labels: dict[str, str] = {}
        for original_label, canonical_label in raw_labels.items():
            original = _require_non_empty_string(
                original_label, f"datasets.{name}.labels key"
            )
            canonical = _require_non_empty_string(
                canonical_label, f"datasets.{name}.labels.{original}"
            )
            if canonical != IGNORE and canonical not in CANONICAL_CLASSES:
                raise MappingValidationError(
                    f"datasets.{name}.labels.{original} has unsupported canonical label "
                    f"{canonical!r}"
                )
            labels[original] = canonical
        datasets[name] = DatasetClassMapping(label_source=label_source, labels=labels)
    return datasets


def load_class_mapping(path: Path) -> ClassMappingConfig:
    """Load a YAML mapping file and validate every dataset-specific entry."""

    try:
        with path.open("r", encoding="utf-8") as file:
            raw_config = yaml.safe_load(file)
    except OSError as error:
        raise MappingValidationError(f"Could not read mapping file {path}: {error}") from error
    except yaml.YAMLError as error:
        raise MappingValidationError(f"Invalid YAML in mapping file {path}: {error}") from error

    config = _require_mapping(raw_config, "root")
    if config.get("version") != 1:
        raise MappingValidationError("version must be 1")
    _validate_canonical_classes(config)
    datasets = _parse_dataset_mappings(config)
    LOGGER.info("Loaded class mappings for %d datasets from %s", len(datasets), path)
    return ClassMappingConfig(datasets=datasets)

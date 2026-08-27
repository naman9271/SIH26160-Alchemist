"""Tests for safe, dataset-specific label mapping configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.label_mapping import IGNORE, MappingValidationError, load_class_mapping


MAPPING_PATH = Path(__file__).resolve().parents[1] / "config" / "class_mapping.yaml"


def test_loads_the_project_mapping_and_preserves_source_label() -> None:
    config = load_class_mapping(MAPPING_PATH)

    result = config.map_label("consolidated_traffic_data.csv", "VPN-VOIP")

    assert result.original_label == "VPN-VOIP"
    assert result.canonical_label == "voip"
    assert result.is_configured is True
    assert result.is_ignored is False


@pytest.mark.parametrize(
    ("dataset_name", "label"),
    [
        ("cicdarknet2020.parquet", "Tor"),
        ("Network-Traffic-Dataset", "Discord"),
        ("USTC-TFC2016", "Cridex"),
        ("consolidated_traffic_data.csv", "STREAMING"),
    ],
)
def test_status_ambiguous_and_malware_labels_are_ignored(
    dataset_name: str, label: str
) -> None:
    config = load_class_mapping(MAPPING_PATH)

    result = config.map_label(dataset_name, label)

    assert result.canonical_label == IGNORE
    assert result.is_configured is True
    assert result.original_label == label


def test_unknown_dataset_or_label_fails_closed_to_ignore() -> None:
    config = load_class_mapping(MAPPING_PATH)

    unknown_label = config.map_label("Network-Traffic-Dataset", "Unseen App")
    unknown_dataset = config.map_label("unseen-dataset", "VOIP")

    assert unknown_label.canonical_label == IGNORE
    assert unknown_label.is_configured is False
    assert unknown_dataset.canonical_label == IGNORE
    assert unknown_dataset.is_configured is False


def test_rejects_an_unsupported_canonical_label(tmp_path: Path) -> None:
    mapping = tmp_path / "invalid_mapping.yaml"
    mapping.write_text(
        """
version: 1
canonical_classes: [web, video, voip, email, file_transfer, messaging, icmp]
ignore_label: IGNORE
datasets:
  sample:
    label_source: label
    labels:
      something: malware
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(MappingValidationError, match="unsupported canonical label"):
        load_class_mapping(mapping)


def test_rejects_incomplete_canonical_class_list(tmp_path: Path) -> None:
    mapping = tmp_path / "invalid_mapping.yaml"
    mapping.write_text(
        """
version: 1
canonical_classes: [web]
ignore_label: IGNORE
datasets:
  sample:
    label_source: label
    labels:
      something: IGNORE
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(MappingValidationError, match="canonical_classes"):
        load_class_mapping(mapping)

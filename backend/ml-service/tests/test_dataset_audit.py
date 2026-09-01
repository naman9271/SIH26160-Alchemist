"""Focused tests for dataset audit helpers and non-mutating CSV inspection."""

from __future__ import annotations

from pathlib import Path

from src.dataset_audit import audit_external_datasets, map_labels


def test_audit_csv_reports_labels_missing_values_and_feature_overlap(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    external_root.mkdir()
    dataset = external_root / "sample"
    dataset.mkdir()
    csv_file = dataset / "flows.csv"
    csv_file.write_text(
        "flow_id,duration,traffic_type,src_ip\n"
        "one,1.5,BROWSING,10.0.0.1\n"
        "two,,VIDEO,\n",
        encoding="utf-8",
    )

    report = audit_external_datasets(external_root)
    audited = report["datasets"][0]

    assert csv_file.read_text(encoding="utf-8").startswith("flow_id")
    assert audited["available_label_columns"] == ["traffic_type"]
    assert audited["class_counts"] == {"traffic_type": {"BROWSING": 1, "VIDEO": 1}}
    assert audited["missing_values"]["duration"] == 1
    assert audited["flow_features_overlap"] == {
        "duration": ["duration"],
        "flow_id": ["flow_id"],
    }
    assert "flow_id" in audited["possible_leakage_columns"]
    assert "src_ip" in audited["possible_leakage_columns"]


def test_map_labels_does_not_guess_ambiguous_or_non_target_labels() -> None:
    mappings, unresolved, do_not_map = map_labels(
        {"Amazon Prime Video", "Discord", "ProtonVPN", "Gmail"}
    )

    assert {mapping["target_class"] for mapping in mappings} == {"video", "email"}
    assert unresolved == ["Discord"]
    assert do_not_map == ["ProtonVPN"]


def test_map_labels_maps_explicit_vpn_prefixed_traffic_labels() -> None:
    mappings, unresolved, do_not_map = map_labels({"VPN-VOIP", "VPN-STREAMING"})

    assert mappings[0]["source_label"] == "VPN-VOIP"
    assert mappings[0]["target_class"] == "voip"
    assert unresolved == ["VPN-STREAMING"]
    assert do_not_map == []

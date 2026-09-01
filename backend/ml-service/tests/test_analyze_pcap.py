"""Integration tests for offline metadata-only capture inference."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
import yaml

from src.analyze_pcap import analyze_capture, load_feature_extraction_config, main
from src.features import (
    FeatureExtractionConfig,
    extract_window_features,
    main as features_main,
)
from src.predict import Predictor
from src.schemas import FlowFeatures
from tests.test_predict import prepare_predictor_config
from tests.test_preprocess import write_two_packet_capture


def configured_predictor(tmp_path: Path) -> tuple[Path, Predictor, FeatureExtractionConfig]:
    config_path = prepare_predictor_config(tmp_path, threshold=0.0)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["feature_extraction"] = {
        "window_duration_seconds": 30.0,
        "burst_gap_seconds": 0.1,
        "idle_gap_seconds": 1.0,
    }
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return config_path, Predictor.from_config(config_path), load_feature_extraction_config(config_path)


@pytest.mark.parametrize(("suffix", "pcapng"), [(".pcap", False), (".pcapng", True)])
def test_capture_to_prediction_pipeline_with_small_fixture(
    tmp_path: Path, suffix: str, pcapng: bool
) -> None:
    capture = tmp_path / f"fixture{suffix}"
    write_two_packet_capture(capture, pcapng=pcapng)
    _, predictor, feature_config = configured_predictor(tmp_path)

    report = analyze_capture(capture, predictor, feature_config)

    assert report["capture"] == {"name": capture.name, "format": suffix.lstrip(".")}
    assert report["summary"]["valid_windows"] == 1
    assert report["summary"]["analyzed_packets"] == 2
    assert report["summary"]["payload_decryption_attempted"] is False
    assert sum(report["summary"]["class_distribution"].values()) == 1
    window = report["windows"][0]
    assert window["flow_window_id"].startswith(capture.name)
    assert len(window["top_predictions"]) == 3
    assert window["flow_statistics"]["packet_count"] == 2
    assert window["flow_statistics"]["burst_count"] == 2
    assert window["flow_statistics"]["idle_time_ratio"] == 0.0
    assert window["explanations"] == []


def test_window_extractor_produces_strict_flow_features(tmp_path: Path) -> None:
    capture = tmp_path / "strict.pcap"
    write_two_packet_capture(capture)
    config = FeatureExtractionConfig(
        window_duration_seconds=30.0,
        burst_gap_seconds=0.1,
        idle_gap_seconds=1.0,
    )

    windows = list(extract_window_features(capture, capture.name, config))
    validated = [FlowFeatures.model_validate(item) for item in windows]

    assert len(validated) == 1
    assert validated[0].upload_download_ratio == pytest.approx(1.0)
    assert validated[0].mean_burst_size == pytest.approx(1.0)


def test_cli_emits_capture_windows_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = tmp_path / "cli-fixture.pcap"
    write_two_packet_capture(capture)
    config_path, _, _ = configured_predictor(tmp_path)
    monkeypatch.setattr(
        "sys.argv",
        ["analyze_pcap", "--pcap", str(capture), "--config", str(config_path)],
    )

    main()
    output = json.loads(capsys.readouterr().out)

    assert output["summary"]["valid_windows"] == 1
    assert output["windows"][0]["predicted_class"] in {"web", "video", "voip"}


def test_feature_extraction_config_rejects_overlapping_timing_thresholds(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "model.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "feature_extraction": {
                    "window_duration_seconds": 10.0,
                    "burst_gap_seconds": 2.0,
                    "idle_gap_seconds": 1.0,
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="burst_gap_seconds"):
        load_feature_extraction_config(config_path)


def test_features_cli_writes_metadata_only_csv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "features.pcap"
    output = tmp_path / "features.csv"
    write_two_packet_capture(capture)
    monkeypatch.setattr(
        "sys.argv",
        ["features", "--pcap", str(capture), "--output", str(output)],
    )

    features_main()

    with output.open(encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert len(rows) == 1
    assert set(rows[0]) >= {"flow_id", "packet_count", "idle_time_ratio"}
    assert rows[0]["packet_count"] == "2"

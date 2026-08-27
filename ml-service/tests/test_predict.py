"""Tests for the local selected-model prediction entry point."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
import yaml

from src.predict import PredictionError, Predictor, load_input, load_prediction_config
from src.schemas import TrafficClass
from tests.test_leakage_audit import prepare_trained_fixture
from tests.test_schemas import valid_flow_features


def prepare_predictor_config(tmp_path: Path, threshold: float = 0.0) -> Path:
    dataset_path, models_dir, metrics_path = prepare_trained_fixture(tmp_path)
    del dataset_path
    metadata_path = models_dir / "model_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["model_version"] = "fixture-model-v1"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    config_path = tmp_path / "model.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "model": {
                    "models_dir": str(models_dir),
                    "training_metrics_path": str(metrics_path),
                },
                "unknown_detection": {
                    "method": "max_class_probability_threshold",
                    "confidence_threshold": threshold,
                },
            }
        ),
        encoding="utf-8",
    )
    return config_path


def test_predictor_returns_valid_result_in_exact_persisted_feature_order(tmp_path: Path) -> None:
    predictor = Predictor.from_config(prepare_predictor_config(tmp_path))

    result = predictor.predict(valid_flow_features())

    assert result.flow_id == "flow-001"
    assert result.predicted_class in {TrafficClass.WEB, TrafficClass.VIDEO, TrafficClass.VOIP}
    assert result.is_unknown is False
    assert len(result.top_predictions) == 3
    assert result.top_predictions[0].traffic_class is result.predicted_class
    assert result.top_explanations == []
    assert result.inference_time_ms >= 0


def test_predictor_uses_calibrated_threshold_to_return_unknown(tmp_path: Path) -> None:
    predictor = Predictor.from_config(prepare_predictor_config(tmp_path, threshold=0.60))
    predictor._model = SimpleNamespace(  # type: ignore[attr-defined]
        predict_proba=lambda values: np.asarray([[0.55, 0.30, 0.15]])
    )

    result = predictor.predict(valid_flow_features())

    assert result.predicted_class is TrafficClass.UNKNOWN
    assert result.is_unknown is True
    assert result.top_predictions[0].traffic_class is TrafficClass.VIDEO


def test_predictor_only_loads_model_during_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_prediction_config(prepare_predictor_config(tmp_path))
    import src.predict as predict_module

    original_load = predict_module.joblib.load
    calls = 0

    def tracked_load(path: Path) -> object:
        nonlocal calls
        calls += 1
        return original_load(path)

    monkeypatch.setattr(predict_module.joblib, "load", tracked_load)
    predictor = Predictor(config)
    predictor.predict(valid_flow_features())
    predictor.predict(valid_flow_features())

    assert calls == 1


def test_prediction_rejects_invalid_flow_input_safely(tmp_path: Path) -> None:
    predictor = Predictor.from_config(prepare_predictor_config(tmp_path))
    invalid = valid_flow_features()
    invalid["download_bytes"] = 1

    with pytest.raises(PredictionError, match="Invalid FlowFeatures"):
        predictor.predict(invalid)


def test_optional_explanation_is_converted_to_prediction_result_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    predictor = Predictor.from_config(prepare_predictor_config(tmp_path))
    monkeypatch.setattr(
        "src.predict.explain_prediction",
        lambda *args, **kwargs: [
            {
                "feature": "duration",
                "display_name": "Flow Duration",
                "value": 2.5,
                "impact": 0.31,
                "direction": "supports_prediction",
            }
        ],
    )

    result = predictor.predict(valid_flow_features(), include_explanations=True)

    assert result.top_explanations[0].display_name == "Flow Duration"
    assert result.top_explanations[0].impact == pytest.approx(0.31)


def test_config_requires_a_calibrated_threshold(tmp_path: Path) -> None:
    config_path = prepare_predictor_config(tmp_path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    raw["unknown_detection"]["confidence_threshold"] = None
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    with pytest.raises(PredictionError, match="not calibrated"):
        load_prediction_config(config_path)


def test_load_input_requires_one_json_object(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    input_path.write_text("[]", encoding="utf-8")

    with pytest.raises(PredictionError, match="one object"):
        load_input(input_path)

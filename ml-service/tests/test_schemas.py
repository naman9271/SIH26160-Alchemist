"""Tests for the ML service data contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.schemas import (
    ClassPrediction,
    FeatureExplanation,
    FlowFeatures,
    PredictionResult,
    TrafficClass,
)


def valid_flow_features() -> dict[str, object]:
    return {
        "flow_id": "flow-001",
        "duration": 2.5,
        "packet_count": 10,
        "total_bytes": 1_500,
        "packets_per_second": 4.0,
        "bytes_per_second": 600.0,
        "mean_packet_size": 150.0,
        "std_packet_size": 20.0,
        "min_packet_size": 100.0,
        "max_packet_size": 200.0,
        "p25_packet_size": 125.0,
        "median_packet_size": 150.0,
        "p75_packet_size": 175.0,
        "p95_packet_size": 195.0,
        "mean_interarrival_time": 0.25,
        "std_interarrival_time": 0.05,
        "upload_packets": 4,
        "download_packets": 6,
        "upload_bytes": 600,
        "download_bytes": 900,
        "upload_download_ratio": 2 / 3,
        "burst_count": 2,
        "mean_burst_size": 5.0,
        "idle_time_ratio": 0.1,
    }


def valid_prediction_result() -> dict[str, object]:
    return {
        "flow_id": "flow-001",
        "predicted_class": TrafficClass.VIDEO,
        "confidence": 0.91,
        "is_unknown": False,
        "top_predictions": [
            ClassPrediction(traffic_class=TrafficClass.VIDEO, confidence=0.91),
            ClassPrediction(traffic_class=TrafficClass.WEB, confidence=0.08),
        ],
        "model_version": "0.1.0",
        "top_explanations": [
            FeatureExplanation(
                feature="bytes_per_second",
                display_name="Bytes per Second",
                value=600.0,
                impact=0.42,
                direction="supports_prediction",
            ),
        ],
        "inference_time_ms": 3.4,
    }


def test_flow_features_accepts_valid_metadata() -> None:
    features = FlowFeatures(**valid_flow_features())

    assert features.flow_id == "flow-001"
    assert features.packet_count == 10


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("duration", 0),
        ("packet_count", 0),
        ("idle_time_ratio", 1.1),
        ("mean_packet_size", float("inf")),
    ],
)
def test_flow_features_rejects_invalid_numeric_values(field: str, value: object) -> None:
    values = valid_flow_features()
    values[field] = value

    with pytest.raises(ValidationError):
        FlowFeatures(**values)


def test_flow_features_rejects_inconsistent_directional_totals() -> None:
    values = valid_flow_features()
    values["download_bytes"] = 899

    with pytest.raises(ValidationError, match="directional byte counts"):
        FlowFeatures(**values)


def test_flow_features_rejects_unordered_percentiles() -> None:
    values = valid_flow_features()
    values["p75_packet_size"] = 140.0

    with pytest.raises(ValidationError, match="percentiles must be ordered"):
        FlowFeatures(**values)


def test_prediction_result_accepts_known_prediction() -> None:
    result = PredictionResult(**valid_prediction_result())

    assert result.is_unknown is False
    assert result.top_predictions[0].traffic_class is TrafficClass.VIDEO


def test_prediction_result_accepts_unknown_prediction() -> None:
    values = valid_prediction_result()
    values.update(
        predicted_class=TrafficClass.UNKNOWN,
        confidence=0.35,
        is_unknown=True,
        top_predictions=[
            ClassPrediction(traffic_class=TrafficClass.WEB, confidence=0.35),
            ClassPrediction(traffic_class=TrafficClass.VIDEO, confidence=0.3),
        ],
    )

    result = PredictionResult(**values)

    assert result.predicted_class is TrafficClass.UNKNOWN


def test_prediction_result_rejects_unknown_as_fitted_probability() -> None:
    values = valid_prediction_result()
    values.update(
        predicted_class=TrafficClass.UNKNOWN,
        confidence=0.35,
        is_unknown=True,
        top_predictions=[
            ClassPrediction(traffic_class=TrafficClass.UNKNOWN, confidence=0.35),
        ],
    )

    with pytest.raises(ValidationError, match="rejection outcome"):
        PredictionResult(**values)


def test_prediction_result_rejects_inconsistent_unknown_state() -> None:
    values = valid_prediction_result()
    values["is_unknown"] = True

    with pytest.raises(ValidationError, match="is_unknown must match"):
        PredictionResult(**values)


def test_prediction_result_rejects_unsorted_predictions() -> None:
    values = valid_prediction_result()
    values["top_predictions"] = [
        ClassPrediction(traffic_class=TrafficClass.VIDEO, confidence=0.5),
        ClassPrediction(traffic_class=TrafficClass.WEB, confidence=0.9),
    ]

    with pytest.raises(ValidationError, match="descending confidence"):
        PredictionResult(**values)

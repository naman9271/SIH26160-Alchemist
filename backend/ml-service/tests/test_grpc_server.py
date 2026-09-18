"""Integration tests for the inference-only gRPC API."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import grpc
import pytest
from google.protobuf import empty_pb2

from proto.ml.v1 import traffic_classifier_pb2 as pb2
from proto.ml.v1 import traffic_classifier_pb2_grpc as pb2_grpc
from src.grpc_server import GrpcServerConfig, create_server, load_grpc_config
from src.predict import Predictor
from src.schemas import (
    ClassPrediction,
    FeatureExplanation,
    PredictionResult,
    TrafficClass,
)
from tests.test_predict import prepare_predictor_config
from tests.test_schemas import valid_flow_features


def valid_flow_request() -> pb2.FlowFeatures:
    return pb2.FlowFeatures(**valid_flow_features())


def server_config(**updates: Any) -> GrpcServerConfig:
    values: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": 0,
        "max_workers": 2,
        "request_timeout_seconds": 1.0,
        "shutdown_grace_seconds": 0.2,
        "explanations_enabled": False,
    }
    values.update(updates)
    return GrpcServerConfig(**values)


def start_test_server(predictor: Any, config: GrpcServerConfig) -> tuple[Any, Any, Any]:
    handle = create_server(predictor, config)
    handle.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{handle.bound_port}")
    grpc.channel_ready_future(channel).result(timeout=2)
    return handle, channel, pb2_grpc.TrafficClassifierStub(channel)


def test_grpc_predict_and_health_use_loaded_predictor(tmp_path: Path) -> None:
    predictor = Predictor.from_config(prepare_predictor_config(tmp_path, threshold=0.0))
    handle, channel, stub = start_test_server(predictor, server_config())
    try:
        response = stub.PredictTraffic(valid_flow_request(), timeout=2)
        health = stub.HealthCheck(empty_pb2.Empty(), timeout=2)
    finally:
        channel.close()
        handle.stop()

    assert response.flow_id == "flow-001"
    assert response.predicted_class != pb2.TRAFFIC_CLASS_UNSPECIFIED
    assert len(response.top_predictions) == 3
    assert response.model_version == "fixture-model-v1"
    assert response.inference_time_ms >= 0
    assert health.status == pb2.SERVING_STATUS_SERVING
    assert health.model_loaded is True
    assert health.model_version == "fixture-model-v1"


def test_grpc_invalid_request_returns_invalid_argument(tmp_path: Path) -> None:
    predictor = Predictor.from_config(prepare_predictor_config(tmp_path, threshold=0.0))
    handle, channel, stub = start_test_server(predictor, server_config())
    try:
        with pytest.raises(grpc.RpcError) as caught:
            stub.PredictTraffic(pb2.FlowFeatures(flow_id="incomplete"), timeout=2)
    finally:
        channel.close()
        handle.stop()

    assert caught.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    assert "Invalid FlowFeatures" in caught.value.details()


class ControlledPredictor:
    model_version = "controlled-v1"

    def __init__(self, delay_seconds: float = 0.0) -> None:
        self.delay_seconds = delay_seconds
        self.explanation_flags: list[bool] = []

    def predict(
        self, flow: object, *, include_explanations: bool = False
    ) -> PredictionResult:
        self.explanation_flags.append(include_explanations)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        explanations = (
            [
                FeatureExplanation(
                    feature="duration",
                    display_name="Flow Duration",
                    value=2.5,
                    impact=0.31,
                    direction="supports_prediction",
                )
            ]
            if include_explanations
            else []
        )
        return PredictionResult(
            flow_id="flow-001",
            window_id="window-001",
            aggregation_scope="aggregate_endpoint_channel_estimate",
            predicted_class=TrafficClass.WEB,
            confidence=0.8,
            is_unknown=False,
            top_predictions=[
                ClassPrediction(traffic_class=TrafficClass.WEB, confidence=0.8),
                ClassPrediction(traffic_class=TrafficClass.VIDEO, confidence=0.15),
                ClassPrediction(traffic_class=TrafficClass.VOIP, confidence=0.05),
            ],
            model_version=self.model_version,
            top_explanations=explanations,
            inference_time_ms=1.0,
        )


def test_grpc_explanations_require_server_permission_and_call_opt_in() -> None:
    predictor = ControlledPredictor()
    handle, channel, stub = start_test_server(
        predictor, server_config(explanations_enabled=True)
    )
    try:
        without_opt_in = stub.PredictTraffic(valid_flow_request(), timeout=2)
        with_opt_in = stub.PredictTraffic(
            valid_flow_request(),
            timeout=2,
            metadata=(("x-include-explanations", "true"),),
        )
    finally:
        channel.close()
        handle.stop()

    assert len(without_opt_in.top_explanations) == 0
    assert len(with_opt_in.top_explanations) == 1
    assert with_opt_in.top_explanations[0].direction == (
        pb2.EXPLANATION_DIRECTION_SUPPORTS_PREDICTION
    )
    assert predictor.explanation_flags == [False, True]


def test_grpc_server_timeout_returns_deadline_exceeded() -> None:
    predictor = ControlledPredictor(delay_seconds=0.05)
    handle, channel, stub = start_test_server(
        predictor, server_config(request_timeout_seconds=0.01)
    )
    try:
        with pytest.raises(grpc.RpcError) as caught:
            stub.PredictTraffic(valid_flow_request(), timeout=1)
    finally:
        channel.close()
        handle.stop()

    assert caught.value.code() == grpc.StatusCode.DEADLINE_EXCEEDED


def test_grpc_configuration_is_loaded_from_model_yaml(tmp_path: Path) -> None:
    config_path = prepare_predictor_config(tmp_path)
    with config_path.open("a", encoding="utf-8") as file:
        file.write(
            "grpc:\n"
            "  host: 127.0.0.1\n"
            "  port: 55001\n"
            "  max_workers: 3\n"
            "  request_timeout_seconds: 2.5\n"
            "  shutdown_grace_seconds: 1.0\n"
            "  explanations_enabled: false\n"
        )

    config = load_grpc_config(config_path)

    assert config.host == "127.0.0.1"
    assert config.port == 55001
    assert config.max_workers == 3
    assert config.request_timeout_seconds == pytest.approx(2.5)

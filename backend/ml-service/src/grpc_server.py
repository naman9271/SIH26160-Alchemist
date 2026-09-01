"""Minimal gRPC inference server for the persisted traffic classifier.

The selected model is constructed exactly once before the server starts.
Training code is never invoked by this module.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import signal
import threading
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import grpc
import yaml
from google.protobuf import empty_pb2
from pydantic import ValidationError

from proto.ml.v1 import traffic_classifier_pb2 as pb2
from proto.ml.v1 import traffic_classifier_pb2_grpc as pb2_grpc
from src.predict import PredictionError, Predictor
from src.schemas import FlowFeatures, PredictionResult, TrafficClass

LOGGER = logging.getLogger(__name__)
EXPLANATION_METADATA_KEY = "x-include-explanations"

TRAFFIC_CLASS_TO_PROTO = {
    TrafficClass.WEB: pb2.TRAFFIC_CLASS_WEB,
    TrafficClass.VIDEO: pb2.TRAFFIC_CLASS_VIDEO,
    TrafficClass.VOIP: pb2.TRAFFIC_CLASS_VOIP,
    TrafficClass.EMAIL: pb2.TRAFFIC_CLASS_EMAIL,
    TrafficClass.FILE_TRANSFER: pb2.TRAFFIC_CLASS_FILE_TRANSFER,
    TrafficClass.MESSAGING: pb2.TRAFFIC_CLASS_MESSAGING,
    TrafficClass.ICMP: pb2.TRAFFIC_CLASS_ICMP,
    TrafficClass.UNKNOWN: pb2.TRAFFIC_CLASS_UNKNOWN,
}
EXPLANATION_DIRECTION_TO_PROTO = {
    "supports_prediction": pb2.EXPLANATION_DIRECTION_SUPPORTS_PREDICTION,
    "opposes_prediction": pb2.EXPLANATION_DIRECTION_OPPOSES_PREDICTION,
    "neutral": pb2.EXPLANATION_DIRECTION_NEUTRAL,
}


class ServerConfigurationError(ValueError):
    """Raised when gRPC server configuration is invalid."""


@dataclass(frozen=True)
class GrpcServerConfig:
    """Validated runtime policy for the local inference server."""

    host: str
    port: int
    max_workers: int
    request_timeout_seconds: float
    shutdown_grace_seconds: float
    explanations_enabled: bool

    def validate(self) -> None:
        if not self.host.strip():
            raise ServerConfigurationError("grpc.host must not be blank")
        if not 0 <= self.port <= 65_535:
            raise ServerConfigurationError("grpc.port must be within [0, 65535]")
        if self.max_workers < 1:
            raise ServerConfigurationError("grpc.max_workers must be positive")
        if not math.isfinite(self.request_timeout_seconds) or self.request_timeout_seconds <= 0:
            raise ServerConfigurationError("grpc.request_timeout_seconds must be positive")
        if not math.isfinite(self.shutdown_grace_seconds) or self.shutdown_grace_seconds < 0:
            raise ServerConfigurationError("grpc.shutdown_grace_seconds must be non-negative")


class JsonLogFormatter(logging.Formatter):
    """Small structured formatter suitable for local service logs."""

    _extra_fields = (
        "event",
        "flow_id",
        "predicted_class",
        "is_unknown",
        "inference_time_ms",
        "grpc_code",
        "host",
        "port",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in self._extra_fields:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True)


def configure_structured_logging(level: int = logging.INFO) -> None:
    """Configure one JSON stream handler for the server process."""

    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def _require_number(value: object, field: str, *, integer: bool = False) -> int | float:
    if isinstance(value, bool):
        raise ServerConfigurationError(f"grpc.{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ServerConfigurationError(f"grpc.{field} must be numeric") from error
    if not math.isfinite(number):
        raise ServerConfigurationError(f"grpc.{field} must be finite")
    if integer:
        if not number.is_integer():
            raise ServerConfigurationError(f"grpc.{field} must be an integer")
        return int(number)
    return number


def load_grpc_config(config_path: Path) -> GrpcServerConfig:
    """Load host, port, timeout, and shutdown behavior from model YAML."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ServerConfigurationError(f"Could not read server config {config_path}: {error}") from error
    grpc_config = raw.get("grpc") if isinstance(raw, Mapping) else None
    if not isinstance(grpc_config, Mapping):
        raise ServerConfigurationError("Model config has no grpc mapping")
    host = grpc_config.get("host")
    explanations_enabled = grpc_config.get("explanations_enabled")
    if not isinstance(host, str):
        raise ServerConfigurationError("grpc.host must be a string")
    if not isinstance(explanations_enabled, bool):
        raise ServerConfigurationError("grpc.explanations_enabled must be boolean")
    config = GrpcServerConfig(
        host=host,
        port=int(_require_number(grpc_config.get("port"), "port", integer=True)),
        max_workers=int(
            _require_number(grpc_config.get("max_workers"), "max_workers", integer=True)
        ),
        request_timeout_seconds=float(
            _require_number(
                grpc_config.get("request_timeout_seconds"), "request_timeout_seconds"
            )
        ),
        shutdown_grace_seconds=float(
            _require_number(
                grpc_config.get("shutdown_grace_seconds"), "shutdown_grace_seconds"
            )
        ),
        explanations_enabled=explanations_enabled,
    )
    config.validate()
    return config


def _flow_from_proto(request: pb2.FlowFeatures) -> FlowFeatures:
    values = {
        field: getattr(request, field)
        for field in FlowFeatures.model_fields
        if request.HasField(field)
    }
    return FlowFeatures.model_validate(values)


def _prediction_to_proto(result: PredictionResult) -> pb2.PredictionResult:
    return pb2.PredictionResult(
        flow_id=result.flow_id,
        predicted_class=TRAFFIC_CLASS_TO_PROTO[result.predicted_class],
        confidence=result.confidence,
        is_unknown=result.is_unknown,
        top_predictions=[
            pb2.ClassPrediction(
                traffic_class=TRAFFIC_CLASS_TO_PROTO[item.traffic_class],
                confidence=item.confidence,
            )
            for item in result.top_predictions
        ],
        model_version=result.model_version,
        top_explanations=[
            pb2.FeatureExplanation(
                feature=item.feature,
                display_name=item.display_name,
                value=item.value,
                impact=item.impact,
                direction=EXPLANATION_DIRECTION_TO_PROTO[item.direction],
            )
            for item in result.top_explanations
        ],
        inference_time_ms=result.inference_time_ms,
    )


class TrafficClassifierService(pb2_grpc.TrafficClassifierServicer):
    """Validated RPC adapter around one already-loaded ``Predictor``."""

    def __init__(self, predictor: Predictor, config: GrpcServerConfig) -> None:
        self._predictor = predictor
        self._config = config
        self._inference_pool = ThreadPoolExecutor(
            max_workers=config.max_workers, thread_name_prefix="ml-inference"
        )
        self._serving = True

    def close(self) -> None:
        self._serving = False
        self._inference_pool.shutdown(wait=True, cancel_futures=True)

    def begin_shutdown(self) -> None:
        """Reject new predictions while active requests drain."""

        self._serving = False

    def _explanations_requested(self, context: grpc.ServicerContext) -> bool:
        if not self._config.explanations_enabled:
            return False
        metadata = {item.key.casefold(): item.value for item in context.invocation_metadata()}
        return metadata.get(EXPLANATION_METADATA_KEY, "false").casefold() in {"1", "true", "yes"}

    def _effective_timeout(self, context: grpc.ServicerContext) -> float:
        remaining = context.time_remaining()
        if remaining is None:
            return self._config.request_timeout_seconds
        return min(self._config.request_timeout_seconds, max(0.0, remaining))

    def PredictTraffic(
        self, request: pb2.FlowFeatures, context: grpc.ServicerContext
    ) -> pb2.PredictionResult:
        if not self._serving:
            context.abort(grpc.StatusCode.UNAVAILABLE, "Inference service is shutting down")
        try:
            flow = _flow_from_proto(request)
        except (ValidationError, ValueError) as error:
            LOGGER.info(
                "prediction_request_rejected",
                extra={"event": "prediction_request_rejected", "grpc_code": "INVALID_ARGUMENT"},
            )
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid FlowFeatures: {error}")

        timeout = self._effective_timeout(context)
        if timeout <= 0:
            context.abort(grpc.StatusCode.DEADLINE_EXCEEDED, "Prediction deadline expired")
        future = self._inference_pool.submit(
            self._predictor.predict,
            flow,
            include_explanations=self._explanations_requested(context),
        )
        try:
            result = future.result(timeout=timeout)
        except FutureTimeoutError:
            future.cancel()
            LOGGER.warning(
                "prediction_timeout",
                extra={
                    "event": "prediction_timeout",
                    "flow_id": flow.flow_id,
                    "grpc_code": "DEADLINE_EXCEEDED",
                },
            )
            context.abort(grpc.StatusCode.DEADLINE_EXCEEDED, "Prediction exceeded its deadline")
        except PredictionError as error:
            LOGGER.exception(
                "prediction_failed",
                extra={"event": "prediction_failed", "flow_id": flow.flow_id, "grpc_code": "INTERNAL"},
            )
            context.abort(grpc.StatusCode.INTERNAL, f"Prediction failed: {error}")
        except Exception:
            LOGGER.exception(
                "unexpected_prediction_failure",
                extra={"event": "prediction_failed", "flow_id": flow.flow_id, "grpc_code": "INTERNAL"},
            )
            context.abort(grpc.StatusCode.INTERNAL, "Prediction failed unexpectedly")

        LOGGER.info(
            "prediction_completed",
            extra={
                "event": "prediction_completed",
                "flow_id": result.flow_id,
                "predicted_class": result.predicted_class.value,
                "is_unknown": result.is_unknown,
                "inference_time_ms": result.inference_time_ms,
            },
        )
        return _prediction_to_proto(result)

    def HealthCheck(
        self, request: empty_pb2.Empty, context: grpc.ServicerContext
    ) -> pb2.HealthStatus:
        del request, context
        return pb2.HealthStatus(
            status=(
                pb2.SERVING_STATUS_SERVING
                if self._serving
                else pb2.SERVING_STATUS_NOT_SERVING
            ),
            model_loaded=True,
            model_version=self._predictor.model_version,
        )


@dataclass
class RunningServer:
    """Server resources with deterministic graceful shutdown."""

    server: grpc.Server
    service: TrafficClassifierService
    handler_pool: ThreadPoolExecutor
    config: GrpcServerConfig
    bound_port: int

    def start(self) -> None:
        self.server.start()

    def stop(self) -> None:
        self.service.begin_shutdown()
        stopped = self.server.stop(self.config.shutdown_grace_seconds)
        stopped.wait(timeout=self.config.shutdown_grace_seconds + 1.0)
        self.service.close()
        self.handler_pool.shutdown(wait=True, cancel_futures=True)


def create_server(predictor: Predictor, config: GrpcServerConfig) -> RunningServer:
    """Create an unstarted gRPC server around one existing predictor."""

    config.validate()
    handler_pool = ThreadPoolExecutor(
        max_workers=config.max_workers, thread_name_prefix="grpc-handler"
    )
    server = grpc.server(handler_pool)
    service = TrafficClassifierService(predictor, config)
    pb2_grpc.add_TrafficClassifierServicer_to_server(service, server)
    address = f"{config.host}:{config.port}"
    try:
        bound_port = server.add_insecure_port(address)
    except RuntimeError as error:
        service.close()
        handler_pool.shutdown(wait=True, cancel_futures=True)
        raise ServerConfigurationError(f"Could not bind gRPC server to {address}") from error
    if bound_port == 0:
        service.close()
        handler_pool.shutdown(wait=True, cancel_futures=True)
        raise ServerConfigurationError(f"Could not bind gRPC server to {address}")
    return RunningServer(server, service, handler_pool, config, bound_port)


def build_server_from_config(
    model_config_path: Path,
    server_config: GrpcServerConfig,
    *,
    models_dir_override: Path | None = None,
    training_metrics_override: Path | None = None,
) -> RunningServer:
    """Load the selected model once, then construct the unstarted server."""

    predictor = Predictor.from_config(
        model_config_path,
        models_dir_override=models_dir_override,
        training_metrics_override=training_metrics_override,
    )
    return create_server(predictor, server_config)


def serve_until_shutdown(handle: RunningServer) -> None:
    """Start the server and gracefully stop on SIGINT or SIGTERM."""

    shutdown_requested = threading.Event()

    def request_shutdown(signum: int, frame: object) -> None:
        del frame
        LOGGER.info("shutdown_requested", extra={"event": "shutdown_requested"})
        shutdown_requested.set()

    previous_handlers = {
        signum: signal.signal(signum, request_shutdown)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    handle.start()
    LOGGER.info(
        "grpc_server_started",
        extra={
            "event": "grpc_server_started",
            "host": handle.config.host,
            "port": handle.bound_port,
        },
    )
    try:
        shutdown_requested.wait()
    finally:
        handle.stop()
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)
        LOGGER.info("grpc_server_stopped", extra={"event": "grpc_server_stopped"})


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=service_root / "config" / "model.yaml")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--models-dir", type=Path)
    parser.add_argument("--training-metrics", type=Path)
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    configure_structured_logging()
    try:
        server_config = load_grpc_config(args.config)
        if args.host is not None:
            server_config = replace(server_config, host=args.host)
        if args.port is not None:
            server_config = replace(server_config, port=args.port)
        server_config.validate()
        handle = build_server_from_config(
            args.config,
            server_config,
            models_dir_override=args.models_dir,
            training_metrics_override=args.training_metrics,
        )
        serve_until_shutdown(handle)
    except (PredictionError, ServerConfigurationError) as error:
        LOGGER.error(
            "grpc_server_start_failed: %s",
            error,
            extra={"event": "grpc_server_start_failed"},
        )
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()

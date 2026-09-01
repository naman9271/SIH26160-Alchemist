"""Inference for the separate experimental Isolation Forest component."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from src.predict import load_input
from src.schemas import FlowFeatures

LOGGER = logging.getLogger(__name__)


class AnomalyPredictionError(ValueError):
    """Raised for safe anomaly inference failures."""


class AnomalyStatus(StrEnum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"


class AnomalyPrediction(BaseModel):
    """Result independent from the traffic-classification result."""

    model_config = ConfigDict(extra="forbid")

    flow_id: str = Field(min_length=1)
    anomaly_score: float = Field(ge=0, le=1)
    anomaly_status: AnomalyStatus
    model_version: str = Field(min_length=1)

    @field_validator("anomaly_score")
    @classmethod
    def finite_score(cls, value: float) -> float:
        if not isfinite(value):
            raise ValueError("anomaly_score must be finite")
        return value


@dataclass(frozen=True)
class AnomalyPredictConfig:
    enabled: bool
    model_path: Path
    metadata_path: Path


def _resolve_path(config_path: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise AnomalyPredictionError(f"{field} must be a non-empty path")
    path = Path(value)
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def load_anomaly_predict_config(config_path: Path) -> AnomalyPredictConfig:
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise AnomalyPredictionError(f"Could not read model config {config_path}: {error}") from error
    anomaly = raw.get("anomaly_detection") if isinstance(raw, Mapping) else None
    if not isinstance(anomaly, Mapping):
        raise AnomalyPredictionError("Config has no anomaly_detection mapping")
    enabled = anomaly.get("enabled")
    if not isinstance(enabled, bool):
        raise AnomalyPredictionError("anomaly_detection.enabled must be boolean")
    if anomaly.get("method") != "isolation_forest":
        raise AnomalyPredictionError("Unsupported anomaly_detection.method")
    return AnomalyPredictConfig(
        enabled=enabled,
        model_path=_resolve_path(config_path, anomaly.get("model_path"), "anomaly.model_path"),
        metadata_path=_resolve_path(
            config_path, anomaly.get("metadata_path"), "anomaly.metadata_path"
        ),
    )


class AnomalyDetector:
    """One loaded Isolation Forest with persisted score normalization."""

    def __init__(self, config: AnomalyPredictConfig) -> None:
        if not config.enabled:
            raise AnomalyPredictionError("Anomaly detection is disabled in configuration")
        missing = [path for path in (config.model_path, config.metadata_path) if not path.is_file()]
        if missing:
            raise AnomalyPredictionError(
                "Required anomaly artifacts are unavailable: "
                + ", ".join(str(path) for path in missing)
            )
        try:
            metadata = json.loads(config.metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise AnomalyPredictionError(f"Could not read anomaly metadata: {error}") from error
        if metadata.get("method") != "isolation_forest":
            raise AnomalyPredictionError("Anomaly metadata method is invalid")
        self._feature_order = self._validate_feature_order(metadata.get("feature_order"))
        normalization = metadata.get("normalization")
        if not isinstance(normalization, Mapping):
            raise AnomalyPredictionError("Anomaly metadata normalization is invalid")
        try:
            self._raw_low = float(normalization["raw_score_low"])
            self._raw_high = float(normalization["raw_score_high"])
            self._raw_threshold = float(metadata["raw_suspicious_threshold"])
        except (KeyError, TypeError, ValueError) as error:
            raise AnomalyPredictionError("Anomaly metadata score bounds are invalid") from error
        if not all(isfinite(value) for value in (self._raw_low, self._raw_high, self._raw_threshold)):
            raise AnomalyPredictionError("Anomaly metadata score bounds must be finite")
        if self._raw_high <= self._raw_low:
            raise AnomalyPredictionError("Anomaly normalization high must exceed low")
        model_version = metadata.get("model_version")
        if not isinstance(model_version, str) or not model_version:
            raise AnomalyPredictionError("Anomaly metadata model_version is invalid")
        self._model_version = model_version
        try:
            self._model = joblib.load(config.model_path)
        except Exception as error:
            raise AnomalyPredictionError(f"Could not load anomaly model: {error}") from error
        if not hasattr(self._model, "score_samples"):
            raise AnomalyPredictionError("Anomaly model does not expose score_samples")

    @classmethod
    def from_config(cls, config_path: Path) -> "AnomalyDetector":
        return cls(load_anomaly_predict_config(config_path))

    @staticmethod
    def _validate_feature_order(value: object) -> tuple[str, ...]:
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) for item in value)
        ):
            raise AnomalyPredictionError("Anomaly metadata feature_order is invalid")
        allowed = set(FlowFeatures.model_fields) - {"flow_id"}
        order = tuple(value)
        if len(set(order)) != len(order) or any(item not in allowed for item in order):
            raise AnomalyPredictionError("Anomaly feature order contains invalid fields")
        return order

    def predict(self, flow: FlowFeatures | Mapping[str, Any]) -> AnomalyPrediction:
        try:
            validated = flow if isinstance(flow, FlowFeatures) else FlowFeatures.model_validate(flow)
        except ValidationError as error:
            raise AnomalyPredictionError(f"Invalid FlowFeatures input: {error}") from error
        values = validated.model_dump()
        features = np.asarray(
            [[float(values[feature]) for feature in self._feature_order]], dtype=float
        )
        try:
            raw_score = -float(np.asarray(self._model.score_samples(features), dtype=float)[0])
        except Exception as error:
            raise AnomalyPredictionError(f"Anomaly scoring failed: {error}") from error
        normalized = float(
            np.clip(
                (raw_score - self._raw_low) / (self._raw_high - self._raw_low),
                0.0,
                1.0,
            )
        )
        return AnomalyPrediction(
            flow_id=validated.flow_id,
            anomaly_score=round(normalized, 6),
            anomaly_status=(
                AnomalyStatus.SUSPICIOUS
                if raw_score > self._raw_threshold
                else AnomalyStatus.NORMAL
            ),
            model_version=self._model_version,
        )


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=service_root / "config" / "model.yaml")
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        detector = AnomalyDetector.from_config(args.config)
        result = detector.predict(load_input(args.input))
    except (AnomalyPredictionError, ValueError) as error:
        LOGGER.error("Anomaly prediction failed: %s", error)
        raise SystemExit(2) from error
    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

"""Local prediction entry point for the selected persisted traffic classifier.

Example:

    python -m src.predict --input sample.json

This module deliberately exposes no HTTP or gRPC surface. Instantiate one
``Predictor`` per process so model loading occurs once and subsequent flow
predictions reuse the in-memory selected model.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

import joblib
import numpy as np
import yaml
from pydantic import ValidationError

from src.explain import ExplanationError, explain_prediction
from src.schemas import ClassPrediction, FeatureExplanation, FlowFeatures, PredictionResult, TrafficClass
from src.unknown_detection import apply_confidence_threshold, validate_threshold

LOGGER = logging.getLogger(__name__)


class PredictionError(ValueError):
    """Raised for safe, user-actionable local prediction failures."""


@dataclass(frozen=True)
class PredictionConfig:
    """Resolved selected-model locations and calibrated rejection threshold."""

    models_dir: Path
    training_metrics_path: Path
    confidence_threshold: float


def _resolve_path(config_path: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise PredictionError(f"{field} must be a non-empty path")
    path = Path(value)
    return path if path.is_absolute() else (config_path.parent / path).resolve()


def load_prediction_config(
    config_path: Path,
    *,
    models_dir_override: Path | None = None,
    training_metrics_override: Path | None = None,
) -> PredictionConfig:
    """Load the model paths and only an explicitly calibrated threshold."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise PredictionError(f"Could not read model config {config_path}: {error}") from error
    if not isinstance(raw, Mapping):
        raise PredictionError("Model configuration must be a mapping")
    model = raw.get("model")
    unknown = raw.get("unknown_detection")
    if not isinstance(model, Mapping) or not isinstance(unknown, Mapping):
        raise PredictionError("Model configuration needs model and unknown_detection mappings")
    if unknown.get("method") != "max_class_probability_threshold":
        raise PredictionError("Unsupported unknown_detection.method")
    threshold = unknown.get("confidence_threshold")
    if threshold is None:
        raise PredictionError(
            "UNKNOWN confidence threshold is not calibrated; run python -m src.calibrate_unknown"
        )
    try:
        calibrated_threshold = validate_threshold(float(threshold))
    except (TypeError, ValueError) as error:
        raise PredictionError(f"Invalid calibrated UNKNOWN threshold: {error}") from error
    return PredictionConfig(
        models_dir=(models_dir_override or _resolve_path(config_path, model.get("models_dir"), "model.models_dir")).resolve(),
        training_metrics_path=(
            training_metrics_override
            or _resolve_path(
                config_path, model.get("training_metrics_path"), "model.training_metrics_path"
            )
        ).resolve(),
        confidence_threshold=calibrated_threshold,
    )


class Predictor:
    """A single in-memory selected model with validated prediction behavior."""

    def __init__(self, config: PredictionConfig) -> None:
        self._config = config
        metadata_path = config.models_dir / "model_metadata.json"
        required = [metadata_path, config.training_metrics_path]
        missing = [path for path in required if not path.is_file()]
        if missing:
            raise PredictionError(
                "Required selected-model artifacts are unavailable: "
                + ", ".join(str(path) for path in missing)
            )
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            training_metrics = json.loads(config.training_metrics_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PredictionError(f"Could not read selected-model metadata: {error}") from error
        selected = training_metrics.get("selected_model")
        filenames = {"random_forest": "random_forest.joblib", "xgboost": "xgboost.joblib"}
        if selected not in filenames:
            raise PredictionError("Training metrics do not identify a supported selected_model")
        model_path = config.models_dir / filenames[str(selected)]
        if not model_path.is_file():
            raise PredictionError(f"Selected model artifact does not exist: {model_path}")

        self._feature_order = self._validate_feature_order(metadata.get("feature_order"))
        self._class_order = self._validate_class_order(metadata.get("class_order"))
        model_version = metadata.get("model_version")
        if not isinstance(model_version, str) or not model_version.strip():
            raise PredictionError("Model metadata has no model_version")
        self._model_version = model_version
        self._assert_threshold_matches_metadata(metadata)
        try:
            self._model = joblib.load(model_path)
        except Exception as error:  # joblib has several backend-specific exception types.
            raise PredictionError(f"Could not load selected model {model_path}: {error}") from error
        if not hasattr(self._model, "predict_proba"):
            raise PredictionError("Selected model does not expose predict_proba")
        self._selected_model = str(selected)

    @classmethod
    def from_config(
        cls,
        config_path: Path,
        *,
        models_dir_override: Path | None = None,
        training_metrics_override: Path | None = None,
    ) -> "Predictor":
        """Build a reusable predictor from structured configuration."""

        return cls(
            load_prediction_config(
                config_path,
                models_dir_override=models_dir_override,
                training_metrics_override=training_metrics_override,
            )
        )

    @property
    def model_version(self) -> str:
        """Version of the selected model loaded by this process."""

        return self._model_version

    @property
    def selected_model(self) -> str:
        """Selected persisted model family name."""

        return self._selected_model

    @staticmethod
    def _validate_feature_order(value: object) -> tuple[str, ...]:
        if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
            raise PredictionError("Model metadata feature_order is invalid")
        allowed = set(FlowFeatures.model_fields) - {"flow_id"}
        order = tuple(value)
        invalid = [feature for feature in order if feature not in allowed]
        if invalid or len(set(order)) != len(order):
            raise PredictionError("Model metadata feature_order contains invalid or duplicate features")
        return order

    @staticmethod
    def _validate_class_order(value: object) -> tuple[TrafficClass, ...]:
        if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
            raise PredictionError("Model metadata class_order is invalid")
        try:
            classes = tuple(TrafficClass(item) for item in value)
        except ValueError as error:
            raise PredictionError("Model metadata contains an unsupported traffic class") from error
        if TrafficClass.UNKNOWN in classes or len(set(classes)) != len(classes):
            raise PredictionError("Model class_order must contain unique known traffic classes")
        return classes

    def _assert_threshold_matches_metadata(self, metadata: Mapping[str, Any]) -> None:
        unknown = metadata.get("unknown_detection")
        if not isinstance(unknown, Mapping) or unknown.get("status") != "calibrated":
            return
        stored = unknown.get("confidence_threshold")
        try:
            stored_threshold = validate_threshold(float(stored))
        except (TypeError, ValueError) as error:
            raise PredictionError("Model metadata has an invalid calibrated UNKNOWN threshold") from error
        if not np.isclose(stored_threshold, self._config.confidence_threshold, atol=1e-12):
            raise PredictionError("Configured UNKNOWN threshold does not match selected model metadata")

    def _validate_flow(self, flow: FlowFeatures | Mapping[str, Any]) -> FlowFeatures:
        try:
            return flow if isinstance(flow, FlowFeatures) else FlowFeatures.model_validate(flow)
        except ValidationError as error:
            raise PredictionError(f"Invalid FlowFeatures input: {error}") from error

    def predict(
        self, flow: FlowFeatures | Mapping[str, Any], *, include_explanations: bool = False
    ) -> PredictionResult:
        """Classify one validated flow with optional compact SHAP explanation."""

        started = perf_counter()
        validated_flow = self._validate_flow(flow)
        values = validated_flow.model_dump()
        feature_vector = np.asarray(
            [[float(values[feature]) for feature in self._feature_order]], dtype=float
        )
        try:
            probabilities = np.asarray(self._model.predict_proba(feature_vector), dtype=float)
        except Exception as error:
            raise PredictionError(f"Selected model prediction failed: {error}") from error
        if probabilities.shape != (1, len(self._class_order)):
            raise PredictionError("Selected model probability output does not match class metadata")
        probability_row = probabilities[0]
        try:
            decision = apply_confidence_threshold(
                probability_row,
                [item.value for item in self._class_order],
                self._config.confidence_threshold,
                top_k=3,
            )
        except ValueError as error:
            raise PredictionError(f"Selected model returned invalid probabilities: {error}") from error
        predicted_index = int(np.argmax(probability_row))
        try:
            explanation_items = explain_prediction(
                self._model,
                feature_vector[0],
                self._feature_order,
                predicted_index,
                enabled=include_explanations,
            )
            explanations = [FeatureExplanation.model_validate(item) for item in explanation_items]
        except (ExplanationError, ValidationError) as error:
            raise PredictionError(f"Prediction explanation failed: {error}") from error

        return PredictionResult(
            flow_id=validated_flow.flow_id,
            predicted_class=TrafficClass(decision.predicted_class),
            confidence=decision.confidence,
            is_unknown=decision.is_unknown,
            top_predictions=[
                ClassPrediction(
                    traffic_class=TrafficClass(item.traffic_class), confidence=item.confidence
                )
                for item in decision.top_predictions
            ],
            model_version=self._model_version,
            top_explanations=explanations,
            inference_time_ms=round((perf_counter() - started) * 1_000, 6),
        )


def load_input(path: Path) -> Mapping[str, Any]:
    """Load exactly one JSON object for the local command-line interface."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PredictionError(f"Could not read JSON input {path}: {error}") from error
    if not isinstance(value, Mapping):
        raise PredictionError("Prediction input JSON must be one object")
    return value


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="One FlowFeatures JSON object.")
    parser.add_argument("--explain", action="store_true", help="Include up to five SHAP feature impacts.")
    parser.add_argument("--config", type=Path, default=service_root / "config" / "model.yaml")
    parser.add_argument("--models-dir", type=Path)
    parser.add_argument("--training-metrics", type=Path)
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        predictor = Predictor.from_config(
            args.config,
            models_dir_override=args.models_dir,
            training_metrics_override=args.training_metrics,
        )
        result = predictor.predict(load_input(args.input), include_explanations=args.explain)
    except PredictionError as error:
        LOGGER.error("Prediction failed: %s", error)
        raise SystemExit(2) from error
    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

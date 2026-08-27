"""Offline PCAP/PCAPNG-to-prediction pipeline using traffic metadata only.

Example:

    python -m src.analyze_pcap --pcap capture.pcap

Packets are grouped into bidirectional flow windows. No payload is decrypted or
used as a model feature.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from src.features import FeatureExtractionConfig, extract_window_features
from src.predict import PredictionError, Predictor
from src.schemas import FlowFeatures, PredictionResult

LOGGER = logging.getLogger(__name__)

KEY_STATISTICS = (
    "duration",
    "packet_count",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "mean_packet_size",
    "upload_packets",
    "download_packets",
    "upload_bytes",
    "download_bytes",
    "burst_count",
    "idle_time_ratio",
)


class PcapAnalysisError(ValueError):
    """Raised when an offline capture cannot be analyzed safely."""


def _positive_float(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise PcapAnalysisError(f"feature_extraction.{field} must be a positive number")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise PcapAnalysisError(
            f"feature_extraction.{field} must be a positive number"
        ) from error
    if number <= 0:
        raise PcapAnalysisError(f"feature_extraction.{field} must be a positive number")
    return number


def load_feature_extraction_config(
    config_path: Path,
    *,
    window_duration_override: float | None = None,
    burst_gap_override: float | None = None,
    idle_gap_override: float | None = None,
) -> FeatureExtractionConfig:
    """Load configured window and timing thresholds from model YAML."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise PcapAnalysisError(f"Could not read model config {config_path}: {error}") from error
    extraction = raw.get("feature_extraction") if isinstance(raw, Mapping) else None
    if not isinstance(extraction, Mapping):
        raise PcapAnalysisError("Model config has no feature_extraction mapping")
    config = FeatureExtractionConfig(
        window_duration_seconds=_positive_float(
            window_duration_override
            if window_duration_override is not None
            else extraction.get("window_duration_seconds"),
            "window_duration_seconds",
        ),
        burst_gap_seconds=_positive_float(
            burst_gap_override if burst_gap_override is not None else extraction.get("burst_gap_seconds"),
            "burst_gap_seconds",
        ),
        idle_gap_seconds=_positive_float(
            idle_gap_override if idle_gap_override is not None else extraction.get("idle_gap_seconds"),
            "idle_gap_seconds",
        ),
    )
    try:
        config.validate()
    except ValueError as error:
        raise PcapAnalysisError(f"Invalid feature extraction configuration: {error}") from error
    return config


def _window_output(features: FlowFeatures, prediction: PredictionResult) -> dict[str, Any]:
    values = features.model_dump()
    return {
        "flow_window_id": prediction.flow_id,
        "predicted_class": prediction.predicted_class.value,
        "confidence": prediction.confidence,
        "is_unknown": prediction.is_unknown,
        "top_predictions": [
            {
                "traffic_class": item.traffic_class.value,
                "confidence": item.confidence,
            }
            for item in prediction.top_predictions
        ],
        "flow_statistics": {name: values[name] for name in KEY_STATISTICS},
        "explanations": [item.model_dump(mode="json") for item in prediction.top_explanations],
        "model_version": prediction.model_version,
        "inference_time_ms": prediction.inference_time_ms,
    }


def _summary(path: Path, windows: list[dict[str, Any]]) -> dict[str, Any]:
    class_distribution = Counter(str(item["predicted_class"]) for item in windows)
    unknown_count = sum(bool(item["is_unknown"]) for item in windows)
    confidences = [float(item["confidence"]) for item in windows]
    statistics = [item["flow_statistics"] for item in windows]
    return {
        "capture_name": path.name,
        "capture_size_bytes": path.stat().st_size,
        "valid_windows": len(windows),
        "class_distribution": dict(sorted(class_distribution.items())),
        "unknown_windows": unknown_count,
        "unknown_rate": round(unknown_count / len(windows), 6) if windows else 0.0,
        "average_confidence": round(sum(confidences) / len(confidences), 6) if confidences else None,
        "analyzed_packets": sum(int(item["packet_count"]) for item in statistics),
        "analyzed_bytes": sum(int(item["total_bytes"]) for item in statistics),
        "sum_window_duration_seconds": round(
            sum(float(item["duration"]) for item in statistics), 6
        ),
        "payload_decryption_attempted": False,
    }


def analyze_capture(
    path: Path,
    predictor: Predictor,
    feature_config: FeatureExtractionConfig,
    *,
    include_explanations: bool = False,
) -> dict[str, Any]:
    """Extract, validate, and classify every valid flow window in one capture."""

    if not path.is_file():
        raise PcapAnalysisError(f"Capture does not exist: {path}")
    if path.suffix.casefold() not in {".pcap", ".pcapng"}:
        raise PcapAnalysisError("Capture must use a .pcap or .pcapng extension")
    windows: list[dict[str, Any]] = []
    try:
        extracted = extract_window_features(path, path.name, feature_config)
        for raw_features in extracted:
            try:
                features = FlowFeatures.model_validate(raw_features)
            except ValidationError as error:
                LOGGER.warning(
                    "Skipping invalid flow window %s: %s", raw_features.get("flow_id"), error
                )
                continue
            prediction = predictor.predict(
                features, include_explanations=include_explanations
            )
            windows.append(_window_output(features, prediction))
    except (OSError, ValueError, PredictionError) as error:
        raise PcapAnalysisError(f"Could not analyze capture {path}: {error}") from error
    return {
        "capture": {
            "name": path.name,
            "format": path.suffix.casefold().lstrip("."),
        },
        "windows": windows,
        "summary": _summary(path, windows),
    }


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--config", type=Path, default=service_root / "config" / "model.yaml")
    parser.add_argument("--models-dir", type=Path)
    parser.add_argument("--training-metrics", type=Path)
    parser.add_argument("--window-seconds", type=float)
    parser.add_argument("--burst-gap-seconds", type=float)
    parser.add_argument("--idle-gap-seconds", type=float)
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        feature_config = load_feature_extraction_config(
            args.config,
            window_duration_override=args.window_seconds,
            burst_gap_override=args.burst_gap_seconds,
            idle_gap_override=args.idle_gap_seconds,
        )
        predictor = Predictor.from_config(
            args.config,
            models_dir_override=args.models_dir,
            training_metrics_override=args.training_metrics,
        )
        report = analyze_capture(
            args.pcap,
            predictor,
            feature_config,
            include_explanations=args.explain,
        )
    except (PcapAnalysisError, PredictionError) as error:
        LOGGER.error("PCAP analysis failed: %s", error)
        raise SystemExit(2) from error
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

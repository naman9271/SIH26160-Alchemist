"""Optional, compact SHAP explanations for persisted tree-model predictions.

SHAP is imported only when an explanation is requested. The normal inference
path can therefore call :func:`explain_prediction` with ``enabled=False``
without incurring SHAP's import or computation cost.
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

import numpy as np

MAX_EXPLANATIONS = 5

FEATURE_DISPLAY_NAMES = {
    "duration": "Flow Duration",
    "packet_count": "Packet Count",
    "total_bytes": "Total Bytes",
    "packets_per_second": "Packets per Second",
    "bytes_per_second": "Bytes per Second",
    "mean_packet_size": "Average Packet Size",
    "std_packet_size": "Packet Size Variation",
    "min_packet_size": "Minimum Packet Size",
    "max_packet_size": "Maximum Packet Size",
    "p25_packet_size": "25th Percentile Packet Size",
    "median_packet_size": "Median Packet Size",
    "p75_packet_size": "75th Percentile Packet Size",
    "p95_packet_size": "95th Percentile Packet Size",
    "mean_interarrival_time": "Average Interarrival Time",
    "std_interarrival_time": "Interarrival Time Variation",
    "upload_packets": "Upload Packets",
    "download_packets": "Download Packets",
    "upload_bytes": "Upload Bytes",
    "download_bytes": "Download Bytes",
    "upload_download_ratio": "Upload/Download Ratio",
    "burst_count": "Burst Count",
    "mean_burst_size": "Average Burst Size",
    "idle_time_ratio": "Idle Time Ratio",
}


class ExplanationError(ValueError):
    """Raised when a selected model cannot produce a safe SHAP explanation."""


@dataclass(frozen=True)
class FeatureImpact:
    """Small frontend-safe explanation item; never exposes a full SHAP matrix."""

    feature: str
    display_name: str
    value: float
    impact: float
    direction: str

    def to_dict(self) -> dict[str, str | float]:
        """Return the API representation expected by frontend consumers."""

        return asdict(self)


def _load_shap() -> Any:
    try:
        return importlib.import_module("shap")
    except ImportError as error:
        raise ExplanationError(
            "SHAP explanations require the optional shap dependency; install requirements.txt"
        ) from error


def _pipeline_parts(model: Any) -> tuple[Any, Any]:
    named_steps = getattr(model, "named_steps", None)
    if not isinstance(named_steps, dict):
        raise ExplanationError("Selected model must be a fitted sklearn pipeline")
    imputer = named_steps.get("imputer")
    classifier = named_steps.get("classifier")
    if imputer is None or classifier is None:
        raise ExplanationError("Selected model pipeline must contain imputer and classifier steps")
    if not (hasattr(classifier, "estimators_") or hasattr(classifier, "get_booster")):
        raise ExplanationError("SHAP explanations support only fitted tree classifiers")
    return imputer, classifier


def _class_impacts(shap_values: Any, class_index: int, feature_count: int) -> np.ndarray:
    """Normalize SHAP's version-dependent multiclass output into one vector."""

    values = getattr(shap_values, "values", shap_values)
    if isinstance(values, list):
        if class_index >= len(values):
            raise ExplanationError("Predicted class index is absent from SHAP output")
        selected = np.asarray(values[class_index], dtype=float)
        if selected.ndim == 2 and selected.shape[0] == 1:
            selected = selected[0]
    else:
        array = np.asarray(values, dtype=float)
        if array.ndim == 2:
            selected = array[0] if array.shape[0] == 1 else array
        elif array.ndim == 3:
            if array.shape[0] == 1 and array.shape[1] == feature_count:
                selected = array[0, :, class_index]
            elif array.shape[0] > class_index and array.shape[2] == feature_count:
                selected = array[class_index, 0, :]
            else:
                raise ExplanationError("Unsupported multiclass SHAP output dimensions")
        else:
            raise ExplanationError("Unsupported SHAP output dimensions")
    selected = np.asarray(selected, dtype=float).reshape(-1)
    if selected.shape[0] != feature_count or not np.all(np.isfinite(selected)):
        raise ExplanationError("SHAP output does not match finite model feature contributions")
    return selected


def explain_prediction(
    model: Any,
    feature_values: Sequence[float] | np.ndarray,
    feature_order: Sequence[str],
    predicted_class_index: int,
    *,
    enabled: bool = False,
    max_features: int = MAX_EXPLANATIONS,
) -> list[dict[str, str | float]]:
    """Return at most five ranked contributions for one selected-model prediction.

    ``predicted_class_index`` is the index of the selected class in persisted
    model metadata. When disabled, this function returns immediately without
    importing SHAP or transforming data.
    """

    if not enabled:
        return []
    if not 1 <= max_features <= MAX_EXPLANATIONS:
        raise ExplanationError(f"max_features must be within [1, {MAX_EXPLANATIONS}]")
    values = np.asarray(feature_values, dtype=float)
    if values.ndim != 1 or len(values) != len(feature_order):
        raise ExplanationError("feature_values must be one-dimensional and match feature_order")
    if not isinstance(predicted_class_index, int) or predicted_class_index < 0:
        raise ExplanationError("predicted_class_index must be a non-negative integer")

    imputer, classifier = _pipeline_parts(model)
    transformed = np.asarray(imputer.transform(values.reshape(1, -1)), dtype=float)
    if transformed.shape != (1, len(feature_order)):
        raise ExplanationError("Imputer output does not match the persisted feature order")
    if not np.all(np.isfinite(transformed)):
        raise ExplanationError("Imputer output contains NaN or infinite values")
    shap = _load_shap()
    impacts = _class_impacts(
        shap.TreeExplainer(classifier).shap_values(transformed),
        predicted_class_index,
        len(feature_order),
    )
    ranked_indices = sorted(range(len(feature_order)), key=lambda index: abs(impacts[index]), reverse=True)
    explanations = []
    for index in ranked_indices[:max_features]:
        impact = float(impacts[index])
        explanations.append(
            FeatureImpact(
                feature=str(feature_order[index]),
                display_name=FEATURE_DISPLAY_NAMES.get(
                    str(feature_order[index]), str(feature_order[index]).replace("_", " ").title()
                ),
                value=round(float(transformed[0, index]), 6),
                impact=round(impact, 6),
                direction=(
                    "supports_prediction"
                    if impact > 0
                    else "opposes_prediction" if impact < 0 else "neutral"
                ),
            ).to_dict()
        )
    return explanations

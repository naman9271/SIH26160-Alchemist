"""Confidence-threshold rejection for open-set traffic classification.

This is a baseline open-set method. A low maximum class probability is useful
for rejecting uncertain predictions, but it cannot guarantee detection of every
unseen traffic type.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Sequence

import numpy as np

UNKNOWN_LABEL = "UNKNOWN"


@dataclass(frozen=True)
class RankedPrediction:
    """A known model class and its probability."""

    traffic_class: str
    confidence: float


@dataclass(frozen=True)
class UnknownDecision:
    """Thresholded decision while preserving the model's known-class ranking."""

    predicted_class: str
    confidence: float
    is_unknown: bool
    top_predictions: tuple[RankedPrediction, ...]


def validate_threshold(threshold: float) -> float:
    """Validate and normalize a confidence threshold."""

    if isinstance(threshold, bool) or not isfinite(float(threshold)):
        raise ValueError("confidence threshold must be finite")
    normalized = float(threshold)
    if not 0 <= normalized <= 1:
        raise ValueError("confidence threshold must be within [0, 1]")
    return normalized


def apply_confidence_threshold(
    probabilities: Sequence[float] | np.ndarray,
    class_order: Sequence[str],
    threshold: float,
    *,
    top_k: int = 3,
) -> UnknownDecision:
    """Return UNKNOWN when the largest known-class probability is too low."""

    validated_threshold = validate_threshold(threshold)
    values = np.asarray(probabilities, dtype=float)
    if values.ndim != 1 or len(values) != len(class_order) or not len(values):
        raise ValueError("probabilities must be one-dimensional and match class_order")
    if len(set(class_order)) != len(class_order) or any(not label for label in class_order):
        raise ValueError("class_order must contain unique non-empty labels")
    if UNKNOWN_LABEL in class_order:
        raise ValueError("UNKNOWN must be a rejection outcome, not a fitted model class")
    if top_k < 1:
        raise ValueError("top_k must be positive")
    if not np.all(np.isfinite(values)) or np.any(values < 0) or np.any(values > 1):
        raise ValueError("probabilities must be finite values within [0, 1]")
    if not np.isclose(float(values.sum()), 1.0, atol=1e-6):
        raise ValueError("class probabilities must sum to 1")

    ranking = np.argsort(values)[::-1]
    best_index = int(ranking[0])
    confidence = float(values[best_index])
    is_unknown = confidence < validated_threshold
    top_predictions = tuple(
        RankedPrediction(str(class_order[int(index)]), float(values[int(index)]))
        for index in ranking[: min(top_k, len(ranking))]
    )
    return UnknownDecision(
        predicted_class=UNKNOWN_LABEL if is_unknown else str(class_order[best_index]),
        confidence=confidence,
        is_unknown=is_unknown,
        top_predictions=top_predictions,
    )

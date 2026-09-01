"""Tests for confidence-threshold UNKNOWN decisions."""

from __future__ import annotations

import pytest

from src.unknown_detection import UNKNOWN_LABEL, apply_confidence_threshold


def test_low_maximum_probability_returns_unknown_and_preserves_known_ranking() -> None:
    decision = apply_confidence_threshold(
        [0.45, 0.35, 0.20], ["web", "video", "voip"], threshold=0.50, top_k=2
    )

    assert decision.predicted_class == UNKNOWN_LABEL
    assert decision.is_unknown is True
    assert decision.confidence == pytest.approx(0.45)
    assert [item.traffic_class for item in decision.top_predictions] == ["web", "video"]


def test_sufficient_probability_returns_known_class() -> None:
    decision = apply_confidence_threshold(
        [0.15, 0.75, 0.10], ["web", "video", "voip"], threshold=0.70
    )

    assert decision.predicted_class == "video"
    assert decision.is_unknown is False


@pytest.mark.parametrize("threshold", [-0.01, 1.01, float("nan")])
def test_invalid_threshold_is_rejected(threshold: float) -> None:
    with pytest.raises(ValueError, match="threshold"):
        apply_confidence_threshold([0.5, 0.5], ["web", "video"], threshold)


def test_probabilities_must_form_a_distribution() -> None:
    with pytest.raises(ValueError, match="sum to 1"):
        apply_confidence_threshold([0.2, 0.2], ["web", "video"], 0.5)

"""Tests for compact optional SHAP prediction explanations."""

from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from src.explain import ExplanationError, explain_prediction


class IdentityImputer:
    def transform(self, values: np.ndarray) -> np.ndarray:
        return values


class FakeTreeClassifier:
    estimators_ = [object()]


def selected_tree_pipeline() -> SimpleNamespace:
    return SimpleNamespace(
        named_steps={"imputer": IdentityImputer(), "classifier": FakeTreeClassifier()}
    )


def test_disabled_explanations_return_without_loading_shap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.explain._load_shap", lambda: pytest.fail("SHAP was loaded"))

    result = explain_prediction(
        selected_tree_pipeline(), [1.0, 2.0], ["duration", "packet_count"], 0, enabled=False
    )

    assert result == []


def test_explanations_are_top_five_frontend_safe_items(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeExplainer:
        def __init__(self, classifier: FakeTreeClassifier) -> None:
            assert isinstance(classifier, FakeTreeClassifier)

        def shap_values(self, values: np.ndarray) -> np.ndarray:
            assert values.shape == (1, 6)
            # Current SHAP-style output: samples × features × classes.
            return np.array(
                [
                    [
                        [0.1, 0.2],
                        [0.2, -0.4],
                        [0.1, 0.0],
                        [0.3, 0.31],
                        [0.4, -0.15],
                        [0.5, 0.08],
                    ]
                ]
            )

    monkeypatch.setattr("src.explain._load_shap", lambda: SimpleNamespace(TreeExplainer=FakeExplainer))
    features = [1180.2, 10.0, 1500.0, 4.0, 600.0, 150.0]
    names = [
        "mean_packet_size",
        "packet_count",
        "total_bytes",
        "packets_per_second",
        "bytes_per_second",
        "unknown_custom_feature",
    ]

    result = explain_prediction(
        selected_tree_pipeline(), features, names, predicted_class_index=1, enabled=True
    )

    assert len(result) == 5
    assert result[0] == {
        "feature": "packet_count",
        "display_name": "Packet Count",
        "value": 10.0,
        "impact": -0.4,
        "direction": "opposes_prediction",
    }
    assert result[1]["feature"] == "packets_per_second"
    assert result[1]["direction"] == "supports_prediction"
    assert {"feature", "display_name", "value", "impact", "direction"} == set(result[0])
    assert result[-1]["feature"] == "unknown_custom_feature"
    assert result[-1]["display_name"] == "Unknown Custom Feature"


def test_explanations_reject_more_than_five_requested_features() -> None:
    with pytest.raises(ExplanationError, match="max_features"):
        explain_prediction(
            selected_tree_pipeline(), [1.0], ["duration"], 0, enabled=True, max_features=6
        )

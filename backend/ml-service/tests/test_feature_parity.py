from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.features import (
    DEFAULT_BURST_GAP_SECONDS,
    DEFAULT_IDLE_GAP_SECONDS,
    _FlowAccumulator,
    _finalize_flow,
)


def test_python_features_match_shared_golden_capture() -> None:
    path = Path(__file__).resolve().parents[2] / "src/internal/featurespec/golden_capture.json"
    golden = json.loads(path.read_text(encoding="utf-8"))
    flow = _FlowAccumulator(initiator=("first-observed", 0))
    for packet in golden["packets"]:
        flow.add_direction(packet["time_seconds"], packet["size_bytes"], packet["forward"])
    result = _finalize_flow(
        golden["capture_id"],
        "one-channel",
        flow,
        burst_gap_seconds=DEFAULT_BURST_GAP_SECONDS,
        idle_gap_seconds=DEFAULT_IDLE_GAP_SECONDS,
        require_complete_features=True,
    )
    assert result is not None
    for name, expected in golden["expected"].items():
        assert result[name] == pytest.approx(expected, abs=1e-9)

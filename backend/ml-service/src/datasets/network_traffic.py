"""Adapter for Network-Traffic-Dataset packet captures."""

from __future__ import annotations

import re
from pathlib import Path

from src.datasets.pcap_base import PcapDatasetAdapter


class NetworkTrafficDatasetAdapter(PcapDatasetAdapter):
    cli_name = "network-traffic-dataset"
    mapping_dataset_name = "Network-Traffic-Dataset"
    input_name = "Network-Traffic-Dataset"

    def original_label_for_capture(self, capture_path: Path) -> str:
        relative = capture_path.relative_to(self.input_path)
        if len(relative.parts) > 1:
            return relative.parts[0]
        return re.sub(r"[_-]?\d+$", "", capture_path.stem).replace("_", " ")

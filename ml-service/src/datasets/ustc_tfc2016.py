"""Adapter for USTC-TFC2016 benign and malware packet captures."""

from __future__ import annotations

import re
from pathlib import Path

from src.datasets.pcap_base import PcapDatasetAdapter


class UstcTfc2016Adapter(PcapDatasetAdapter):
    cli_name = "ustc-tfc2016"
    mapping_dataset_name = "USTC-TFC2016"
    input_name = "USTC-TFC2016"

    def original_label_for_capture(self, capture_path: Path) -> str:
        relative = capture_path.relative_to(self.input_path)
        components = list(relative.parts[:-1])
        if components and components[0] in {"Benign", "Malware"}:
            components = components[1:]
        if components:
            return components[0]
        return re.sub(r"[_-]?\d+$", "", capture_path.stem)

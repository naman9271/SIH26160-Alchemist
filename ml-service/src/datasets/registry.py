"""Explicit registry for independently runnable public-dataset adapters."""

from __future__ import annotations

from pathlib import Path
from typing import TypeAlias

from src.datasets.base import DatasetAdapter
from src.datasets.cic_darknet2020 import CicDarknet2020Adapter
from src.datasets.cic_vpn2016 import CicVpn2016Adapter
from src.datasets.ipsec_pcap_lab import IpsecPcapLabAdapter
from src.datasets.network_traffic import NetworkTrafficDatasetAdapter
from src.datasets.ustc_tfc2016 import UstcTfc2016Adapter
from src.label_mapping import ClassMappingConfig

AdapterType: TypeAlias = type[DatasetAdapter]

ADAPTERS: dict[str, AdapterType] = {
    CicDarknet2020Adapter.cli_name: CicDarknet2020Adapter,
    CicVpn2016Adapter.cli_name: CicVpn2016Adapter,
    IpsecPcapLabAdapter.cli_name: IpsecPcapLabAdapter,
    NetworkTrafficDatasetAdapter.cli_name: NetworkTrafficDatasetAdapter,
    UstcTfc2016Adapter.cli_name: UstcTfc2016Adapter,
}


def create_adapter(
    dataset_name: str, external_root: Path, class_mappings: ClassMappingConfig
) -> DatasetAdapter:
    """Create exactly one requested adapter; datasets are never combined here."""

    try:
        adapter_type = ADAPTERS[dataset_name]
    except KeyError as error:
        supported = ", ".join(sorted(ADAPTERS))
        raise ValueError(f"Unknown dataset {dataset_name!r}; choose one of: {supported}") from error
    return adapter_type(external_root=external_root, class_mappings=class_mappings)

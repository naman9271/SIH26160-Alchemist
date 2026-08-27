"""Dataset-specific preprocessing adapters."""

from src.datasets.registry import ADAPTERS, create_adapter

__all__ = ["ADAPTERS", "create_adapter"]

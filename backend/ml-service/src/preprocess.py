"""Preprocess one audited public dataset into the common nullable schema.

Example:

    python -m src.preprocess --dataset cic-vpn2016

This command never combines datasets and does not train a model.
"""

from __future__ import annotations

import argparse
import logging
import os
from collections.abc import Iterable
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from src.datasets import ADAPTERS, create_adapter
from src.datasets.base import NUMERIC_FEATURE_COLUMNS, PreprocessedRecord
from src.label_mapping import load_class_mapping

LOGGER = logging.getLogger(__name__)

INTEGER_FEATURES = {
    "packet_count",
    "total_bytes",
    "upload_packets",
    "download_packets",
    "upload_bytes",
    "download_bytes",
    "burst_count",
}


def common_arrow_schema() -> pa.Schema:
    """Return a stable physical schema shared by all independent outputs."""

    fields = [
        pa.field("dataset_source", pa.string(), nullable=False),
        pa.field("capture_id", pa.string()),
        pa.field("source_record_id", pa.string()),
        pa.field("original_label", pa.string(), nullable=False),
        pa.field("canonical_label", pa.string(), nullable=False),
        pa.field("split_group_id", pa.string(), nullable=False),
        pa.field("declared_split", pa.string()),
        pa.field("locked_test_generation", pa.string()),
        pa.field("excluded_leakage_columns", pa.list_(pa.string()), nullable=False),
        pa.field("flow_id", pa.string()),
    ]
    fields.extend(
        pa.field(name, pa.int64() if name in INTEGER_FEATURES else pa.float64())
        for name in NUMERIC_FEATURE_COLUMNS
    )
    return pa.schema(fields)


def write_records(
    records: Iterable[PreprocessedRecord], output_path: Path, batch_size: int = 10_000
) -> int:
    """Write validated records atomically in bounded batches."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    schema = common_arrow_schema()
    writer: pq.ParquetWriter | None = None
    batch: list[dict[str, object]] = []
    written = 0

    def flush() -> None:
        nonlocal writer, written
        if not batch:
            return
        table = pa.Table.from_pylist(batch, schema=schema)
        writer = writer or pq.ParquetWriter(temporary_path, schema=schema, compression="snappy")
        writer.write_table(table)
        written += len(batch)
        batch.clear()

    try:
        for record in records:
            batch.append(record.model_dump())
            if len(batch) >= batch_size:
                flush()
        flush()
        if writer is None:
            pq.write_table(pa.Table.from_pylist([], schema=schema), temporary_path)
        else:
            writer.close()
            writer = None
        temporary_path.replace(output_path)
    except Exception:
        if writer is not None:
            writer.close()
        temporary_path.unlink(missing_ok=True)
        raise
    return written


def preprocess_dataset(
    dataset_name: str,
    external_root: Path,
    output_dir: Path,
    mapping_path: Path,
) -> Path:
    """Preprocess one named dataset and return its independent output path."""

    mappings = load_class_mapping(mapping_path)
    adapter = create_adapter(dataset_name, external_root, mappings)
    output_path = output_dir / f"{dataset_name}.parquet"
    written = write_records(adapter.iter_records(), output_path)
    adapter.log_summary()
    LOGGER.info("Wrote %d records to %s", written, output_path)
    return output_path


def parse_args() -> argparse.Namespace:
    service_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, choices=sorted(ADAPTERS))
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path(os.environ.get("ML_EXTERNAL_DATA_DIR", service_root / "data" / "external")),
        help="External dataset root (or set ML_EXTERNAL_DATA_DIR).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.environ.get("ML_PROCESSED_DATA_DIR", service_root / "data" / "processed")),
        help="Independent output directory (or set ML_PROCESSED_DATA_DIR).",
    )
    parser.add_argument(
        "--mapping-config",
        type=Path,
        default=Path(
            os.environ.get("ML_CLASS_MAPPING_CONFIG", service_root / "config" / "class_mapping.yaml")
        ),
        help="Dataset-specific class mapping YAML (or set ML_CLASS_MAPPING_CONFIG).",
    )
    return parser.parse_args()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    preprocess_dataset(
        dataset_name=args.dataset,
        external_root=args.data_root,
        output_dir=args.output_dir,
        mapping_path=args.mapping_config,
    )


if __name__ == "__main__":
    main()

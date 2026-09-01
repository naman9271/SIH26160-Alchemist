"""Flow-level metadata extraction for PCAP and PCAPNG captures.

No payload decryption is attempted. Endpoint addresses and ports are used only
to group packets and are never returned as model features.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import socket
import statistics
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from math import floor, isfinite
from pathlib import Path
from typing import BinaryIO, Hashable

import dpkt

LOGGER = logging.getLogger(__name__)

DEFAULT_WINDOW_DURATION_SECONDS = 10.0
DEFAULT_BURST_GAP_SECONDS = 0.1
DEFAULT_IDLE_GAP_SECONDS = 1.0
CSV_FIELDNAMES = (
    "flow_id",
    "duration",
    "packet_count",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "p25_packet_size",
    "median_packet_size",
    "p75_packet_size",
    "p95_packet_size",
    "mean_interarrival_time",
    "std_interarrival_time",
    "upload_packets",
    "download_packets",
    "upload_bytes",
    "download_bytes",
    "upload_download_ratio",
    "burst_count",
    "mean_burst_size",
    "idle_time_ratio",
)


@dataclass(frozen=True)
class FeatureExtractionConfig:
    """Configured timing policy for inference-ready flow windows."""

    window_duration_seconds: float
    burst_gap_seconds: float
    idle_gap_seconds: float

    def validate(self) -> None:
        values = {
            "window_duration_seconds": self.window_duration_seconds,
            "burst_gap_seconds": self.burst_gap_seconds,
            "idle_gap_seconds": self.idle_gap_seconds,
        }
        for name, value in values.items():
            if not isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        if self.burst_gap_seconds >= self.idle_gap_seconds:
            raise ValueError("burst_gap_seconds must be below idle_gap_seconds")
        if self.idle_gap_seconds > self.window_duration_seconds:
            raise ValueError("idle_gap_seconds must not exceed window_duration_seconds")


@dataclass
class _FlowAccumulator:
    initiator: tuple[str, int]
    timestamps: list[float] = field(default_factory=list)
    packet_sizes: list[int] = field(default_factory=list)
    upload_sizes: list[int] = field(default_factory=list)
    download_sizes: list[int] = field(default_factory=list)
    upload_flags: list[bool] = field(default_factory=list)

    def add(self, timestamp: float, packet_size: int, source: tuple[str, int]) -> None:
        is_upload = source == self.initiator
        self.timestamps.append(timestamp)
        self.packet_sizes.append(packet_size)
        self.upload_flags.append(is_upload)
        if is_upload:
            self.upload_sizes.append(packet_size)
        else:
            self.download_sizes.append(packet_size)

    def add_direction(self, timestamp: float, packet_size: int, is_upload: bool) -> None:
        """Add a packet to a derived window without retaining endpoint metadata."""

        self.timestamps.append(timestamp)
        self.packet_sizes.append(packet_size)
        self.upload_flags.append(is_upload)
        if is_upload:
            self.upload_sizes.append(packet_size)
        else:
            self.download_sizes.append(packet_size)


def _capture_reader(file: BinaryIO, path: Path) -> dpkt.pcap.Reader | dpkt.pcapng.Reader:
    try:
        return dpkt.pcap.Reader(file)
    except (ValueError, dpkt.dpkt.NeedData):
        file.seek(0)
        try:
            return dpkt.pcapng.Reader(file)
        except (ValueError, dpkt.dpkt.NeedData) as error:
            raise ValueError(f"unsupported or corrupt capture: {path}") from error


def _network_packet(frame: bytes) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
    try:
        packet = dpkt.ethernet.Ethernet(frame).data
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None
    return packet if isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)) else None


def _endpoint(ip_packet: dpkt.ip.IP | dpkt.ip6.IP6, source: bool) -> tuple[str, int]:
    address = ip_packet.src if source else ip_packet.dst
    family = socket.AF_INET if isinstance(ip_packet, dpkt.ip.IP) else socket.AF_INET6
    host = socket.inet_ntop(family, address)
    transport = ip_packet.data
    port = 0
    if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        port = int(transport.sport if source else transport.dport)
    return host, port


def _flow_key(
    ip_packet: dpkt.ip.IP | dpkt.ip6.IP6,
) -> tuple[Hashable, tuple[str, int], tuple[str, int]]:
    source = _endpoint(ip_packet, True)
    destination = _endpoint(ip_packet, False)
    endpoints = tuple(sorted((source, destination)))
    protocol = int(ip_packet.p if isinstance(ip_packet, dpkt.ip.IP) else ip_packet.nxt)
    return (protocol, endpoints), source, destination


def _percentile(values: list[int], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def _flow_identifier(capture_id: str, key: Hashable) -> str:
    digest = hashlib.sha256(repr(key).encode("utf-8")).hexdigest()[:20]
    return f"{capture_id}:{digest}"


def _finalize_flow(
    capture_id: str,
    key: Hashable,
    flow: _FlowAccumulator,
    *,
    burst_gap_seconds: float | None = None,
    idle_gap_seconds: float | None = None,
    require_complete_features: bool = False,
) -> dict[str, object] | None:
    if len(flow.timestamps) < 2:
        return None
    ordered_timestamps = sorted(flow.timestamps)
    duration = ordered_timestamps[-1] - ordered_timestamps[0]
    if duration <= 0:
        return None

    interarrivals = [
        later - earlier for earlier, later in zip(ordered_timestamps, ordered_timestamps[1:])
    ]
    total_bytes = sum(flow.packet_sizes)
    upload_bytes = sum(flow.upload_sizes)
    download_bytes = sum(flow.download_sizes)
    burst_count: int | None = None
    mean_burst_size: float | None = None
    idle_time_ratio: float | None = None
    if burst_gap_seconds is not None and idle_gap_seconds is not None:
        burst_count = 1 + sum(gap > burst_gap_seconds for gap in interarrivals)
        mean_burst_size = len(flow.packet_sizes) / burst_count
        idle_time = sum(gap for gap in interarrivals if gap >= idle_gap_seconds)
        idle_time_ratio = min(1.0, idle_time / duration)
    return {
        "flow_id": _flow_identifier(capture_id, key),
        "duration": duration,
        "packet_count": len(flow.packet_sizes),
        "total_bytes": total_bytes,
        "packets_per_second": len(flow.packet_sizes) / duration,
        "bytes_per_second": total_bytes / duration,
        "mean_packet_size": statistics.fmean(flow.packet_sizes),
        "std_packet_size": statistics.pstdev(flow.packet_sizes),
        "min_packet_size": float(min(flow.packet_sizes)),
        "max_packet_size": float(max(flow.packet_sizes)),
        "p25_packet_size": _percentile(flow.packet_sizes, 0.25),
        "median_packet_size": _percentile(flow.packet_sizes, 0.50),
        "p75_packet_size": _percentile(flow.packet_sizes, 0.75),
        "p95_packet_size": _percentile(flow.packet_sizes, 0.95),
        "mean_interarrival_time": statistics.fmean(interarrivals),
        "std_interarrival_time": statistics.pstdev(interarrivals),
        "upload_packets": len(flow.upload_sizes),
        "download_packets": len(flow.download_sizes),
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
        "upload_download_ratio": (
            upload_bytes / download_bytes
            if download_bytes
            else float(upload_bytes) if require_complete_features else None
        ),
        "burst_count": burst_count,
        "mean_burst_size": mean_burst_size,
        "idle_time_ratio": idle_time_ratio,
    }


def _is_encrypted_ipsec_data(ip_packet: dpkt.ip.IP | dpkt.ip6.IP6) -> bool:
    """Accept ESP, including RFC 3948 UDP encapsulation, but not IKE/keepalives."""

    protocol = int(ip_packet.p if isinstance(ip_packet, dpkt.ip.IP) else ip_packet.nxt)
    if protocol == 50:
        return True
    transport = ip_packet.data
    if protocol != 17 or not isinstance(transport, dpkt.udp.UDP):
        return False
    if int(transport.sport) != 4500 and int(transport.dport) != 4500:
        return False
    payload = bytes(transport.data)
    if payload == b"\xff" or len(payload) < 4:
        return False
    return payload[:4] != b"\x00\x00\x00\x00"


def _read_capture_flows(
    path: Path,
    packet_filter: Callable[[dpkt.ip.IP | dpkt.ip6.IP6], bool] | None = None,
) -> tuple[dict[Hashable, _FlowAccumulator], int]:
    flows: dict[Hashable, _FlowAccumulator] = {}
    malformed_frames = 0
    with path.open("rb") as file:
        reader = _capture_reader(file, path)
        for timestamp, frame in reader:
            ip_packet = _network_packet(frame)
            if ip_packet is None:
                malformed_frames += 1
                continue
            if packet_filter is not None and not packet_filter(ip_packet):
                continue
            key, source, _ = _flow_key(ip_packet)
            flow = flows.setdefault(key, _FlowAccumulator(initiator=source))
            flow.add(float(timestamp), len(frame), source)
    return flows, malformed_frames


def extract_flow_features(path: Path, capture_id: str) -> Iterator[dict[str, object]]:
    """Yield bidirectional flow metadata from one PCAP or PCAPNG capture."""

    flows, malformed_frames = _read_capture_flows(path)

    if malformed_frames:
        LOGGER.info("%s ignored %d non-IP or malformed frames", path, malformed_frames)
    for key, flow in flows.items():
        features = _finalize_flow(capture_id, key, flow)
        if features is not None:
            yield features
        else:
            LOGGER.debug("%s skipped a flow with fewer than two timed packets", path)


def extract_window_features(
    path: Path,
    capture_id: str,
    config: FeatureExtractionConfig,
    *,
    encrypted_ipsec_only: bool = False,
) -> Iterator[dict[str, object]]:
    """Yield complete, inference-ready metadata for fixed per-flow windows."""

    config.validate()
    flows, malformed_frames = _read_capture_flows(
        path, _is_encrypted_ipsec_data if encrypted_ipsec_only else None
    )
    if malformed_frames:
        LOGGER.info("%s ignored %d non-IP or malformed frames", path, malformed_frames)
    for key, flow in flows.items():
        first_timestamp = min(flow.timestamps, default=0.0)
        windows: dict[int, _FlowAccumulator] = {}
        packets = zip(flow.timestamps, flow.packet_sizes, flow.upload_flags)
        for timestamp, packet_size, is_upload in packets:
            window_index = floor((timestamp - first_timestamp) / config.window_duration_seconds)
            window = windows.setdefault(
                window_index, _FlowAccumulator(initiator=flow.initiator)
            )
            window.add_direction(timestamp, packet_size, is_upload)
        for window_index, window in sorted(windows.items()):
            window_key = (key, "window", window_index)
            features = _finalize_flow(
                capture_id,
                window_key,
                window,
                burst_gap_seconds=config.burst_gap_seconds,
                idle_gap_seconds=config.idle_gap_seconds,
                require_complete_features=True,
            )
            if features is not None:
                yield features
            else:
                LOGGER.debug(
                    "%s skipped flow window %d with fewer than two timed packets",
                    path,
                    window_index,
                )


def write_window_features_csv(
    pcap_path: Path,
    output_path: Path,
    config: FeatureExtractionConfig,
) -> int:
    """Extract fixed-window metadata and write a stable CSV without payload data."""

    if not pcap_path.is_file():
        raise ValueError(f"Capture does not exist: {pcap_path}")
    if pcap_path.suffix.casefold() not in {".pcap", ".pcapng"}:
        raise ValueError("Capture must use a .pcap or .pcapng extension")
    config.validate()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    written = 0
    try:
        with temporary_path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            for features in extract_window_features(pcap_path, pcap_path.name, config):
                writer.writerow({name: features.get(name) for name in CSV_FIELDNAMES})
                written += 1
        temporary_path.replace(output_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    LOGGER.info("Wrote %d flow windows to %s", written, output_path)
    return written


def parse_args() -> argparse.Namespace:
    """Parse the metadata-only feature-extraction CLI arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--window-seconds", type=float, default=DEFAULT_WINDOW_DURATION_SECONDS)
    parser.add_argument("--burst-gap-seconds", type=float, default=DEFAULT_BURST_GAP_SECONDS)
    parser.add_argument("--idle-gap-seconds", type=float, default=DEFAULT_IDLE_GAP_SECONDS)
    return parser.parse_args()


def main() -> None:
    """Write metadata-only fixed-window features for one PCAP or PCAPNG file."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args()
    try:
        write_window_features_csv(
            args.pcap,
            args.output,
            FeatureExtractionConfig(
                window_duration_seconds=args.window_seconds,
                burst_gap_seconds=args.burst_gap_seconds,
                idle_gap_seconds=args.idle_gap_seconds,
            ),
        )
    except (OSError, ValueError) as error:
        LOGGER.error("Feature extraction failed: %s", error)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()

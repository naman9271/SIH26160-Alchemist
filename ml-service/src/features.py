"""Flow-level metadata extraction for PCAP and PCAPNG captures.

No payload decryption is attempted. Endpoint addresses and ports are used only
to group packets and are never returned as model features.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import statistics
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Hashable

import dpkt

LOGGER = logging.getLogger(__name__)


@dataclass
class _FlowAccumulator:
    initiator: tuple[str, int]
    timestamps: list[float] = field(default_factory=list)
    packet_sizes: list[int] = field(default_factory=list)
    upload_sizes: list[int] = field(default_factory=list)
    download_sizes: list[int] = field(default_factory=list)

    def add(self, timestamp: float, packet_size: int, source: tuple[str, int]) -> None:
        self.timestamps.append(timestamp)
        self.packet_sizes.append(packet_size)
        if source == self.initiator:
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


def _finalize_flow(capture_id: str, key: Hashable, flow: _FlowAccumulator) -> dict[str, object] | None:
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
        "upload_download_ratio": upload_bytes / download_bytes if download_bytes else None,
        # These need an agreed burst/idle threshold and remain unavailable until
        # that threshold is supplied through configuration.
        "burst_count": None,
        "mean_burst_size": None,
        "idle_time_ratio": None,
    }


def extract_flow_features(path: Path, capture_id: str) -> Iterator[dict[str, object]]:
    """Yield bidirectional flow metadata from one PCAP or PCAPNG capture."""

    flows: dict[Hashable, _FlowAccumulator] = {}
    malformed_frames = 0
    with path.open("rb") as file:
        reader = _capture_reader(file, path)
        for timestamp, frame in reader:
            ip_packet = _network_packet(frame)
            if ip_packet is None:
                malformed_frames += 1
                continue
            key, source, _ = _flow_key(ip_packet)
            flow = flows.setdefault(key, _FlowAccumulator(initiator=source))
            flow.add(float(timestamp), len(frame), source)

    if malformed_frames:
        LOGGER.info("%s ignored %d non-IP or malformed frames", path, malformed_frames)
    for key, flow in flows.items():
        features = _finalize_flow(capture_id, key, flow)
        if features is not None:
            yield features
        else:
            LOGGER.debug("%s skipped a flow with fewer than two timed packets", path)

"""Core data model for WireNose packet capture and analysis."""

from __future__ import annotations

import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.packet import Packet
from scapy.plist import PacketList


@dataclass
class CaptureMetadata:
    """Metadata about a capture session or pcap read."""

    interface: str | None
    bpf_filter: str | None
    start_time: datetime
    end_time: datetime | None = None
    packet_count: int = 0
    pcap_path: Path | None = None


@dataclass
class PacketStats:
    """Thread-safe accumulator for packet statistics.

    The internal lock protects all mutations in `update()` so that a TUI
    reader thread can safely call `to_dict()` / `top_*` while the capture
    thread writes.
    """

    protocol_counts: Counter = field(default_factory=Counter)
    src_ips: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)
    total_bytes: int = 0
    packet_count: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, packet: Packet) -> None:
        """Process a single Scapy packet and accumulate stats.

        Extracts protocol layers, source/dest IPs, and byte count.
        All mutations are protected by the internal lock.
        """
        # Determine protocols present in packet layers
        protocols: list[str] = []
        src_ip: str | None = None
        dst_ip: str | None = None

        # Walk the layer stack to identify protocols
        # Import layer classes locally so models.py only needs the base Packet import at module level
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP

        if packet.haslayer(ARP):
            protocols.append("ARP")
        if packet.haslayer(IP):
            protocols.append("IP")
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        if packet.haslayer(IPv6):
            protocols.append("IPv6")
            ipv6_layer = packet[IPv6]
            if src_ip is None:
                src_ip = ipv6_layer.src
            if dst_ip is None:
                dst_ip = ipv6_layer.dst
        if packet.haslayer(TCP):
            protocols.append("TCP")
        if packet.haslayer(UDP):
            protocols.append("UDP")
        if packet.haslayer(ICMP):
            protocols.append("ICMP")

        # Fall back to a generic label if no recognized protocol matched
        if not protocols:
            protocols.append("Other")

        byte_count = len(packet)

        with self._lock:
            for proto in protocols:
                self.protocol_counts[proto] += 1
            if src_ip is not None:
                self.src_ips[src_ip] += 1
            if dst_ip is not None:
                self.dst_ips[dst_ip] += 1
            self.total_bytes += byte_count
            self.packet_count += 1

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable snapshot of the current stats."""
        with self._lock:
            return {
                "protocol_counts": dict(self.protocol_counts),
                "src_ips": dict(self.src_ips),
                "dst_ips": dict(self.dst_ips),
                "total_bytes": self.total_bytes,
                "packet_count": self.packet_count,
            }

    def top_src_ips(self, n: int = 10) -> list[tuple[str, int]]:
        """Return the top-N source IPs by packet count."""
        with self._lock:
            return self.src_ips.most_common(n)

    def top_dst_ips(self, n: int = 10) -> list[tuple[str, int]]:
        """Return the top-N destination IPs by packet count."""
        with self._lock:
            return self.dst_ips.most_common(n)


@dataclass
class CaptureResult:
    """Container for a complete capture or analysis result."""

    packets: PacketList | None
    stats: PacketStats
    metadata: CaptureMetadata

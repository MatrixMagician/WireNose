"""Tests for wirenose.models — data model and thread-safe stats accumulation."""

from __future__ import annotations

import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.plist import PacketList

from wirenose.models import CaptureMetadata, CaptureResult, PacketStats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tcp_packet(src: str = "10.0.0.1", dst: str = "10.0.0.2") -> Ether:
    """Build a minimal TCP packet."""
    return Ether() / IP(src=src, dst=dst) / TCP(sport=12345, dport=80)


def _udp_packet(src: str = "10.0.0.3", dst: str = "10.0.0.4") -> Ether:
    """Build a minimal UDP packet."""
    return Ether() / IP(src=src, dst=dst) / UDP(sport=5000, dport=53)


def _icmp_packet(src: str = "10.0.0.5", dst: str = "10.0.0.6") -> Ether:
    """Build a minimal ICMP packet."""
    return Ether() / IP(src=src, dst=dst) / ICMP()


def _arp_packet() -> Ether:
    """Build a minimal ARP packet (no IP layer)."""
    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.1")


# ---------------------------------------------------------------------------
# PacketStats.update() — protocol, IP, and byte counting
# ---------------------------------------------------------------------------

class TestPacketStatsUpdate:
    """Verify that update() correctly classifies packets."""

    def test_tcp_packet_counts(self) -> None:
        stats = PacketStats()
        pkt = _tcp_packet()
        stats.update(pkt)

        assert stats.packet_count == 1
        assert stats.protocol_counts["TCP"] == 1
        assert stats.protocol_counts["IP"] == 1
        assert stats.src_ips["10.0.0.1"] == 1
        assert stats.dst_ips["10.0.0.2"] == 1
        assert stats.total_bytes == len(pkt)

    def test_udp_packet_counts(self) -> None:
        stats = PacketStats()
        pkt = _udp_packet()
        stats.update(pkt)

        assert stats.protocol_counts["UDP"] == 1
        assert stats.protocol_counts["IP"] == 1
        assert stats.src_ips["10.0.0.3"] == 1
        assert stats.dst_ips["10.0.0.4"] == 1

    def test_icmp_packet_counts(self) -> None:
        stats = PacketStats()
        pkt = _icmp_packet()
        stats.update(pkt)

        assert stats.protocol_counts["ICMP"] == 1
        assert stats.protocol_counts["IP"] == 1

    def test_arp_packet_has_no_ip(self) -> None:
        stats = PacketStats()
        pkt = _arp_packet()
        stats.update(pkt)

        assert stats.protocol_counts["ARP"] == 1
        assert "IP" not in stats.protocol_counts
        # ARP packets have no IP layer → no src/dst IPs recorded
        assert stats.packet_count == 1
        assert len(stats.src_ips) == 0
        assert len(stats.dst_ips) == 0

    def test_multiple_packets_accumulate(self) -> None:
        stats = PacketStats()
        pkts = [_tcp_packet(), _tcp_packet(), _udp_packet(), _icmp_packet(), _arp_packet()]
        for pkt in pkts:
            stats.update(pkt)

        assert stats.packet_count == 5
        assert stats.protocol_counts["TCP"] == 2
        assert stats.protocol_counts["UDP"] == 1
        assert stats.protocol_counts["ICMP"] == 1
        assert stats.protocol_counts["ARP"] == 1
        assert stats.total_bytes == sum(len(p) for p in pkts)

    def test_byte_count_matches_packet_len(self) -> None:
        stats = PacketStats()
        pkt = _tcp_packet()
        stats.update(pkt)
        assert stats.total_bytes == len(pkt)


# ---------------------------------------------------------------------------
# PacketStats — thread safety
# ---------------------------------------------------------------------------

class TestPacketStatsThreadSafety:
    """Concurrent updates from multiple threads must produce correct totals."""

    def test_concurrent_updates_correct_total(self) -> None:
        stats = PacketStats()
        packets_per_thread = 200
        num_threads = 8
        pkt = _tcp_packet(src="192.168.1.1", dst="192.168.1.2")

        def worker() -> None:
            for _ in range(packets_per_thread):
                stats.update(pkt)

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected_total = packets_per_thread * num_threads
        assert stats.packet_count == expected_total
        assert stats.src_ips["192.168.1.1"] == expected_total
        assert stats.dst_ips["192.168.1.2"] == expected_total
        assert stats.total_bytes == expected_total * len(pkt)


# ---------------------------------------------------------------------------
# PacketStats — to_dict / top-N queries
# ---------------------------------------------------------------------------

class TestPacketStatsQueries:
    """Verify serialization and top-N helpers."""

    def test_to_dict_snapshot(self) -> None:
        stats = PacketStats()
        stats.update(_tcp_packet(src="1.1.1.1", dst="2.2.2.2"))
        stats.update(_udp_packet(src="3.3.3.3", dst="4.4.4.4"))

        d = stats.to_dict()
        assert d["packet_count"] == 2
        assert d["protocol_counts"]["TCP"] == 1
        assert d["protocol_counts"]["UDP"] == 1
        assert "1.1.1.1" in d["src_ips"]
        assert "4.4.4.4" in d["dst_ips"]
        assert d["total_bytes"] > 0

    def test_top_src_ips(self) -> None:
        stats = PacketStats()
        # Create uneven distribution: 3 packets from .1, 1 from .2
        for _ in range(3):
            stats.update(_tcp_packet(src="10.0.0.1", dst="10.0.0.99"))
        stats.update(_tcp_packet(src="10.0.0.2", dst="10.0.0.99"))

        top = stats.top_src_ips(1)
        assert len(top) == 1
        assert top[0] == ("10.0.0.1", 3)

    def test_top_dst_ips(self) -> None:
        stats = PacketStats()
        for _ in range(5):
            stats.update(_tcp_packet(src="10.0.0.1", dst="10.0.0.50"))
        for _ in range(2):
            stats.update(_tcp_packet(src="10.0.0.1", dst="10.0.0.60"))

        top = stats.top_dst_ips(2)
        assert top[0] == ("10.0.0.50", 5)
        assert top[1] == ("10.0.0.60", 2)


# ---------------------------------------------------------------------------
# CaptureMetadata
# ---------------------------------------------------------------------------

class TestCaptureMetadata:
    """Verify CaptureMetadata fields and serialization-readiness."""

    def test_fields_roundtrip(self) -> None:
        now = datetime.now(tz=timezone.utc)
        meta = CaptureMetadata(
            interface="eth0",
            bpf_filter="tcp port 80",
            start_time=now,
            end_time=now,
            packet_count=42,
            pcap_path=Path("/tmp/capture.pcap"),
        )
        assert meta.interface == "eth0"
        assert meta.bpf_filter == "tcp port 80"
        assert meta.start_time == now
        assert meta.end_time == now
        assert meta.packet_count == 42
        assert meta.pcap_path == Path("/tmp/capture.pcap")

    def test_defaults(self) -> None:
        meta = CaptureMetadata(
            interface=None,
            bpf_filter=None,
            start_time=datetime.now(tz=timezone.utc),
        )
        assert meta.end_time is None
        assert meta.packet_count == 0
        assert meta.pcap_path is None


# ---------------------------------------------------------------------------
# CaptureResult
# ---------------------------------------------------------------------------

class TestCaptureResult:
    """Verify CaptureResult composes stats + metadata."""

    def test_compose(self) -> None:
        stats = PacketStats()
        stats.update(_tcp_packet())
        meta = CaptureMetadata(
            interface="lo",
            bpf_filter=None,
            start_time=datetime.now(tz=timezone.utc),
            packet_count=1,
        )
        packets = PacketList([_tcp_packet()])
        result = CaptureResult(packets=packets, stats=stats, metadata=meta)

        assert result.packets is not None
        assert len(result.packets) == 1
        assert result.stats.packet_count == 1
        assert result.metadata.interface == "lo"

    def test_packets_can_be_none(self) -> None:
        """When store=False, packets may be None while stats are populated."""
        stats = PacketStats()
        stats.update(_tcp_packet())
        meta = CaptureMetadata(
            interface="eth0",
            bpf_filter=None,
            start_time=datetime.now(tz=timezone.utc),
            packet_count=1,
        )
        result = CaptureResult(packets=None, stats=stats, metadata=meta)

        assert result.packets is None
        assert result.stats.packet_count == 1

"""Shared pytest fixtures for WireNose tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    """Generate a small pcap file with mixed-protocol packets.

    Returns the path to the temporary pcap file. Covers TCP, UDP, ICMP,
    and ARP protocols with varied source/destination IPs.
    """
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / TCP(sport=12346, dport=443),
        Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=5000, dport=53),
        Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / ICMP(),
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.1"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345),
        Ether() / IP(src="10.0.0.4", dst="10.0.0.3") / UDP(sport=53, dport=5000),
    ]

    pcap_path = tmp_path / "test_sample.pcap"
    wrpcap(str(pcap_path), packets)
    return pcap_path

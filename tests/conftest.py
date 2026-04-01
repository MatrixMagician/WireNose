"""Shared pytest fixtures for WireNose tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
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


@pytest.fixture
def threat_pcap(tmp_path: Path) -> Path:
    """Generate a composite pcap that triggers all 6 threat detectors.

    Returns the path to a temporary pcap file with packets designed to
    exceed default thresholds for every built-in detector.
    """
    packets = []

    # Port scan: 25 unique ports from one source (> threshold 20)
    for port in range(1, 26):
        packets.append(
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=port, flags="S")
        )

    # SYN flood: 110 SYN-only packets (> threshold 100)
    for _ in range(110):
        packets.append(
            Ether() / IP(src="10.0.0.50", dst="10.0.0.2") / TCP(dport=80, flags="S")
        )

    # ARP spoof: one MAC claiming two IPs
    packets.append(
        Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.100")
    )
    packets.append(
        Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.101")
    )

    # DNS tunnel: 25 queries with 40-char labels (> label max 30, > volume 20)
    for i in range(25):
        long_label = f"exfil{'x' * 34}{i:02d}"
        qname = f"{long_label}.evil.com".encode() + b"."
        packets.append(
            Ether()
            / IP(src="10.0.0.10", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype=1))
        )

    # ICMP anomaly: 5 oversized packets (> 800 bytes)
    for _ in range(5):
        packets.append(
            Ether() / IP(src="10.0.0.30", dst="10.0.0.2") / ICMP() / Raw(load=b"\x00" * 1000)
        )

    # Cleartext credentials: FTP USER on port 21
    packets.append(
        Ether()
        / IP(src="10.0.0.40", dst="10.0.0.2")
        / TCP(dport=21)
        / Raw(load=b"USER admin\r\n")
    )

    pcap_path = tmp_path / "threats.pcap"
    wrpcap(str(pcap_path), packets)
    return pcap_path

#!/usr/bin/env python3
"""Generate test fixture pcap files for WireNose tests.

Creates tests/fixtures/sample.pcap with mixed-protocol packets:
TCP, UDP, ICMP, and ARP — varied source/destination IPs.

Run once: uv run python tests/fixtures/generate_fixtures.py
"""

from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap


def generate_sample_pcap(output: Path) -> None:
    """Build and write a diverse set of packets to a pcap file."""
    packets = [
        # TCP packets with varied IPs
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / TCP(sport=12346, dport=443),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345),
        # UDP packets
        Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=5000, dport=53),
        Ether() / IP(src="10.0.0.4", dst="10.0.0.3") / UDP(sport=53, dport=5000),
        # ICMP packets
        Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / ICMP(),
        Ether() / IP(src="10.0.0.6", dst="10.0.0.5") / ICMP(type=0),  # echo reply
        # ARP packets (no IP layer)
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="10.0.0.1"),
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", psrc="10.0.0.1", pdst="10.0.0.7"),
        # Additional TCP for heavier IP counts
        Ether() / IP(src="10.0.0.1", dst="10.0.0.4") / TCP(sport=22, dport=22),
    ]

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)
    print(f"Wrote {len(packets)} packets to {output}")


if __name__ == "__main__":
    fixture_dir = Path(__file__).parent
    generate_sample_pcap(fixture_dir / "sample.pcap")

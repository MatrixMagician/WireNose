#!/usr/bin/env python3
"""Generate test fixture pcap files for WireNose tests.

Creates:
- tests/fixtures/sample.pcap — mixed-protocol packets (TCP, UDP, ICMP, ARP)
- tests/fixtures/threats.pcap — composite pcap triggering all 6 threat detectors

Run once: uv run python tests/fixtures/generate_fixtures.py
"""

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
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


def generate_threat_pcap(output: Path) -> None:
    """Build a composite pcap that triggers all 6 threat detectors.

    Detector thresholds (all use strict > comparison):
    - Port scan: 20 unique (dst_ip, dport) pairs from one source → need 21+
    - SYN flood: 100 SYN-without-ACK from one source → need 101+
    - ARP spoof: one MAC claiming multiple IPs in ARP replies
    - DNS tunnel: label > 30 chars, query volume > 20 to same base domain
    - ICMP anomaly: packet > 800 bytes
    - Cleartext creds: FTP USER/PASS on port 21
    """
    packets = []

    # 1. Port scan: 25 TCP SYN packets to unique ports (> threshold 20)
    for port in range(1, 26):
        packets.append(
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=port, flags="S")
        )

    # 2. SYN flood: 110 SYN-only packets to one destination (> threshold 100)
    for _ in range(110):
        packets.append(
            Ether() / IP(src="10.0.0.50", dst="10.0.0.2") / TCP(dport=80, flags="S")
        )

    # 3. ARP spoof: one MAC claiming two different IPs
    packets.append(
        Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.100")
    )
    packets.append(
        Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.101")
    )

    # 4. DNS tunnel: 25 queries with 40-char random labels (> label max 30, > volume 20)
    for i in range(25):
        long_label = f"exfil{'x' * 34}{i:02d}"  # 40+ chars
        qname = f"{long_label}.evil.com".encode() + b"."
        packets.append(
            Ether()
            / IP(src="10.0.0.10", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype=1))
        )

    # 5. ICMP anomaly: 5 oversized ICMP packets (> 800 bytes)
    for _ in range(5):
        packets.append(
            Ether() / IP(src="10.0.0.30", dst="10.0.0.2") / ICMP() / Raw(load=b"\x00" * 1000)
        )

    # 6. Cleartext credentials: FTP USER command on port 21
    packets.append(
        Ether()
        / IP(src="10.0.0.40", dst="10.0.0.2")
        / TCP(dport=21)
        / Raw(load=b"USER admin\r\n")
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)
    print(f"Wrote {len(packets)} packets to {output}")


if __name__ == "__main__":
    fixture_dir = Path(__file__).parent
    generate_sample_pcap(fixture_dir / "sample.pcap")
    generate_threat_pcap(fixture_dir / "threats.pcap")

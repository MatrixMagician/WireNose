"""ICMP anomaly detector — flags oversized packets and ICMP floods."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from scapy.plist import PacketList

from wirenose.detectors.models import ThreatFinding


def detect_icmp_anomaly(
    packets: PacketList, config: dict[str, Any] | None = None,
) -> list[ThreatFinding]:
    """Detect ICMP anomalies in *packets*.

    Two checks:

    1. **Oversized ICMP** — total packet length exceeding
       *icmp_size_threshold* (default 800) bytes may indicate data
       exfiltration or ICMP tunneling.
    2. **ICMP flood** — a single source sending more than
       *icmp_flood_threshold* (default 50) ICMP packets may be running
       a denial-of-service or reconnaissance sweep.

    Args:
        packets: Scapy PacketList to analyse.
        config: Optional detection configuration dict.

    Returns:
        List of :class:`ThreatFinding` for each detected anomaly.
    """
    if config is None:
        config = {}

    size_threshold: int = config.get("icmp_size_threshold", 800)
    flood_threshold: int = config.get("icmp_flood_threshold", 50)

    # Import layers locally (K002)
    from scapy.layers.inet import ICMP, IP

    # Track ICMP count per source IP
    src_counts: dict[str, list[int]] = defaultdict(list)

    findings: list[ThreatFinding] = []

    for idx, pkt in enumerate(packets):
        if not pkt.haslayer(ICMP):
            continue

        pkt_len = len(pkt)
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"

        src_counts[src_ip].append(idx)

        # Oversized ICMP check
        if pkt_len > size_threshold:
            findings.append(
                ThreatFinding(
                    detector="icmp_anomaly",
                    severity="medium",
                    title="ICMP Anomaly — Oversized Packet",
                    description=(
                        f"ICMP packet from {src_ip} is {pkt_len} bytes "
                        f"(threshold: {size_threshold}), possible ICMP "
                        f"tunneling or data exfiltration"
                    ),
                    source_ip=src_ip,
                    packet_indices=[idx],
                ),
            )

    # ICMP flood check per source
    for src_ip, pkt_indices in src_counts.items():
        if len(pkt_indices) > flood_threshold:
            findings.append(
                ThreatFinding(
                    detector="icmp_anomaly",
                    severity="high",
                    title="ICMP Anomaly — Flood Detected",
                    description=(
                        f"Host {src_ip} sent {len(pkt_indices)} ICMP "
                        f"packets (threshold: {flood_threshold}), "
                        f"possible DoS or reconnaissance"
                    ),
                    source_ip=src_ip,
                    packet_indices=pkt_indices,
                ),
            )

    return findings

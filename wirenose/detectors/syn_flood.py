"""SYN flood detector — flags hosts sending excessive SYN-without-ACK packets."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from scapy.plist import PacketList

from wirenose.detectors.models import ThreatFinding


def detect_syn_flood(
    packets: PacketList, config: dict[str, Any] | None = None,
) -> list[ThreatFinding]:
    """Detect SYN flood activity in *packets*.

    Counts TCP packets with SYN set and ACK not set per source IP.
    Sources exceeding *syn_flood_threshold* are flagged.

    Args:
        packets: Scapy PacketList to analyse.
        config: Optional detection configuration dict.

    Returns:
        List of :class:`ThreatFinding` for each offending source IP.
    """
    if config is None:
        config = {}

    threshold: int = config.get("syn_flood_threshold", 100)

    syn_counts: dict[str, int] = defaultdict(int)
    indices: dict[str, list[int]] = defaultdict(list)

    from scapy.layers.inet import IP, TCP

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            # SYN set (bit 1) and ACK not set (bit 4) — use bitwise ops (FlagValue)
            if (flags & 0x02) and not (flags & 0x10):
                src = pkt[IP].src
                syn_counts[src] += 1
                indices[src].append(idx)

    findings: list[ThreatFinding] = []
    for src_ip, count in syn_counts.items():
        if count > threshold:
            findings.append(
                ThreatFinding(
                    detector="syn_flood",
                    severity="critical",
                    title="SYN Flood Detected",
                    description=(
                        f"Host {src_ip} sent {count} SYN-without-ACK packets "
                        f"(threshold: {threshold})"
                    ),
                    source_ip=src_ip,
                    packet_indices=indices[src_ip],
                ),
            )

    return findings

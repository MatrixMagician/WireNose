"""Port scan detector — flags hosts probing many destination ports."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from scapy.plist import PacketList

from wirenose.detectors.models import ThreatFinding


def detect_port_scan(
    packets: PacketList, config: dict[str, Any] | None = None,
) -> list[ThreatFinding]:
    """Detect port-scan activity in *packets*.

    A source IP touching more than *port_scan_threshold* unique
    (dst_ip, dport) pairs is flagged.

    Args:
        packets: Scapy PacketList to analyse.
        config: Optional detection configuration dict.

    Returns:
        List of :class:`ThreatFinding` for each offending source IP.
    """
    if config is None:
        config = {}

    threshold: int = config.get("port_scan_threshold", 20)

    # src_ip → set of (dst_ip, dport), and src_ip → list of packet indices
    connections: dict[str, set[tuple[str, int]]] = defaultdict(set)
    indices: dict[str, list[int]] = defaultdict(list)

    # Import layers locally (K002 — avoid module-level Scapy layer imports)
    from scapy.layers.inet import IP, TCP

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            src = ip_layer.src
            dst = ip_layer.dst
            dport = tcp_layer.dport
            connections[src].add((dst, dport))
            indices[src].append(idx)

    findings: list[ThreatFinding] = []
    for src_ip, targets in connections.items():
        if len(targets) > threshold:
            findings.append(
                ThreatFinding(
                    detector="port_scan",
                    severity="high",
                    title="Port Scan Detected",
                    description=(
                        f"Host {src_ip} probed {len(targets)} unique "
                        f"destination ports (threshold: {threshold})"
                    ),
                    source_ip=src_ip,
                    packet_indices=indices[src_ip],
                ),
            )

    return findings

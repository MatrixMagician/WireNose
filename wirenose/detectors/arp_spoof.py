"""ARP spoofing detector — flags MAC↔IP mapping conflicts in ARP replies."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from scapy.plist import PacketList

from wirenose.detectors.models import ThreatFinding


def detect_arp_spoof(
    packets: PacketList, config: dict[str, Any] | None = None,
) -> list[ThreatFinding]:
    """Detect ARP spoofing in *packets*.

    Examines ARP reply packets (op==2) and flags:
    - A single MAC address claiming multiple IP addresses.
    - A single IP address associated with multiple MAC addresses.

    Args:
        packets: Scapy PacketList to analyse.
        config: Optional detection configuration dict (reserved for future use).

    Returns:
        List of :class:`ThreatFinding` for detected conflicts.
    """
    if config is None:
        config = {}

    # ARP has no IP layer — use ARP.psrc / ARP.hwsrc directly
    from scapy.layers.l2 import ARP

    mac_to_ips: dict[str, set[str]] = defaultdict(set)
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    mac_indices: dict[str, list[int]] = defaultdict(list)
    ip_indices: dict[str, list[int]] = defaultdict(list)

    for idx, pkt in enumerate(packets):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            arp = pkt[ARP]
            mac = arp.hwsrc
            ip = arp.psrc
            mac_to_ips[mac].add(ip)
            ip_to_macs[ip].add(mac)
            mac_indices[mac].append(idx)
            ip_indices[ip].append(idx)

    findings: list[ThreatFinding] = []

    # One MAC claiming multiple IPs
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            findings.append(
                ThreatFinding(
                    detector="arp_spoof",
                    severity="critical",
                    title="ARP Spoofing Detected",
                    description=(
                        f"MAC {mac} is claiming multiple IPs: "
                        f"{', '.join(sorted(ips))}"
                    ),
                    metadata={"mac": mac, "claimed_ips": sorted(ips)},
                    packet_indices=mac_indices[mac],
                ),
            )

    # One IP mapped to multiple MACs
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            findings.append(
                ThreatFinding(
                    detector="arp_spoof",
                    severity="critical",
                    title="ARP Spoofing Detected",
                    description=(
                        f"IP {ip} is associated with multiple MACs: "
                        f"{', '.join(sorted(macs))}"
                    ),
                    source_ip=ip,
                    metadata={"ip": ip, "macs": sorted(macs)},
                    packet_indices=ip_indices[ip],
                ),
            )

    return findings

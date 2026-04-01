"""DNS tunneling detector — flags long labels, high query volume, and suspicious record types."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from scapy.plist import PacketList

from wirenose.detectors.models import ThreatFinding


def detect_dns_tunnel(
    packets: PacketList, config: dict[str, Any] | None = None,
) -> list[ThreatFinding]:
    """Detect DNS tunneling indicators in *packets*.

    Checks three signals:

    1. **Long subdomain labels** — any single DNS label longer than
       *dns_label_max_length* (default 30) characters suggests data
       exfiltration encoded in the subdomain.
    2. **High query volume** — more than *dns_query_threshold* (default 20)
       queries to the same base domain may indicate C2 beaconing.
    3. **Suspicious record types** — TXT (16) and NULL (10) queries to the
       same domain are common tunneling vectors.

    Args:
        packets: Scapy PacketList to analyse.
        config: Optional detection configuration dict.

    Returns:
        List of :class:`ThreatFinding` for each detected anomaly.
    """
    if config is None:
        config = {}

    label_max: int = config.get("dns_label_max_length", 30)
    query_threshold: int = config.get("dns_query_threshold", 20)

    # Import layers locally (K002)
    from scapy.layers.dns import DNS, DNSQR

    # Track: base_domain → list of packet indices
    domain_queries: dict[str, list[int]] = defaultdict(list)
    # Track: base_domain → set of query types seen
    domain_qtypes: dict[str, set[int]] = defaultdict(set)

    findings: list[ThreatFinding] = []

    # Domains already flagged for long labels (avoid duplicate findings)
    flagged_long_label: set[str] = set()

    for idx, pkt in enumerate(packets):
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            continue

        try:
            raw_qname = pkt[DNSQR].qname
            if isinstance(raw_qname, bytes):
                qname = raw_qname.decode("utf-8", errors="ignore")
            else:
                qname = str(raw_qname)
            qname = qname.rstrip(".")
        except Exception:
            continue

        if not qname:
            continue

        labels = qname.split(".")

        # Extract base domain (last 2 labels) for volume/qtype tracking
        base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname

        domain_queries[base_domain].append(idx)

        qtype = pkt[DNSQR].qtype
        if isinstance(qtype, int):
            domain_qtypes[base_domain].add(qtype)

        # Check for long subdomain labels
        for label in labels:
            if len(label) > label_max and qname not in flagged_long_label:
                flagged_long_label.add(qname)
                findings.append(
                    ThreatFinding(
                        detector="dns_tunnel",
                        severity="high",
                        title="DNS Tunneling — Long Subdomain Label",
                        description=(
                            f"DNS query for '{qname}' contains a label "
                            f"of {len(label)} chars (max: {label_max}), "
                            f"suggesting data exfiltration via DNS"
                        ),
                        packet_indices=[idx],
                    ),
                )
                break

    # Check query volume per base domain
    for domain, pkt_indices in domain_queries.items():
        if len(pkt_indices) > query_threshold:
            findings.append(
                ThreatFinding(
                    detector="dns_tunnel",
                    severity="medium",
                    title="DNS Tunneling — High Query Volume",
                    description=(
                        f"Domain '{domain}' received {len(pkt_indices)} "
                        f"queries (threshold: {query_threshold}), "
                        f"possible C2 beaconing"
                    ),
                    packet_indices=pkt_indices,
                ),
            )

    # Check suspicious record types (TXT=16, NULL=10)
    suspicious_qtypes = {16, 10}
    for domain, qtypes in domain_qtypes.items():
        hits = qtypes & suspicious_qtypes
        if hits:
            type_names = []
            if 16 in hits:
                type_names.append("TXT")
            if 10 in hits:
                type_names.append("NULL")
            findings.append(
                ThreatFinding(
                    detector="dns_tunnel",
                    severity="medium",
                    title="DNS Tunneling — Suspicious Record Types",
                    description=(
                        f"Domain '{domain}' queried with suspicious "
                        f"record types: {', '.join(type_names)}"
                    ),
                    packet_indices=domain_queries[domain],
                ),
            )

    return findings

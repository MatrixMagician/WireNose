"""Cleartext credentials detector — flags unencrypted authentication in common protocols."""

from __future__ import annotations

import re
from typing import Any

from scapy.plist import PacketList

from wirenose.detectors.models import ThreatFinding

# Ports where cleartext credential exchange is expected.
_CLEARTEXT_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    587: "SMTP",
}

# Patterns that indicate credential exchange on specific protocols.
# Each tuple: (compiled regex, service name, severity).
_CREDENTIAL_PATTERNS: list[tuple[re.Pattern[bytes], str, str]] = [
    (re.compile(rb"(?i)^USER\s+\S+", re.MULTILINE), "FTP/POP3", "critical"),
    (re.compile(rb"(?i)^PASS\s+\S+", re.MULTILINE), "FTP/POP3", "critical"),
    (re.compile(rb"(?i)AUTH\s+(LOGIN|PLAIN)", re.MULTILINE), "SMTP", "critical"),
]

# Matches HTTP Basic Auth header in raw bytes (any port).
_HTTP_BASIC_RE = re.compile(rb"(?i)Authorization:\s*Basic\s+(\S+)")


def _truncate(value: str, max_len: int = 20) -> str:
    """Truncate *value* to *max_len* chars, appending '…' if trimmed."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "…"


def detect_cleartext_creds(
    packets: PacketList, config: dict[str, Any] | None = None,
) -> list[ThreatFinding]:
    """Detect cleartext credential exchange in *packets*.

    Inspects:

    * **HTTP Basic Auth** — ``Authorization: Basic`` in HTTPRequest layer
      or as raw bytes on any port.
    * **FTP** (port 21) — ``USER`` / ``PASS`` commands.
    * **POP3** (port 110) — ``USER`` / ``PASS`` commands.
    * **SMTP** (ports 25, 587) — ``AUTH LOGIN`` / ``AUTH PLAIN``.
    * **Telnet** (port 23) — any raw payload on the Telnet port is
      treated as potentially credential-bearing.

    Credential values are truncated to 20 characters in finding
    descriptions.

    Args:
        packets: Scapy PacketList to analyse.
        config: Optional detection configuration dict.

    Returns:
        List of :class:`ThreatFinding` for each detected cleartext exchange.
    """
    if config is None:
        config = {}

    # Import layers locally (K002)
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    findings: list[ThreatFinding] = []

    for idx, pkt in enumerate(packets):
        if not pkt.haslayer(TCP):
            continue

        dport = pkt[TCP].dport
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"

        # --- HTTP Basic Auth via HTTPRequest layer ---
        try:
            from scapy.layers.http import HTTPRequest

            if pkt.haslayer(HTTPRequest):
                auth = getattr(pkt[HTTPRequest], "Authorization", None)
                if auth and b"Basic" in (auth if isinstance(auth, bytes) else auth.encode()):
                    auth_str = auth.decode("utf-8", errors="ignore") if isinstance(auth, bytes) else str(auth)
                    findings.append(
                        ThreatFinding(
                            detector="cleartext_creds",
                            severity="critical",
                            title="Cleartext Credentials — HTTP Basic Auth",
                            description=(
                                f"HTTP Basic Auth from {src_ip} → {dst_ip}:{dport}, "
                                f"credentials: {_truncate(auth_str)}"
                            ),
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            packet_indices=[idx],
                        ),
                    )
                    continue
        except ImportError:
            pass  # HTTPRequest layer not available — fall through to raw check

        # --- Raw payload analysis ---
        if not pkt.haslayer(Raw):
            continue

        try:
            payload = bytes(pkt[Raw].load)
        except Exception:
            continue

        if not payload:
            continue

        # HTTP Basic Auth in raw bytes (any port)
        basic_match = _HTTP_BASIC_RE.search(payload)
        if basic_match:
            cred_val = basic_match.group(1).decode("utf-8", errors="ignore")
            findings.append(
                ThreatFinding(
                    detector="cleartext_creds",
                    severity="critical",
                    title="Cleartext Credentials — HTTP Basic Auth",
                    description=(
                        f"HTTP Basic Auth from {src_ip} → {dst_ip}:{dport}, "
                        f"credentials: {_truncate(cred_val)}"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    packet_indices=[idx],
                ),
            )
            continue

        # Protocol-specific credential patterns on known ports
        service = _CLEARTEXT_PORTS.get(dport)
        if service:
            if service == "Telnet":
                # Any raw payload on Telnet port is potentially credential-bearing
                payload_preview = payload.decode("utf-8", errors="ignore").strip()
                if payload_preview:
                    findings.append(
                        ThreatFinding(
                            detector="cleartext_creds",
                            severity="critical",
                            title="Cleartext Credentials — Telnet",
                            description=(
                                f"Telnet traffic from {src_ip} → {dst_ip}:{dport}, "
                                f"payload: {_truncate(payload_preview)}"
                            ),
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            packet_indices=[idx],
                        ),
                    )
                continue

            # FTP, POP3, SMTP pattern matching
            for pattern, proto_name, severity in _CREDENTIAL_PATTERNS:
                match = pattern.search(payload)
                if match:
                    matched_text = match.group(0).decode("utf-8", errors="ignore").strip()
                    findings.append(
                        ThreatFinding(
                            detector="cleartext_creds",
                            severity=severity,
                            title=f"Cleartext Credentials — {service}",
                            description=(
                                f"{service} credential exchange from {src_ip} → "
                                f"{dst_ip}:{dport}, matched: {_truncate(matched_text)}"
                            ),
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            packet_indices=[idx],
                        ),
                    )
                    break  # One finding per packet is enough

    return findings

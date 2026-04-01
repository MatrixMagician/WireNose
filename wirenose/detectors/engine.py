"""Threat detection engine — runs registered detectors against a PacketList."""

from __future__ import annotations

import logging
from typing import Any, Callable

from scapy.plist import PacketList

from wirenose.detectors.models import SEVERITY_ORDER, ThreatFinding

logger = logging.getLogger(__name__)

# Type alias for a detector function.
DetectorFunc = Callable[[PacketList, dict[str, Any]], list[ThreatFinding]]


class ThreatEngine:
    """Orchestrates threat detection across registered detector functions.

    Each detector is called with ``(packets, config)`` and returns a list
    of :class:`ThreatFinding`.  Per-detector exceptions are logged and
    swallowed so one failing detector never blocks the rest.
    """

    def __init__(self) -> None:
        self._detectors: list[DetectorFunc] = []
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register the built-in detector functions."""
        from wirenose.detectors.arp_spoof import detect_arp_spoof
        from wirenose.detectors.port_scan import detect_port_scan
        from wirenose.detectors.syn_flood import detect_syn_flood

        self._detectors.extend([
            detect_port_scan,
            detect_syn_flood,
            detect_arp_spoof,
        ])

    def register(self, detector: DetectorFunc) -> None:
        """Add a custom detector function."""
        self._detectors.append(detector)

    def analyze(
        self,
        packets: PacketList,
        config: dict[str, Any] | None = None,
    ) -> list[ThreatFinding]:
        """Run all registered detectors and return sorted findings.

        Args:
            packets: Scapy PacketList to analyse.
            config: Optional detection configuration dict passed to each
                    detector.

        Returns:
            Findings sorted by severity (most critical first), then title.
        """
        if config is None:
            config = {}

        findings: list[ThreatFinding] = []

        for detector in self._detectors:
            name = getattr(detector, "__name__", repr(detector))
            try:
                results = detector(packets, config)
                findings.extend(results)
            except Exception:
                logger.warning(
                    "Detector %s raised an exception — skipping",
                    name,
                    exc_info=True,
                )

        # Sort: severity (critical first), then title alphabetically
        findings.sort(
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 999), f.title),
        )

        return findings

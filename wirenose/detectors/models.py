"""Threat finding data model — universal output contract for all detectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Severity ordering for sorting findings (most critical first).
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class ThreatFinding:
    """A single threat detected during analysis.

    Every detector emits a list of these.  ``ThreatEngine`` collects and
    sorts them by severity then title for deterministic output.
    """

    detector: str
    severity: str
    title: str
    description: str
    source_ip: str | None = None
    dest_ip: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime | None = None
    packet_indices: list[int] = field(default_factory=list)

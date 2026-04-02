"""JSON export and pcap copy utilities for WireNose report generation."""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from wirenose import __version__
from wirenose.detectors.models import SEVERITY_ORDER, ThreatFinding
from wirenose.models import CaptureResult


def _json_default(obj: Any) -> Any:
    """Custom JSON serializer for types that json.dumps cannot handle natively.

    Handles:
    - datetime → ISO-8601 string
    - Path → string
    - Scapy EDecimal (or any Decimal-like) → float
    - Sets → sorted list
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    # Scapy EDecimal inherits from Decimal — catch any Decimal-like via duck typing
    try:
        return float(obj)
    except (TypeError, ValueError):
        pass
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def export_json(
    result: CaptureResult,
    findings: list[ThreatFinding],
    output_dir: Path,
) -> Path:
    """Serialize capture results and threat findings to a structured JSON file.

    The output follows the WireNose report JSON schema:

    .. code-block:: json

        {
            "wirenose_version": "0.1.0",
            "generated_at": "ISO-8601",
            "capture": { ... },
            "stats": { ... },
            "findings": [ ... ],
            "finding_summary": { "total": N, "by_severity": { ... } }
        }

    Args:
        result: Capture result with packets, stats, and metadata.
        findings: Sorted list of threat findings from detection.
        output_dir: Directory to write ``report.json`` into (created if needed).

    Returns:
        Path to the written JSON file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    meta = result.metadata
    stats = result.stats

    # Build severity counts — initialize all known severity levels to 0
    by_severity: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        key = f.severity.lower()
        by_severity[key] = by_severity.get(key, 0) + 1

    report_data: dict[str, Any] = {
        "wirenose_version": __version__,
        "generated_at": datetime.now().isoformat(),
        "capture": {
            "source": str(meta.pcap_path) if meta.pcap_path else None,
            "interface": meta.interface,
            "bpf_filter": meta.bpf_filter,
            "start_time": meta.start_time.isoformat() if meta.start_time else None,
            "end_time": meta.end_time.isoformat() if meta.end_time else None,
            "packet_count": meta.packet_count,
            "total_bytes": stats.total_bytes,
        },
        "stats": {
            "protocol_counts": dict(stats.protocol_counts),
            "top_src_ips": stats.top_src_ips(10),
            "top_dst_ips": stats.top_dst_ips(10),
        },
        "findings": [
            {
                "detector": f.detector,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "source_ip": f.source_ip,
                "dest_ip": f.dest_ip,
                "metadata": f.metadata,
                "timestamp": f.timestamp,
                "packet_indices": f.packet_indices,
            }
            for f in findings
        ],
        "finding_summary": {
            "total": len(findings),
            "by_severity": by_severity,
        },
    }

    json_path = output_dir / "report.json"
    json_path.write_text(
        json.dumps(report_data, indent=2, default=_json_default),
        encoding="utf-8",
    )
    return json_path


def copy_pcap(source: Path | None, output_dir: Path) -> Path | None:
    """Copy source pcap file into the output directory.

    Args:
        source: Path to the original pcap file, or ``None`` (e.g. live capture
                without a saved pcap).
        output_dir: Destination directory (created if needed).

    Returns:
        Path to the copied file, or ``None`` if *source* was ``None`` or did
        not exist on disk.
    """
    if source is None:
        return None

    if not source.exists():
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / source.name
    shutil.copy2(source, dest)
    return dest

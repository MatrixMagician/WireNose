"""Chart generation and HTML report assembly for WireNose analysis results."""

from __future__ import annotations

import base64
import io
from datetime import datetime
from pathlib import Path
from string import Template
from typing import TYPE_CHECKING

# Agg backend MUST be set before any pyplot import anywhere in the process.
import matplotlib
matplotlib.use("Agg")

if TYPE_CHECKING:
    from scapy.plist import PacketList

    from wirenose.detectors.models import ThreatFinding
    from wirenose.models import CaptureMetadata, CaptureResult, PacketStats


# ── Chart helpers ────────────────────────────────────────────────────


def _fig_to_base64(fig: matplotlib.figure.Figure) -> str:
    """Render a matplotlib figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=100)
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("ascii")
    buf.close()
    return encoded


def _chart_protocol_distribution(protocol_counts: dict[str, int]) -> str:
    """Bar chart of protocol packet counts.

    Returns base64-encoded PNG, or empty string if *protocol_counts* is empty.
    """
    if not protocol_counts:
        return ""

    import matplotlib.pyplot as plt

    sorted_items = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)
    names = [name for name, _ in sorted_items]
    counts = [count for _, count in sorted_items]

    fig, ax = plt.subplots(figsize=(6, max(3, len(names) * 0.4)))
    bars = ax.barh(names, counts, color="#4a90d9")
    ax.set_xlabel("Packet Count")
    ax.set_title("Protocol Distribution")
    ax.invert_yaxis()

    # Add count labels on bars
    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + max(counts) * 0.01, bar.get_y() + bar.get_height() / 2,
                str(count), va="center", fontsize=9)

    fig.tight_layout()
    result = _fig_to_base64(fig)
    plt.close(fig)
    return result


def _chart_traffic_volume(packets: PacketList | None) -> str:
    """Line chart of packet count over time.

    Returns base64-encoded PNG, or empty string if *packets* is None/empty.
    """
    if packets is None or len(packets) == 0:
        return ""

    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates

    timestamps = [float(pkt.time) for pkt in packets]
    if not timestamps:
        return ""

    t_min = min(timestamps)
    t_max = max(timestamps)
    span = t_max - t_min

    # Degenerate case: all packets at the same timestamp
    if span < 0.001:
        fig, ax = plt.subplots(figsize=(8, 3))
        dt = datetime.fromtimestamp(t_min)
        ax.bar([dt.strftime("%H:%M:%S")], [len(timestamps)], color="#4a90d9")
        ax.set_ylabel("Packets")
        ax.set_title("Traffic Volume (all packets at same time)")
        fig.tight_layout()
        result = _fig_to_base64(fig)
        plt.close(fig)
        return result

    # Determine bin count: aim for 20-50 bins, minimum 5
    n_bins = max(5, min(50, len(timestamps) // 5))

    fig, ax = plt.subplots(figsize=(8, 3))
    ax.hist(timestamps, bins=n_bins, color="#4a90d9", edgecolor="#2c5f8a", alpha=0.8)
    ax.set_xlabel("Time (epoch seconds)")
    ax.set_ylabel("Packets")
    ax.set_title("Traffic Volume Over Time")
    fig.tight_layout()
    result = _fig_to_base64(fig)
    plt.close(fig)
    return result


def _chart_top_talkers(
    top_src: list[tuple[str, int]],
    top_dst: list[tuple[str, int]],
) -> str:
    """Horizontal bar chart of top source and destination IPs.

    Returns base64-encoded PNG, or empty string if both lists are empty.
    """
    if not top_src and not top_dst:
        return ""

    import matplotlib.pyplot as plt
    import numpy as np

    # Merge all IPs and align data
    all_ips: list[str] = []
    src_map = dict(top_src)
    dst_map = dict(top_dst)

    seen: set[str] = set()
    for ip, _ in top_src:
        if ip not in seen:
            all_ips.append(ip)
            seen.add(ip)
    for ip, _ in top_dst:
        if ip not in seen:
            all_ips.append(ip)
            seen.add(ip)

    # Limit to top 10 by combined count
    all_ips.sort(key=lambda ip: src_map.get(ip, 0) + dst_map.get(ip, 0), reverse=True)
    all_ips = all_ips[:10]

    src_counts = [src_map.get(ip, 0) for ip in all_ips]
    dst_counts = [dst_map.get(ip, 0) for ip in all_ips]

    y_pos = np.arange(len(all_ips))
    height = 0.35

    fig, ax = plt.subplots(figsize=(7, max(3, len(all_ips) * 0.5)))
    ax.barh(y_pos - height / 2, src_counts, height, label="Source", color="#4a90d9")
    ax.barh(y_pos + height / 2, dst_counts, height, label="Destination", color="#e8724a")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(all_ips)
    ax.set_xlabel("Packet Count")
    ax.set_title("Top Talkers (Source & Destination)")
    ax.legend()
    ax.invert_yaxis()
    fig.tight_layout()
    result = _fig_to_base64(fig)
    plt.close(fig)
    return result


def _chart_alert_timeline(
    findings: list[ThreatFinding],
    packets: PacketList | None,
) -> str:
    """Scatter chart plotting findings by time and severity.

    Uses ``finding.timestamp`` if available, otherwise maps
    ``packet_indices`` to packet timestamps.  Returns empty string if
    *findings* is empty.
    """
    if not findings:
        return ""

    import matplotlib.pyplot as plt

    severity_y = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    severity_colors = {
        "critical": "#d32f2f",
        "high": "#e64a19",
        "medium": "#fbc02d",
        "low": "#1976d2",
        "info": "#757575",
    }

    xs: list[float] = []
    ys: list[int] = []
    colors: list[str] = []
    labels: list[str] = []

    for finding in findings:
        t: float | None = None
        if finding.timestamp is not None:
            t = finding.timestamp.timestamp()
        elif finding.packet_indices and packets is not None and len(packets) > 0:
            idx = finding.packet_indices[0]
            if 0 <= idx < len(packets):
                t = float(packets[idx].time)

        if t is None:
            continue

        xs.append(t)
        ys.append(severity_y.get(finding.severity.lower(), 0))
        colors.append(severity_colors.get(finding.severity.lower(), "#757575"))
        labels.append(finding.title)

    if not xs:
        # All findings lacked timestamps — produce placeholder
        fig, ax = plt.subplots(figsize=(8, 3))
        ax.text(0.5, 0.5, "No timestamp data available", ha="center", va="center",
                transform=ax.transAxes, fontsize=12, color="#999")
        ax.set_title("Alert Timeline")
        fig.tight_layout()
        result = _fig_to_base64(fig)
        plt.close(fig)
        return result

    fig, ax = plt.subplots(figsize=(8, 3))
    ax.scatter(xs, ys, c=colors, s=100, edgecolors="black", linewidth=0.5, zorder=5)
    ax.set_yticks(list(severity_y.values()))
    ax.set_yticklabels(list(severity_y.keys()))
    ax.set_xlabel("Time (epoch seconds)")
    ax.set_title("Alert Timeline")
    fig.tight_layout()
    result = _fig_to_base64(fig)
    plt.close(fig)
    return result


# ── HTML Template ────────────────────────────────────────────────────

_HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WireNose Analysis Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #f5f5f5; color: #333; line-height: 1.6; padding: 2rem; }
  .container { max-width: 960px; margin: 0 auto; }
  header { background: linear-gradient(135deg, #1a237e, #283593); color: #fff;
           padding: 1.5rem 2rem; border-radius: 8px 8px 0 0; }
  header h1 { font-size: 1.8rem; }
  header .subtitle { opacity: 0.8; font-size: 0.9rem; margin-top: 0.3rem; }
  section { background: #fff; padding: 1.5rem 2rem; border-bottom: 1px solid #e0e0e0; }
  section h2 { color: #1a237e; font-size: 1.2rem; margin-bottom: 0.8rem;
               border-bottom: 2px solid #e8eaf6; padding-bottom: 0.4rem; }
  .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem 2rem; }
  .meta-grid dt { font-weight: 600; color: #555; }
  .meta-grid dd { margin: 0; }
  .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 12px;
           font-size: 0.75rem; font-weight: 700; color: #fff; text-transform: uppercase; }
  .badge-critical { background: #d32f2f; }
  .badge-high { background: #e64a19; }
  .badge-medium { background: #fbc02d; color: #333; }
  .badge-low { background: #1976d2; }
  .badge-info { background: #757575; }
  .summary-bar { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem; }
  .summary-item { font-size: 0.95rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #e0e0e0; }
  th { background: #f5f5f5; font-weight: 600; font-size: 0.85rem; color: #555; }
  td { font-size: 0.9rem; }
  .chart-section img { max-width: 100%; height: auto; margin: 0.5rem 0; border: 1px solid #e0e0e0;
                       border-radius: 4px; }
  footer { background: #fafafa; padding: 1rem 2rem; border-radius: 0 0 8px 8px;
           border-top: 1px solid #e0e0e0; text-align: center; font-size: 0.8rem; color: #999; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>&#x1F50D; WireNose Analysis Report</h1>
    <div class="subtitle">Generated: ${generated_at}</div>
  </header>

  <section>
    <h2>Capture Metadata</h2>
    <dl class="meta-grid">
      <dt>Source</dt><dd>${source}</dd>
      <dt>Packets</dt><dd>${packet_count}</dd>
      <dt>Duration</dt><dd>${duration}</dd>
      <dt>Total Bytes</dt><dd>${total_bytes}</dd>
      <dt>Start Time</dt><dd>${start_time}</dd>
      <dt>End Time</dt><dd>${end_time}</dd>
    </dl>
  </section>

  <section>
    <h2>Finding Summary</h2>
    <div class="summary-bar">
      <span class="summary-item"><strong>${finding_total}</strong> findings total</span>
      ${severity_badges}
    </div>
  </section>

  <section>
    <h2>Threat Findings</h2>
    ${findings_table}
  </section>

  <section class="chart-section">
    <h2>Charts</h2>
    ${charts_html}
  </section>

  <footer>
    WireNose v${version} &mdash; Report generated ${generated_at}
  </footer>
</div>
</body>
</html>
""")


# ── HTML assembly ────────────────────────────────────────────────────


def _build_html(
    metadata: CaptureMetadata,
    stats: PacketStats,
    findings: list[ThreatFinding],
    charts: dict[str, str],
    config: dict,
) -> str:
    """Assemble a self-contained HTML report from analysis data.

    Args:
        metadata: Capture session metadata.
        stats: Accumulated packet statistics.
        findings: Sorted threat findings.
        charts: Mapping of chart name → base64-encoded PNG string.
        config: Optional configuration overrides (currently unused).

    Returns:
        Complete HTML document string.
    """
    from wirenose import __version__
    from wirenose.output import _human_bytes

    # Metadata fields
    source = str(metadata.pcap_path) if metadata.pcap_path else (metadata.interface or "—")
    duration = "—"
    if metadata.start_time and metadata.end_time:
        secs = (metadata.end_time - metadata.start_time).total_seconds()
        duration = f"{secs:.2f}s"

    start_time = metadata.start_time.isoformat() if metadata.start_time else "—"
    end_time = metadata.end_time.isoformat() if metadata.end_time else "—"

    # Severity badge counts
    from wirenose.detectors.models import SEVERITY_ORDER
    sev_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        key = f.severity.lower()
        sev_counts[key] = sev_counts.get(key, 0) + 1

    badge_parts: list[str] = []
    for sev, count in sev_counts.items():
        if count > 0:
            badge_parts.append(
                f'<span class="summary-item"><span class="badge badge-{sev}">{sev}</span> {count}</span>'
            )
    severity_badges = "\n      ".join(badge_parts) if badge_parts else "<em>No threats detected</em>"

    # Findings table
    if findings:
        rows: list[str] = []
        for f in findings:
            src = f.source_ip or "—"
            dst = f.dest_ip or "—"
            rows.append(
                f"<tr><td><span class=\"badge badge-{f.severity.lower()}\">{f.severity.upper()}</span></td>"
                f"<td>{f.detector}</td><td>{f.title}</td>"
                f"<td>{f.description}</td><td>{src} → {dst}</td></tr>"
            )
        findings_table = (
            "<table><thead><tr><th>Severity</th><th>Detector</th>"
            "<th>Title</th><th>Description</th><th>Source → Dest</th></tr></thead>"
            "<tbody>" + "\n".join(rows) + "</tbody></table>"
        )
    else:
        findings_table = "<p><em>No threats detected.</em></p>"

    # Charts
    chart_names = [
        ("protocol_distribution", "Protocol Distribution"),
        ("traffic_volume", "Traffic Volume Over Time"),
        ("top_talkers", "Top Talkers"),
        ("alert_timeline", "Alert Timeline"),
    ]
    chart_parts: list[str] = []
    for key, label in chart_names:
        b64 = charts.get(key, "")
        if b64:
            chart_parts.append(
                f'<h3>{label}</h3>\n'
                f'<img src="data:image/png;base64,{b64}" alt="{label}">'
            )
    charts_html = "\n".join(chart_parts) if chart_parts else "<p><em>No chart data available.</em></p>"

    return _HTML_TEMPLATE.substitute(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source=source,
        packet_count=str(metadata.packet_count),
        duration=duration,
        total_bytes=_human_bytes(stats.total_bytes),
        start_time=start_time,
        end_time=end_time,
        finding_total=str(len(findings)),
        severity_badges=severity_badges,
        findings_table=findings_table,
        charts_html=charts_html,
        version=__version__,
    )


# ── Public entry point ───────────────────────────────────────────────


def generate_report(
    result: CaptureResult,
    findings: list[ThreatFinding],
    output_dir: Path,
    config: dict | None = None,
) -> Path:
    """Generate a self-contained HTML analysis report.

    Orchestrates chart generation, HTML assembly, and writes the report
    to ``output_dir / 'report.html'``.

    Args:
        result: Complete capture result with packets, stats, and metadata.
        findings: Sorted threat findings from detection.
        output_dir: Directory to write into (created if needed).
        config: Optional configuration overrides.

    Returns:
        Path to the written HTML file.
    """
    cfg = config or {}
    output_dir.mkdir(parents=True, exist_ok=True)

    metadata = result.metadata
    stats = result.stats
    snap = stats.to_dict()

    # Generate charts
    charts: dict[str, str] = {
        "protocol_distribution": _chart_protocol_distribution(snap["protocol_counts"]),
        "traffic_volume": _chart_traffic_volume(result.packets),
        "top_talkers": _chart_top_talkers(
            stats.top_src_ips(10),
            stats.top_dst_ips(10),
        ),
        "alert_timeline": _chart_alert_timeline(findings, result.packets),
    }

    html = _build_html(metadata, stats, findings, charts, cfg)

    report_path = output_dir / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path

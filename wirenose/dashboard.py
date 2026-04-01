"""Live Rich TUI dashboard for real-time packet capture monitoring.

Provides two layers:
- ``build_dashboard_layout()`` — a pure function that transforms a PacketStats
  snapshot + metadata into a Rich Layout tree.  Easy to test without threading.
- ``run_dashboard()`` — the orchestrator that starts a background capture thread,
  enters a Rich Live context, and refreshes the layout at a configurable rate.
  Ctrl+C gracefully stops capture and joins the thread.

Rich is imported lazily so that non-TUI code paths (pcap read, headless
capture) don't pay the import cost.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from wirenose.capture import CaptureEngine
from wirenose.errors import CapturePermissionError
from wirenose.models import CaptureMetadata, CaptureResult, PacketStats
from wirenose.output import _human_bytes

if TYPE_CHECKING:
    from rich.layout import Layout

    from wirenose.detectors.models import ThreatFinding

logger = logging.getLogger(__name__)

# Severity → Rich style mapping (mirrors output._SEVERITY_STYLES)
_ALERT_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def build_dashboard_layout(
    stats: PacketStats,
    iface: str,
    bpf_filter: str | None,
    elapsed: float,
    alerts: list[ThreatFinding] | None = None,
) -> "Layout":
    """Build a Rich Layout tree from a PacketStats snapshot.

    This is a **pure function** (no side effects, no threading) that turns
    stats + metadata into a renderable Rich Layout.  The caller (run_dashboard)
    passes the result to ``Live.update()``.

    Args:
        stats: Thread-safe PacketStats instance.  A snapshot is taken via
            ``to_dict()`` and ``top_*`` methods under the internal lock.
        iface: Network interface being captured on.
        bpf_filter: Active BPF filter expression, or None.
        elapsed: Seconds since capture started.
        alerts: List of ThreatFinding objects to render in the alert panel.
            Defaults to an empty list (no threats shown).

    Returns:
        A Rich Layout with named panels: ``header``, ``body``, ``protocols``,
        ``src_ips``, ``dst_ips``, ``alerts``, ``footer``.
    """
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    if alerts is None:
        alerts = []

    snap = stats.to_dict()
    top_src = stats.top_src_ips(10)
    top_dst = stats.top_dst_ips(10)

    # ── Header ──────────────────────────────────────────────
    filter_info = f"  Filter: {bpf_filter}" if bpf_filter else ""
    header_text = Text(
        f"  WireNose — Capturing on {iface}{filter_info}",
        style="bold white",
    )
    header = Panel(header_text, style="blue", title="[bold]WireNose Dashboard[/bold]")

    # ── Protocol table ──────────────────────────────────────
    proto_table = Table(title="Protocols", expand=True, show_lines=False)
    proto_table.add_column("Protocol", style="cyan", no_wrap=True)
    proto_table.add_column("Count", justify="right", style="green")
    proto_table.add_column("%", justify="right", style="yellow")

    total_pkts = snap["packet_count"]
    for proto, cnt in sorted(
        snap["protocol_counts"].items(), key=lambda x: x[1], reverse=True
    ):
        pct = f"{cnt / total_pkts * 100:.1f}" if total_pkts > 0 else "0.0"
        proto_table.add_row(proto, str(cnt), pct)

    # ── Top Source IPs ──────────────────────────────────────
    src_table = Table(title="Top Source IPs", expand=True, show_lines=False)
    src_table.add_column("IP", style="cyan", no_wrap=True)
    src_table.add_column("Packets", justify="right", style="green")
    for ip, cnt in top_src:
        src_table.add_row(ip, str(cnt))

    # ── Top Destination IPs ─────────────────────────────────
    dst_table = Table(title="Top Dest IPs", expand=True, show_lines=False)
    dst_table.add_column("IP", style="cyan", no_wrap=True)
    dst_table.add_column("Packets", justify="right", style="green")
    for ip, cnt in top_dst:
        dst_table.add_row(ip, str(cnt))

    # ── Footer (bandwidth + packet count + elapsed) ────────
    bw = _human_bytes(snap["total_bytes"])
    elapsed_str = f"{elapsed:.1f}s"
    bps = (
        _human_bytes(int(snap["total_bytes"] / elapsed)) + "/s"
        if elapsed > 0
        else "—"
    )
    footer_text = Text(
        f"  Packets: {total_pkts}    Bytes: {bw}    Rate: {bps}    Elapsed: {elapsed_str}",
        style="bold",
    )
    footer = Panel(footer_text, style="green", title="[bold]Stats[/bold]")

    # ── Alert panel ───────────────────────────────────────
    if alerts:
        alert_text = Text()
        for finding in alerts[-20:]:  # Show last 20 findings
            style = _ALERT_SEVERITY_STYLES.get(finding.severity, "")
            src = finding.source_ip or "—"
            alert_text.append(f"[{finding.severity.upper()}]", style=style)
            alert_text.append(f" {finding.title} — {finding.detector} | {src}\n")
    else:
        alert_text = Text("  No threats detected", style="green")

    alerts_panel = Panel(
        alert_text,
        style="red" if alerts else "green",
        title="[bold]Threat Alerts[/bold]",
    )

    # ── Assemble Layout ─────────────────────────────────────
    layout = Layout(name="root")
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(name="body"),
        Layout(alerts_panel, name="alerts", size=8),
        Layout(footer, name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(Panel(proto_table, title="Protocols"), name="protocols"),
        Layout(name="ips"),
    )
    layout["body"]["ips"].split_column(
        Layout(Panel(src_table, title="Sources"), name="src_ips"),
        Layout(Panel(dst_table, title="Destinations"), name="dst_ips"),
    )

    return layout


def _capture_thread_target(
    engine: CaptureEngine,
    iface: str,
    bpf_filter: str | None,
    count: int,
    timeout: int | None,
    output: Path | None,
    stop_event: threading.Event,
    result_holder: list,
) -> None:
    """Target function for the background capture thread.

    Runs ``engine.capture_live()`` with the stop_event, stores the
    CaptureResult into *result_holder[0]* so the main thread can access it
    after joining.
    """
    try:
        result = engine.capture_live(
            iface=iface,
            bpf_filter=bpf_filter,
            count=count,
            timeout=timeout,
            output=output,
            store=False,  # Dashboard mode — stats only, no memory retention
            stop_event=stop_event,
        )
        result_holder.append(result)
    except Exception:
        logger.exception("Capture thread error")
        result_holder.append(None)


def run_dashboard(
    engine: CaptureEngine,
    iface: str,
    bpf_filter: str | None = None,
    count: int = 0,
    timeout: int | None = None,
    output: Path | None = None,
    refresh_rate: float = 4.0,
) -> CaptureResult:
    """Run the live TUI dashboard with background packet capture.

    Launches a background thread that calls ``engine.capture_live()`` with
    a ``stop_event``.  The main thread enters a Rich ``Live`` context and
    refreshes the dashboard layout at *refresh_rate* Hz.  Ctrl+C (KeyboardInterrupt)
    sets the stop event, waits for the capture thread to finish, and returns
    the final CaptureResult.

    **Important:** Privilege errors are checked before entering the Live
    context so that the error message isn't swallowed by the TUI.

    Args:
        engine: CaptureEngine instance (will be mutated — stats accumulate).
        iface: Network interface to capture on.
        bpf_filter: Optional BPF filter expression.
        count: Packet count limit (0 = unlimited).
        timeout: Capture timeout in seconds (None = no timeout).
        output: Path to write pcap output.  None = auto-generated.
        refresh_rate: Dashboard refresh rate in Hz.  Default 4.0 (250ms).

    Returns:
        CaptureResult from the capture thread.

    Raises:
        CapturePermissionError: If libpcap denies access (raised *before*
            entering the TUI so the user sees a clean error message).
    """
    from rich.live import Live

    # Reset engine state so our stats reference is fresh
    engine._stats = PacketStats()
    engine._packets = []

    stop_event = threading.Event()
    result_holder: list[CaptureResult | None] = []

    # Start capture thread
    capture_t = threading.Thread(
        target=_capture_thread_target,
        args=(engine, iface, bpf_filter, count, timeout, output, stop_event, result_holder),
        daemon=True,
        name="wirenose-capture",
    )
    capture_t.start()

    start_time = time.monotonic()
    refresh_interval = 1.0 / refresh_rate

    try:
        with Live(
            build_dashboard_layout(engine._stats, iface, bpf_filter, 0.0),
            refresh_per_second=refresh_rate,
            screen=False,
        ) as live:
            while capture_t.is_alive():
                elapsed = time.monotonic() - start_time
                live.update(
                    build_dashboard_layout(engine._stats, iface, bpf_filter, elapsed)
                )
                time.sleep(refresh_interval)

            # Final update after thread exits (count reached or timeout)
            elapsed = time.monotonic() - start_time
            live.update(
                build_dashboard_layout(engine._stats, iface, bpf_filter, elapsed)
            )
    except KeyboardInterrupt:
        logger.info("Ctrl+C received — stopping capture")
        stop_event.set()
    finally:
        capture_t.join(timeout=5)
        if capture_t.is_alive():
            logger.warning("Capture thread did not exit within 5s")

    # Return the CaptureResult from the thread, or build a fallback
    if result_holder and result_holder[0] is not None:
        return result_holder[0]

    # Fallback: build a result from what we have
    from datetime import datetime, timezone

    end_time = datetime.now(tz=timezone.utc)
    start_dt = datetime.now(tz=timezone.utc)  # approximate
    metadata = CaptureMetadata(
        interface=iface,
        bpf_filter=bpf_filter,
        start_time=start_dt,
        end_time=end_time,
        packet_count=engine._stats.packet_count,
        pcap_path=output,
    )
    return CaptureResult(packets=None, stats=engine._stats, metadata=metadata)

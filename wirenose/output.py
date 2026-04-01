"""Console output formatting for WireNose capture and analysis results."""

from __future__ import annotations

from typing import TYPE_CHECKING

from wirenose.models import CaptureResult

if TYPE_CHECKING:
    from wirenose.detectors.models import ThreatFinding


def _human_bytes(n: int) -> str:
    """Format byte count as human-readable string (B/KB/MB/GB)."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    else:
        return f"{n / (1024 * 1024 * 1024):.2f} GB"


def print_summary(result: CaptureResult) -> None:
    """Print a formatted summary of a capture or analysis result to stdout.

    Sections:
    - Capture metadata (interface, filter, duration, count, pcap path)
    - Protocol distribution (protocol → count → percentage)
    - Top 10 source IPs
    - Top 10 destination IPs
    - Total bytes transferred
    """
    meta = result.metadata
    stats = result.stats

    # ── Metadata ──
    print()
    print("═" * 50)
    print("  WireNose Capture Summary")
    print("═" * 50)

    if meta.interface:
        print(f"  Interface : {meta.interface}")
    else:
        print(f"  Source    : {meta.pcap_path}")

    if meta.bpf_filter:
        print(f"  Filter    : {meta.bpf_filter}")

    if meta.start_time and meta.end_time:
        duration = (meta.end_time - meta.start_time).total_seconds()
        print(f"  Duration  : {duration:.2f}s")

    print(f"  Packets   : {meta.packet_count}")

    if meta.pcap_path and meta.interface:
        print(f"  Saved to  : {meta.pcap_path}")

    # ── Protocol Distribution ──
    print()
    print("─" * 50)
    print("  Protocol Distribution")
    print("─" * 50)

    snap = stats.to_dict()
    proto_counts = snap["protocol_counts"]
    total_packets = snap["packet_count"]

    if proto_counts:
        # Sort by count descending
        sorted_protos = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)
        name_width = max(len(name) for name, _ in sorted_protos)
        for name, count in sorted_protos:
            pct = (count / total_packets * 100) if total_packets > 0 else 0.0
            print(f"  {name:<{name_width}}  {count:>6}  ({pct:5.1f}%)")
    else:
        print("  No packets captured.")

    # ── Top Source IPs ──
    top_src = stats.top_src_ips(10)
    if top_src:
        print()
        print("─" * 50)
        print("  Top Source IPs")
        print("─" * 50)
        ip_width = max(len(ip) for ip, _ in top_src)
        for ip, count in top_src:
            print(f"  {ip:<{ip_width}}  {count:>6} pkts")

    # ── Top Destination IPs ──
    top_dst = stats.top_dst_ips(10)
    if top_dst:
        print()
        print("─" * 50)
        print("  Top Destination IPs")
        print("─" * 50)
        ip_width = max(len(ip) for ip, _ in top_dst)
        for ip, count in top_dst:
            print(f"  {ip:<{ip_width}}  {count:>6} pkts")

    # ── Bandwidth ──
    print()
    print("─" * 50)
    print(f"  Total bytes: {_human_bytes(stats.total_bytes)}")
    print("═" * 50)
    print()


# Severity → Rich style mapping
_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def print_threats(findings: list[ThreatFinding]) -> None:
    """Print threat findings with severity coloring via Rich.

    Rich is imported lazily (K008) so ``import wirenose.output`` stays cheap
    when threat detection is not used.

    Uses a list format rather than a table to ensure full text is visible
    in both TTY and non-TTY (piped/subprocess) contexts.

    Args:
        findings: Sorted list of :class:`ThreatFinding` from ThreatEngine.
    """
    from rich.console import Console

    console = Console(force_terminal=False)

    if not findings:
        console.print("\n[green]No threats detected.[/green]\n")
        return

    console.print(f"\n[bold]Threat Findings ({len(findings)} total)[/bold]")

    for i, finding in enumerate(findings, 1):
        style = _SEVERITY_STYLES.get(finding.severity, "")
        src = finding.source_ip or "—"
        dst = finding.dest_ip or "—"
        console.print(f"\n  [{style}][{finding.severity.upper()}][/{style}] "
                       f"{finding.title}")
        console.print(f"    Detector: {finding.detector}  |  "
                       f"Source: {src}  →  Dest: {dst}")
        console.print(f"    {finding.description}")

    console.print()

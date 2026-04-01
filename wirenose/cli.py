"""WireNose CLI entry point — capture and analyze subcommands."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from wirenose.capture import CaptureEngine
from wirenose.config import load_config
from wirenose.dashboard import run_dashboard
from wirenose.errors import CapturePermissionError, InvalidFilterError
from wirenose.output import print_summary

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with capture and analyze subcommands."""
    parser = argparse.ArgumentParser(
        prog="wirenose",
        description="WireNose — a Python-based packet sniffer for SOC use",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── capture ──
    cap = subparsers.add_parser("capture", help="Capture live packets from a network interface")
    cap.add_argument("-i", "--interface", required=True, help="Network interface (e.g. lo, eth0)")
    cap.add_argument("-f", "--filter", default=None, help="BPF filter expression (e.g. 'tcp port 80')")
    cap.add_argument("-c", "--count", type=int, default=None, help="Number of packets to capture (default: 100)")
    cap.add_argument("-d", "--duration", type=int, default=None, help="Capture timeout in seconds")
    cap.add_argument("-o", "--output", default=None, help="Output pcap file path (auto-generated if omitted)")
    cap.add_argument(
        "-C", "--config", default=None, metavar="PATH",
        help="Path to YAML config file for default settings",
    )
    cap.add_argument(
        "--no-dashboard", action="store_true", default=False,
        help="Disable live TUI dashboard (use silent capture)",
    )

    # ── analyze ──
    ana = subparsers.add_parser("analyze", help="Read and analyze a pcap file")
    ana.add_argument("pcap_file", help="Path to the .pcap file to analyze")
    ana.add_argument(
        "-C", "--config", default=None, metavar="PATH",
        help="Path to YAML config file for detection settings",
    )

    return parser


def _resolve_capture_args(args: argparse.Namespace) -> tuple[str, str | None, int, int | None, Path | None, float]:
    """Merge CLI args with config file defaults.  CLI args override config.

    Returns:
        (iface, bpf_filter, count, timeout, output_path, refresh_rate)
    """
    cfg = load_config(args.config)

    iface = args.interface  # always required by argparse
    bpf_filter = args.filter if args.filter is not None else cfg.bpf_filter
    count = args.count if args.count is not None else cfg.count
    timeout = args.duration if args.duration is not None else cfg.timeout
    output_path = Path(args.output) if args.output else None
    refresh_rate = cfg.dashboard_refresh_rate

    return iface, bpf_filter, count, timeout, output_path, refresh_rate


def _cmd_capture(args: argparse.Namespace) -> None:
    """Handle the 'capture' subcommand."""
    engine = CaptureEngine()
    iface, bpf_filter, count, timeout, output_path, refresh_rate = _resolve_capture_args(args)

    # Load config for detection settings
    cfg = load_config(args.config)

    use_dashboard = sys.stdout.isatty() and not args.no_dashboard

    if use_dashboard:
        try:
            result = run_dashboard(
                engine=engine,
                iface=iface,
                bpf_filter=bpf_filter,
                count=count,
                timeout=timeout,
                output=output_path,
                refresh_rate=refresh_rate,
                detection_config=cfg.detection if cfg.detection else None,
            )
        except CapturePermissionError:
            print("Error: Live capture requires elevated privileges. Run with sudo.", file=sys.stderr)
            sys.exit(1)
        except InvalidFilterError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            result = engine.capture_live(
                iface=iface,
                bpf_filter=bpf_filter,
                count=count,
                timeout=timeout,
                output=output_path,
            )
        except CapturePermissionError:
            print("Error: Live capture requires elevated privileges. Run with sudo.", file=sys.stderr)
            sys.exit(1)
        except InvalidFilterError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    print_summary(result)


def _cmd_analyze(args: argparse.Namespace) -> None:
    """Handle the 'analyze' subcommand."""
    engine = CaptureEngine()
    pcap_path = Path(args.pcap_file)

    try:
        result = engine.read_pcap(pcap_path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print_summary(result)

    # --- Threat detection ---
    from wirenose.detectors.engine import ThreatEngine
    from wirenose.output import print_threats

    cfg = load_config(args.config)
    threat_engine = ThreatEngine()
    findings = threat_engine.analyze(result.packets, cfg.detection)
    print_threats(findings)


def main() -> None:
    """CLI entry point registered as the `wirenose` console script."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "capture":
        _cmd_capture(args)
    elif args.command == "analyze":
        _cmd_analyze(args)

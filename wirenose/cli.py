"""WireNose CLI entry point — capture and analyze subcommands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from wirenose.capture import CaptureEngine
from wirenose.errors import CapturePermissionError, InvalidFilterError
from wirenose.output import print_summary


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
    cap.add_argument("-c", "--count", type=int, default=100, help="Number of packets to capture (default: 100)")
    cap.add_argument("-d", "--duration", type=int, default=None, help="Capture timeout in seconds")
    cap.add_argument("-o", "--output", default=None, help="Output pcap file path (auto-generated if omitted)")

    # ── analyze ──
    ana = subparsers.add_parser("analyze", help="Read and analyze a pcap file")
    ana.add_argument("pcap_file", help="Path to the .pcap file to analyze")

    return parser


def _cmd_capture(args: argparse.Namespace) -> None:
    """Handle the 'capture' subcommand."""
    engine = CaptureEngine()
    output_path = Path(args.output) if args.output else None

    try:
        result = engine.capture_live(
            iface=args.interface,
            bpf_filter=args.filter,
            count=args.count,
            timeout=args.duration,
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

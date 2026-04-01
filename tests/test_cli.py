"""CLI integration tests — exercise wirenose entry point via subprocess."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

FIXTURE_PCAP = Path(__file__).parent / "fixtures" / "sample.pcap"


def _run_wirenose(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run wirenose CLI via uv and return the completed process."""
    return subprocess.run(
        [sys.executable, "-m", "wirenose", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestAnalyzeSubcommand:
    """Tests for the 'analyze' subcommand."""

    def test_analyze_reads_pcap_and_prints_stats(self) -> None:
        """Analyze a known fixture pcap and verify output contains expected data."""
        result = _run_wirenose("analyze", str(FIXTURE_PCAP))

        assert result.returncode == 0, f"stderr: {result.stderr}"
        out = result.stdout

        # Should contain protocol names from the fixture
        assert "TCP" in out
        assert "UDP" in out
        assert "ICMP" in out
        assert "ARP" in out
        assert "IP" in out

        # Should contain IPs from the fixture packets
        assert "10.0.0.1" in out
        assert "10.0.0.2" in out

        # Should contain structural elements
        assert "Protocol Distribution" in out
        assert "Top Source IPs" in out
        assert "Total bytes" in out

    def test_analyze_missing_file_exits_nonzero(self) -> None:
        """Analyze a non-existent file and verify error exit."""
        result = _run_wirenose("analyze", "nonexistent.pcap")

        assert result.returncode == 1
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()

    def test_analyze_shows_packet_count(self) -> None:
        """Verify the correct packet count appears in output."""
        result = _run_wirenose("analyze", str(FIXTURE_PCAP))

        assert result.returncode == 0
        # Fixture has 10 packets
        assert "10" in result.stdout


class TestCaptureSubcommand:
    """Tests for the 'capture' subcommand (non-root)."""

    def test_capture_without_sudo_exits_nonzero(self) -> None:
        """Capture on a real interface without root should fail with a privilege error."""
        result = _run_wirenose("capture", "-i", "lo")

        assert result.returncode == 1
        assert "elevated privileges" in result.stderr.lower()

    def test_capture_argument_parsing(self) -> None:
        """Verify argparse correctly handles all capture flags.

        We can't actually capture (no root), but we can verify the parser
        doesn't reject valid flag combinations by checking the error is
        about permissions, not argument parsing.
        """
        result = _run_wirenose(
            "capture", "-i", "lo", "-f", "tcp", "-c", "50", "-d", "5", "-o", "/tmp/test.pcap"
        )

        # Should fail on permissions, not on arg parsing
        assert result.returncode == 1
        # Should NOT contain argparse error patterns
        assert "unrecognized arguments" not in result.stderr
        assert "error: argument" not in result.stderr


class TestNoSubcommand:
    """Tests for invocation with no subcommand."""

    def test_no_subcommand_prints_help(self) -> None:
        """Running wirenose with no args should print help text."""
        result = _run_wirenose()

        # Should exit cleanly (0) and show help
        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "wirenose" in result.stdout.lower()
        assert "capture" in result.stdout
        assert "analyze" in result.stdout

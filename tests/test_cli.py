"""CLI integration tests — exercise wirenose entry point via subprocess."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

FIXTURE_PCAP = Path(__file__).parent / "fixtures" / "sample.pcap"
THREAT_PCAP = Path(__file__).parent / "fixtures" / "threats.pcap"


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


class TestNoDashboardFlag:
    """Tests for the --no-dashboard flag."""

    def test_no_dashboard_flag_accepted(self) -> None:
        """Verify --no-dashboard is accepted by argparse without errors."""
        result = _run_wirenose("capture", "-i", "lo", "--no-dashboard")

        # Should fail on permissions, not arg parsing
        assert result.returncode == 1
        assert "unrecognized arguments" not in result.stderr
        assert "elevated privileges" in result.stderr.lower()

    def test_no_dashboard_with_other_flags(self) -> None:
        """--no-dashboard works alongside all other capture flags."""
        result = _run_wirenose(
            "capture", "-i", "lo", "-f", "tcp", "-c", "50",
            "-d", "5", "-o", "/tmp/test.pcap", "--no-dashboard",
        )

        assert result.returncode == 1
        assert "unrecognized arguments" not in result.stderr
        assert "error: argument" not in result.stderr


class TestConfigFlag:
    """Tests for the --config / -C flag."""

    def test_config_flag_accepted(self) -> None:
        """Verify --config is accepted by argparse without errors."""
        # Pass a non-existent config — load_config handles missing gracefully
        result = _run_wirenose("capture", "-i", "lo", "--config", "/tmp/nonexistent.yaml")

        assert result.returncode == 1
        assert "unrecognized arguments" not in result.stderr
        assert "elevated privileges" in result.stderr.lower()

    def test_config_short_flag_accepted(self) -> None:
        """Verify -C short flag works."""
        result = _run_wirenose("capture", "-i", "lo", "-C", "/tmp/nonexistent.yaml")

        assert result.returncode == 1
        assert "unrecognized arguments" not in result.stderr
        assert "elevated privileges" in result.stderr.lower()

    def test_config_combined_with_no_dashboard(self) -> None:
        """Both --config and --no-dashboard can be used together."""
        result = _run_wirenose(
            "capture", "-i", "lo", "-C", "/tmp/nonexistent.yaml", "--no-dashboard",
        )

        assert result.returncode == 1
        assert "unrecognized arguments" not in result.stderr


class TestPrivilegeErrorRegression:
    """Ensure privilege errors are caught before any TUI flash."""

    def test_nonroot_capture_exits_clean_with_privilege_error(self) -> None:
        """Non-root capture must exit 1 with a clean error message — no TUI flash.

        This is a regression test: if the dashboard launches before checking
        privileges, users see a brief TUI flicker before the error.
        """
        result = _run_wirenose("capture", "-i", "lo")

        assert result.returncode == 1
        assert "elevated privileges" in result.stderr.lower()
        # No Rich TUI escape sequences should leak to stdout
        assert "\x1b[" not in result.stdout

    def test_nonroot_with_dashboard_flag_exits_clean(self) -> None:
        """Even without --no-dashboard, non-root gets a clean privilege error."""
        result = _run_wirenose("capture", "-i", "lo", "-d", "5")

        assert result.returncode == 1
        assert "elevated privileges" in result.stderr.lower()


class TestConfigMerging:
    """Test that config file values are used as defaults when CLI args aren't specified."""

    def test_config_values_used_as_defaults(self, tmp_path: Path) -> None:
        """Config file values should provide defaults that CLI args can override.

        We test this via the unit-level _resolve_capture_args() to avoid
        needing root privileges for a full capture.
        """
        import argparse

        from wirenose.cli import _resolve_capture_args

        config_file = tmp_path / "test.yaml"
        config_file.write_text(textwrap.dedent("""\
            bpf_filter: "udp port 53"
            count: 200
            timeout: 60
            dashboard_refresh_rate: 2.0
        """))

        # Simulate argparse namespace with only interface and config set
        ns = argparse.Namespace(
            interface="eth0",
            filter=None,
            count=None,
            duration=None,
            output=None,
            config=str(config_file),
            no_dashboard=False,
        )

        iface, bpf_filter, count, timeout, output_path, refresh_rate = _resolve_capture_args(ns)

        assert iface == "eth0"
        assert bpf_filter == "udp port 53"
        assert count == 200
        assert timeout == 60
        assert output_path is None
        assert refresh_rate == 2.0

    def test_cli_args_override_config(self, tmp_path: Path) -> None:
        """Explicit CLI args should override config file values."""
        import argparse

        from wirenose.cli import _resolve_capture_args

        config_file = tmp_path / "test.yaml"
        config_file.write_text(textwrap.dedent("""\
            bpf_filter: "udp port 53"
            count: 200
            timeout: 60
        """))

        ns = argparse.Namespace(
            interface="lo",
            filter="tcp port 80",
            count=50,
            duration=10,
            output="/tmp/out.pcap",
            config=str(config_file),
            no_dashboard=False,
        )

        iface, bpf_filter, count, timeout, output_path, refresh_rate = _resolve_capture_args(ns)

        assert iface == "lo"
        assert bpf_filter == "tcp port 80"
        assert count == 50
        assert timeout == 10
        assert output_path == Path("/tmp/out.pcap")

    def test_no_config_uses_module_defaults(self) -> None:
        """Without --config, values come from WireNoseConfig defaults."""
        import argparse

        from wirenose.cli import _resolve_capture_args

        ns = argparse.Namespace(
            interface="lo",
            filter=None,
            count=None,
            duration=None,
            output=None,
            config=None,
            no_dashboard=False,
        )

        iface, bpf_filter, count, timeout, output_path, refresh_rate = _resolve_capture_args(ns)

        assert iface == "lo"
        assert bpf_filter is None
        assert count == 100  # WireNoseConfig default
        assert timeout is None
        assert output_path is None
        assert refresh_rate == 4.0  # WireNoseConfig default


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


class TestAnalyzeWithThreats:
    """Tests for threat detection integration in the analyze subcommand."""

    def test_analyze_with_threats_detects_all_six(self) -> None:
        """Analyze the threat fixture pcap and verify all 6 detector types appear."""
        result = _run_wirenose("analyze", str(THREAT_PCAP))

        assert result.returncode == 0, f"stderr: {result.stderr}"
        out = result.stdout

        # Each detector type should produce at least one finding
        assert "port_scan" in out, f"port_scan not found in output:\n{out}"
        assert "syn_flood" in out, f"syn_flood not found in output:\n{out}"
        assert "arp_spoof" in out, f"arp_spoof not found in output:\n{out}"
        assert "dns_tunnel" in out, f"dns_tunnel not found in output:\n{out}"
        assert "icmp_anomaly" in out, f"icmp_anomaly not found in output:\n{out}"
        assert "cleartext_creds" in out, f"cleartext_creds not found in output:\n{out}"

    def test_analyze_with_threats_shows_severity(self) -> None:
        """Threat output should include severity labels."""
        result = _run_wirenose("analyze", str(THREAT_PCAP))

        assert result.returncode == 0
        out = result.stdout
        # At least CRITICAL and HIGH should appear from our detectors
        assert "CRITICAL" in out
        assert "HIGH" in out

    def test_analyze_still_prints_summary(self) -> None:
        """The packet summary section still appears alongside threat findings."""
        result = _run_wirenose("analyze", str(THREAT_PCAP))

        assert result.returncode == 0
        out = result.stdout

        # Summary structural elements
        assert "Protocol Distribution" in out
        assert "Top Source IPs" in out
        assert "Total bytes" in out

        # And threat findings are also present
        assert "Threat Findings" in out

    def test_analyze_with_config_overrides(self, tmp_path: Path) -> None:
        """A config file with a low port_scan_threshold makes the detector trigger earlier."""
        # Create a small pcap with only 6 unique ports (below default 20, above our override 5)
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.utils import wrpcap

        small_pcap = tmp_path / "small.pcap"
        pkts = [
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=port, flags="S")
            for port in range(1, 7)  # 6 unique ports
        ]
        wrpcap(str(small_pcap), pkts)

        # Without config → no port scan detection (6 < 20)
        result_no_config = _run_wirenose("analyze", str(small_pcap))
        assert result_no_config.returncode == 0
        assert "Port Scan" not in result_no_config.stdout

        # With config override → port scan detected (6 > 5)
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text("detection:\n  port_scan_threshold: 5\n")

        result_with_config = _run_wirenose("analyze", str(small_pcap), "-C", str(config_file))
        assert result_with_config.returncode == 0, f"stderr: {result_with_config.stderr}"
        assert "port_scan" in result_with_config.stdout

    def test_analyze_no_threats_shows_clean_message(self) -> None:
        """When no threats are detected, a 'No threats detected' message appears."""
        # The sample fixture has too few packets to trigger any detector
        result = _run_wirenose("analyze", str(FIXTURE_PCAP))

        assert result.returncode == 0
        assert "No threats detected" in result.stdout

    def test_analyze_config_flag_accepted(self) -> None:
        """The -C/--config flag is accepted by the analyze subparser."""
        result = _run_wirenose("analyze", str(FIXTURE_PCAP), "-C", "/tmp/nonexistent.yaml")

        assert result.returncode == 0
        assert "unrecognized arguments" not in result.stderr


class TestCaptureDetectionConfig:
    """Tests that detection config from --config reaches run_dashboard()."""

    def test_detection_config_passed_to_run_dashboard(self, tmp_path: Path) -> None:
        """_cmd_capture should pass cfg.detection to run_dashboard() as detection_config."""
        import argparse
        from unittest.mock import MagicMock, patch

        from wirenose.cli import _cmd_capture

        config_file = tmp_path / "test.yaml"
        config_file.write_text(textwrap.dedent("""\
            detection:
              port_scan_threshold: 5
              syn_flood_threshold: 100
        """))

        ns = argparse.Namespace(
            interface="lo",
            filter=None,
            count=None,
            duration=None,
            output=None,
            config=str(config_file),
            no_dashboard=False,
            command="capture",
        )

        with patch("wirenose.cli.run_dashboard") as mock_dashboard, \
             patch("wirenose.cli.print_summary"), \
             patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            mock_result = MagicMock()
            mock_dashboard.return_value = mock_result

            _cmd_capture(ns)

            mock_dashboard.assert_called_once()
            call_kwargs = mock_dashboard.call_args
            assert call_kwargs[1]["detection_config"] == {
                "port_scan_threshold": 5,
                "syn_flood_threshold": 100,
            }

    def test_no_detection_config_passes_none(self, tmp_path: Path) -> None:
        """When config has no detection section, detection_config should be None."""
        import argparse
        from unittest.mock import MagicMock, patch

        from wirenose.cli import _cmd_capture

        ns = argparse.Namespace(
            interface="lo",
            filter=None,
            count=None,
            duration=None,
            output=None,
            config=None,
            no_dashboard=False,
            command="capture",
        )

        with patch("wirenose.cli.run_dashboard") as mock_dashboard, \
             patch("wirenose.cli.print_summary"), \
             patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            mock_result = MagicMock()
            mock_dashboard.return_value = mock_result

            _cmd_capture(ns)

            mock_dashboard.assert_called_once()
            call_kwargs = mock_dashboard.call_args
            # Empty dict is falsy, so detection_config should be None
            assert call_kwargs[1]["detection_config"] is None


class TestAnalyzeReportFlag:
    """Tests for the --report and --output-dir flags on the analyze subcommand."""

    def test_analyze_report_generates_output_files(self, tmp_path: Path) -> None:
        """--report -o <dir> produces HTML, JSON, and pcap copy in output directory."""
        result = _run_wirenose("analyze", str(THREAT_PCAP), "--report", "-o", str(tmp_path))

        assert result.returncode == 0, f"stderr: {result.stderr}"

        assert (tmp_path / "report.html").exists(), "report.html not found"
        assert (tmp_path / "report.json").exists(), "report.json not found"
        assert (tmp_path / "threats.pcap").exists(), "threats.pcap copy not found"

    def test_analyze_report_html_contains_findings(self, tmp_path: Path) -> None:
        """The generated HTML report contains threat-related text."""
        _run_wirenose("analyze", str(THREAT_PCAP), "--report", "-o", str(tmp_path))

        html = (tmp_path / "report.html").read_text(encoding="utf-8")
        # Threats fixture triggers port_scan and syn_flood among others
        assert "port_scan" in html or "Port Scan" in html
        assert "syn_flood" in html or "SYN Flood" in html

    def test_analyze_report_json_is_valid(self, tmp_path: Path) -> None:
        """The generated JSON report is valid and has expected top-level keys."""
        import json

        _run_wirenose("analyze", str(THREAT_PCAP), "--report", "-o", str(tmp_path))

        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert "wirenose_version" in data
        assert "capture" in data
        assert "findings" in data
        assert "finding_summary" in data
        assert data["finding_summary"]["total"] > 0

    def test_analyze_report_default_output_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--report without -o writes files into the current working directory."""
        monkeypatch.chdir(tmp_path)

        result = _run_wirenose("analyze", str(THREAT_PCAP), "--report")

        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert (tmp_path / "report.html").exists()
        assert (tmp_path / "report.json").exists()

    def test_analyze_without_report_flag_unchanged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without --report, no report files are created and output matches pre-existing behavior."""
        monkeypatch.chdir(tmp_path)

        result = _run_wirenose("analyze", str(THREAT_PCAP))

        assert result.returncode == 0
        # No report files should be generated
        assert not (tmp_path / "report.html").exists()
        assert not (tmp_path / "report.json").exists()
        # Normal output still present
        assert "Report generated" not in result.stdout

    def test_analyze_report_prints_output_paths(self, tmp_path: Path) -> None:
        """When --report is used, output paths are printed to stdout."""
        result = _run_wirenose("analyze", str(THREAT_PCAP), "--report", "-o", str(tmp_path))

        assert result.returncode == 0
        out = result.stdout
        assert "Report generated:" in out
        assert "HTML" in out
        assert "JSON" in out
        assert "PCAP" in out

    def test_analyze_report_creates_output_dir(self, tmp_path: Path) -> None:
        """--output-dir creates the directory if it doesn't exist."""
        new_dir = tmp_path / "nested" / "output"
        assert not new_dir.exists()

        result = _run_wirenose("analyze", str(THREAT_PCAP), "--report", "-o", str(new_dir))

        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert new_dir.exists()
        assert (new_dir / "report.html").exists()

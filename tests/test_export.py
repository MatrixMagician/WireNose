"""Tests for wirenose.export — JSON export and pcap copy utilities."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

from wirenose.detectors.models import ThreatFinding
from wirenose.export import copy_pcap, export_json
from wirenose.models import CaptureMetadata, CaptureResult, PacketStats


# ── Helpers ──────────────────────────────────────────────────────────


def _make_result(
    tmp_path: Path,
    *,
    packet_count: int = 10,
    total_bytes: int = 5000,
    pcap_name: str = "test.pcap",
    interface: str | None = None,
    bpf_filter: str | None = None,
) -> CaptureResult:
    """Build a minimal CaptureResult for testing (no real packets needed)."""
    pcap_path = tmp_path / pcap_name
    pcap_path.write_bytes(b"\x00" * 100)  # dummy file

    meta = CaptureMetadata(
        interface=interface,
        bpf_filter=bpf_filter,
        start_time=datetime(2026, 4, 1, 12, 0, 0),
        end_time=datetime(2026, 4, 1, 12, 5, 0),
        packet_count=packet_count,
        pcap_path=pcap_path,
    )

    stats = PacketStats(
        protocol_counts=Counter({"TCP": 7, "UDP": 2, "ICMP": 1}),
        src_ips=Counter({"10.0.0.1": 5, "10.0.0.2": 3, "10.0.0.3": 2}),
        dst_ips=Counter({"10.0.0.4": 6, "10.0.0.5": 4}),
        total_bytes=total_bytes,
        packet_count=packet_count,
    )

    return CaptureResult(packets=None, stats=stats, metadata=meta)


def _make_findings() -> list[ThreatFinding]:
    """Build a representative set of ThreatFindings covering all severities."""
    return [
        ThreatFinding(
            detector="port_scan",
            severity="high",
            title="Port Scan Detected",
            description="25 unique ports scanned",
            source_ip="10.0.0.1",
            dest_ip="10.0.0.2",
            metadata={"ports_scanned": 25},
            timestamp=datetime(2026, 4, 1, 12, 1, 0),
            packet_indices=[0, 1, 2],
        ),
        ThreatFinding(
            detector="syn_flood",
            severity="critical",
            title="SYN Flood Detected",
            description="110 SYN packets detected",
            source_ip="10.0.0.50",
            dest_ip="10.0.0.2",
            metadata={},
            timestamp=datetime(2026, 4, 1, 12, 2, 0),
        ),
        ThreatFinding(
            detector="arp_spoof",
            severity="medium",
            title="ARP Spoofing Detected",
            description="MAC claiming multiple IPs",
            source_ip=None,
            dest_ip=None,
            metadata={"mac": "aa:bb:cc:dd:ee:01"},
        ),
        ThreatFinding(
            detector="cleartext",
            severity="low",
            title="Cleartext Credentials",
            description="FTP USER command detected",
            source_ip="10.0.0.40",
            dest_ip="10.0.0.2",
        ),
        ThreatFinding(
            detector="icmp_anomaly",
            severity="info",
            title="Oversized ICMP Packets",
            description="5 oversized ICMP packets",
        ),
    ]


# ── JSON Export Tests ────────────────────────────────────────────────


class TestExportJson:
    """Tests for export_json()."""

    def test_produces_valid_json_with_all_keys(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        findings = _make_findings()
        out_dir = tmp_path / "report_out"

        json_path = export_json(result, findings, out_dir)

        assert json_path.exists()
        data = json.loads(json_path.read_text())

        expected_keys = {
            "wirenose_version",
            "generated_at",
            "capture",
            "stats",
            "findings",
            "finding_summary",
        }
        assert set(data.keys()) == expected_keys

    def test_capture_section_correct(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path, packet_count=10, total_bytes=5000)
        json_path = export_json(result, [], tmp_path / "out")
        data = json.loads(json_path.read_text())

        capture = data["capture"]
        assert capture["packet_count"] == 10
        assert capture["total_bytes"] == 5000
        assert capture["interface"] is None
        assert capture["bpf_filter"] is None
        assert "test.pcap" in capture["source"]

    def test_finding_summary_by_severity_matches(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        findings = _make_findings()
        json_path = export_json(result, findings, tmp_path / "out")
        data = json.loads(json_path.read_text())

        summary = data["finding_summary"]
        assert summary["total"] == 5
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_severity"]["low"] == 1
        assert summary["by_severity"]["info"] == 1

    def test_zero_findings(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        json_path = export_json(result, [], tmp_path / "out")
        data = json.loads(json_path.read_text())

        assert data["findings"] == []
        assert data["finding_summary"]["total"] == 0
        for count in data["finding_summary"]["by_severity"].values():
            assert count == 0

    def test_datetime_serialization(self, tmp_path: Path) -> None:
        """Datetimes must be ISO-8601 strings, not raw datetime objects."""
        result = _make_result(tmp_path)
        findings = [
            ThreatFinding(
                detector="test",
                severity="info",
                title="Test",
                description="With timestamp",
                timestamp=datetime(2026, 4, 1, 12, 0, 0),
            ),
        ]
        json_path = export_json(result, findings, tmp_path / "out")
        data = json.loads(json_path.read_text())

        # capture times
        assert isinstance(data["capture"]["start_time"], str)
        assert "2026-04-01" in data["capture"]["start_time"]

        # finding timestamp
        assert isinstance(data["findings"][0]["timestamp"], str)
        assert "2026-04-01" in data["findings"][0]["timestamp"]

    def test_none_values_handled(self, tmp_path: Path) -> None:
        """interface=None, finding.source_ip=None should serialize as JSON null."""
        result = _make_result(tmp_path, interface=None)
        findings = [
            ThreatFinding(
                detector="test",
                severity="info",
                title="Test",
                description="Null fields",
                source_ip=None,
                dest_ip=None,
                timestamp=None,
            ),
        ]
        json_path = export_json(result, findings, tmp_path / "out")
        data = json.loads(json_path.read_text())

        assert data["capture"]["interface"] is None
        assert data["findings"][0]["source_ip"] is None
        assert data["findings"][0]["dest_ip"] is None
        assert data["findings"][0]["timestamp"] is None

    def test_stats_section_has_protocol_counts_and_ips(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        json_path = export_json(result, [], tmp_path / "out")
        data = json.loads(json_path.read_text())

        stats = data["stats"]
        assert "protocol_counts" in stats
        assert stats["protocol_counts"]["TCP"] == 7
        assert "top_src_ips" in stats
        assert "top_dst_ips" in stats
        # top_src_ips is a list of [ip, count] pairs
        assert len(stats["top_src_ips"]) == 3

    def test_wirenose_version_present(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        json_path = export_json(result, [], tmp_path / "out")
        data = json.loads(json_path.read_text())
        assert data["wirenose_version"] == "1.0.0"

    def test_generated_at_is_iso_string(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        json_path = export_json(result, [], tmp_path / "out")
        data = json.loads(json_path.read_text())
        # Should parse without error
        dt = datetime.fromisoformat(data["generated_at"])
        assert isinstance(dt, datetime)

    def test_output_dir_created_if_missing(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        deep_dir = tmp_path / "a" / "b" / "c"
        assert not deep_dir.exists()
        export_json(result, [], deep_dir)
        assert deep_dir.exists()

    def test_findings_with_all_severity_levels(self, tmp_path: Path) -> None:
        """All five severity levels are represented in by_severity."""
        result = _make_result(tmp_path)
        findings = _make_findings()
        json_path = export_json(result, findings, tmp_path / "out")
        data = json.loads(json_path.read_text())

        expected_severities = {"critical", "high", "medium", "low", "info"}
        assert set(data["finding_summary"]["by_severity"].keys()) == expected_severities

    def test_findings_preserve_metadata(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path)
        findings = _make_findings()
        json_path = export_json(result, findings, tmp_path / "out")
        data = json.loads(json_path.read_text())

        port_scan = data["findings"][0]
        assert port_scan["metadata"]["ports_scanned"] == 25
        assert port_scan["packet_indices"] == [0, 1, 2]


# ── copy_pcap Tests ──────────────────────────────────────────────────


class TestCopyPcap:
    """Tests for copy_pcap()."""

    def test_copies_file_and_returns_path(self, tmp_path: Path) -> None:
        source = tmp_path / "original.pcap"
        source.write_bytes(b"pcap-data-here")
        out_dir = tmp_path / "output"

        dest = copy_pcap(source, out_dir)

        assert dest is not None
        assert dest.exists()
        assert dest.name == "original.pcap"
        assert dest.read_bytes() == b"pcap-data-here"

    def test_none_source_returns_none(self, tmp_path: Path) -> None:
        result = copy_pcap(None, tmp_path / "output")
        assert result is None

    def test_nonexistent_source_returns_none(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist.pcap"
        result = copy_pcap(missing, tmp_path / "output")
        assert result is None

    def test_output_dir_created_if_missing(self, tmp_path: Path) -> None:
        source = tmp_path / "test.pcap"
        source.write_bytes(b"data")
        deep_dir = tmp_path / "deep" / "nested" / "dir"

        copy_pcap(source, deep_dir)

        assert deep_dir.exists()

    def test_preserves_filename(self, tmp_path: Path) -> None:
        source = tmp_path / "my_capture_2026.pcap"
        source.write_bytes(b"data")
        out_dir = tmp_path / "out"

        dest = copy_pcap(source, out_dir)

        assert dest is not None
        assert dest.name == "my_capture_2026.pcap"

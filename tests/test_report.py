"""Tests for wirenose.report — chart generation and HTML report assembly."""

from __future__ import annotations

import base64
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.plist import PacketList

from wirenose.detectors.models import ThreatFinding
from wirenose.models import CaptureMetadata, CaptureResult, PacketStats
from wirenose.report import (
    _build_html,
    _chart_alert_timeline,
    _chart_protocol_distribution,
    _chart_top_talkers,
    _chart_traffic_volume,
    generate_report,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_metadata(
    *,
    pcap_path: Path | None = None,
    interface: str | None = None,
    packet_count: int = 10,
) -> CaptureMetadata:
    return CaptureMetadata(
        interface=interface,
        bpf_filter=None,
        start_time=datetime(2026, 4, 1, 12, 0, 0),
        end_time=datetime(2026, 4, 1, 12, 5, 0),
        packet_count=packet_count,
        pcap_path=pcap_path,
    )


def _make_stats(
    *,
    packet_count: int = 10,
    total_bytes: int = 5000,
) -> PacketStats:
    return PacketStats(
        protocol_counts=Counter({"TCP": 7, "UDP": 2, "ICMP": 1}),
        src_ips=Counter({"10.0.0.1": 5, "10.0.0.2": 3, "10.0.0.3": 2}),
        dst_ips=Counter({"10.0.0.4": 6, "10.0.0.5": 4}),
        total_bytes=total_bytes,
        packet_count=packet_count,
    )


def _make_result(tmp_path: Path, *, packets: PacketList | None = None) -> CaptureResult:
    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"\x00" * 100)
    return CaptureResult(
        packets=packets,
        stats=_make_stats(),
        metadata=_make_metadata(pcap_path=pcap_path),
    )


def _make_packets() -> PacketList:
    """Build a small PacketList with varied timestamps."""
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.3") / TCP(sport=1235, dport=443),
        Ether() / IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=5000, dport=53),
        Ether() / IP(src="10.0.0.5", dst="10.0.0.6") / ICMP(),
    ]
    # Assign distinct timestamps (Scapy packets have pkt.time set by default;
    # we override to get a controllable spread)
    base_time = 1711972800.0  # 2024-04-01 12:00:00 UTC
    for i, pkt in enumerate(pkts):
        pkt.time = base_time + i * 10.0
    return PacketList(pkts)


def _make_findings() -> list[ThreatFinding]:
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
            timestamp=datetime(2026, 4, 1, 12, 2, 0),
        ),
        ThreatFinding(
            detector="arp_spoof",
            severity="medium",
            title="ARP Spoofing Detected",
            description="MAC claiming multiple IPs",
        ),
    ]


def _assert_valid_png_base64(b64_str: str) -> None:
    """Decode base64 and check PNG magic header."""
    assert b64_str, "Expected non-empty base64 string"
    raw = base64.b64decode(b64_str)
    assert raw[:4] == b"\x89PNG", f"Not a valid PNG: first 4 bytes = {raw[:4]!r}"


# ── Protocol Distribution Chart ──────────────────────────────────────


class TestChartProtocolDistribution:
    def test_returns_valid_base64_png(self) -> None:
        result = _chart_protocol_distribution({"TCP": 100, "UDP": 30, "ICMP": 5})
        _assert_valid_png_base64(result)

    def test_empty_dict_returns_empty_string(self) -> None:
        assert _chart_protocol_distribution({}) == ""

    def test_single_protocol(self) -> None:
        result = _chart_protocol_distribution({"TCP": 42})
        _assert_valid_png_base64(result)


# ── Traffic Volume Chart ─────────────────────────────────────────────


class TestChartTrafficVolume:
    def test_returns_valid_base64_png(self) -> None:
        pkts = _make_packets()
        result = _chart_traffic_volume(pkts)
        _assert_valid_png_base64(result)

    def test_none_packets_returns_empty(self) -> None:
        assert _chart_traffic_volume(None) == ""

    def test_empty_packetlist_returns_empty(self) -> None:
        assert _chart_traffic_volume(PacketList([])) == ""

    def test_all_same_timestamp(self) -> None:
        """Degenerate case: all packets have identical timestamps."""
        pkts = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP() for _ in range(5)]
        t = 1711972800.0
        for pkt in pkts:
            pkt.time = t
        result = _chart_traffic_volume(PacketList(pkts))
        _assert_valid_png_base64(result)


# ── Top Talkers Chart ────────────────────────────────────────────────


class TestChartTopTalkers:
    def test_returns_valid_base64_png(self) -> None:
        top_src = [("10.0.0.1", 50), ("10.0.0.2", 30)]
        top_dst = [("10.0.0.3", 40), ("10.0.0.4", 20)]
        result = _chart_top_talkers(top_src, top_dst)
        _assert_valid_png_base64(result)

    def test_empty_lists_returns_empty(self) -> None:
        assert _chart_top_talkers([], []) == ""

    def test_single_ip(self) -> None:
        result = _chart_top_talkers([("10.0.0.1", 10)], [])
        _assert_valid_png_base64(result)


# ── Alert Timeline Chart ─────────────────────────────────────────────


class TestChartAlertTimeline:
    def test_with_timestamped_findings(self) -> None:
        findings = _make_findings()
        result = _chart_alert_timeline(findings, None)
        _assert_valid_png_base64(result)

    def test_empty_findings_returns_empty(self) -> None:
        assert _chart_alert_timeline([], None) == ""

    def test_findings_with_none_timestamps_and_packet_indices(self) -> None:
        """Findings without timestamps fall back to packet_indices → packet.time."""
        pkts = _make_packets()
        findings = [
            ThreatFinding(
                detector="test",
                severity="high",
                title="Indexed Finding",
                description="Uses packet index",
                timestamp=None,
                packet_indices=[0, 1],
            ),
        ]
        result = _chart_alert_timeline(findings, pkts)
        _assert_valid_png_base64(result)

    def test_findings_with_none_timestamps_no_packets(self) -> None:
        """Findings with no timestamps and no packets → placeholder chart."""
        findings = [
            ThreatFinding(
                detector="test",
                severity="info",
                title="No Time",
                description="No timestamp data",
                timestamp=None,
                packet_indices=[],
            ),
        ]
        result = _chart_alert_timeline(findings, None)
        # Still produces a chart (placeholder)
        _assert_valid_png_base64(result)


# ── HTML Assembly ─────────────────────────────────────────────────────


class TestBuildHtml:
    def test_produces_valid_html_structure(self) -> None:
        meta = _make_metadata()
        stats = _make_stats()
        html = _build_html(meta, stats, [], {}, {})
        assert "<html" in html
        assert "</html>" in html
        assert "WireNose" in html

    def test_contains_all_sections(self) -> None:
        meta = _make_metadata()
        stats = _make_stats()
        findings = _make_findings()
        charts = {"protocol_distribution": "dGVzdA=="}  # dummy base64
        html = _build_html(meta, stats, findings, charts, {})
        assert "Capture Metadata" in html
        assert "Finding Summary" in html
        assert "Threat Findings" in html
        assert "Charts" in html

    def test_chart_img_tags_with_base64_src(self) -> None:
        meta = _make_metadata()
        stats = _make_stats()
        charts = {"protocol_distribution": "AAAA", "traffic_volume": "BBBB"}
        html = _build_html(meta, stats, [], charts, {})
        assert 'data:image/png;base64,AAAA' in html
        assert 'data:image/png;base64,BBBB' in html

    def test_no_external_references(self) -> None:
        """HTML must be self-contained — no external CSS, JS, or image links."""
        meta = _make_metadata()
        stats = _make_stats()
        html = _build_html(meta, stats, [], {}, {})
        assert "<link" not in html.lower()
        assert '<script src=' not in html.lower()

    def test_findings_appear_in_table(self) -> None:
        meta = _make_metadata()
        stats = _make_stats()
        findings = _make_findings()
        html = _build_html(meta, stats, findings, {}, {})
        assert "Port Scan Detected" in html
        assert "SYN Flood Detected" in html
        assert "port_scan" in html

    def test_severity_badges_present(self) -> None:
        meta = _make_metadata()
        stats = _make_stats()
        findings = _make_findings()
        html = _build_html(meta, stats, findings, {}, {})
        assert "badge-critical" in html
        assert "badge-high" in html


# ── generate_report Integration Tests ─────────────────────────────────


class TestGenerateReport:
    def test_writes_html_and_returns_path(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path, packets=_make_packets())
        findings = _make_findings()
        out_dir = tmp_path / "report_out"

        report_path = generate_report(result, findings, out_dir)

        assert report_path.exists()
        assert report_path.name == "report.html"
        assert report_path.parent == out_dir

        html = report_path.read_text()
        assert "<html" in html
        assert "</html>" in html

    def test_zero_findings_produces_valid_html(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path, packets=_make_packets())
        report_path = generate_report(result, [], tmp_path / "out")

        html = report_path.read_text()
        assert "<html" in html
        assert "No threats detected" in html

    def test_html_contains_finding_text(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path, packets=_make_packets())
        findings = _make_findings()
        report_path = generate_report(result, findings, tmp_path / "out")

        html = report_path.read_text()
        assert "Port Scan Detected" in html
        assert "25 unique ports scanned" in html
        assert "SYN Flood Detected" in html

    def test_html_self_contained(self, tmp_path: Path) -> None:
        """No external stylesheet/script references."""
        result = _make_result(tmp_path, packets=_make_packets())
        report_path = generate_report(result, _make_findings(), tmp_path / "out")

        html = report_path.read_text()
        assert "<link" not in html.lower()
        assert '<script src=' not in html.lower()

    def test_html_contains_chart_images(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path, packets=_make_packets())
        report_path = generate_report(result, _make_findings(), tmp_path / "out")

        html = report_path.read_text()
        assert "data:image/png;base64," in html

    def test_output_dir_created_if_missing(self, tmp_path: Path) -> None:
        result = _make_result(tmp_path, packets=_make_packets())
        deep = tmp_path / "a" / "b" / "c"
        generate_report(result, [], deep)
        assert deep.exists()

    def test_no_packets_produces_valid_html(self, tmp_path: Path) -> None:
        """Packets=None should not crash — charts degrade gracefully."""
        result = _make_result(tmp_path, packets=None)
        report_path = generate_report(result, [], tmp_path / "out")

        html = report_path.read_text()
        assert "<html" in html
        assert "</html>" in html

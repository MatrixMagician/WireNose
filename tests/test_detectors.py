"""Tests for threat detection engine, model, and network-layer detectors."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.plist import PacketList

from wirenose.detectors import (
    SEVERITY_ORDER,
    ThreatEngine,
    ThreatFinding,
    detect_arp_spoof,
    detect_port_scan,
    detect_syn_flood,
)


# ---------------------------------------------------------------------------
# Packet helpers
# ---------------------------------------------------------------------------

def _make_tcp_syn(src: str, dst: str, dport: int) -> Ether:
    """Build a TCP SYN packet (SYN set, ACK not set)."""
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport, flags="S")


def _make_tcp_synack(src: str, dst: str, dport: int) -> Ether:
    """Build a TCP SYN-ACK packet (SYN and ACK set)."""
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport, flags="SA")


def _make_arp_reply(mac: str, ip: str) -> Ether:
    """Build an ARP reply with given MAC and IP."""
    return Ether(src=mac) / ARP(op=2, hwsrc=mac, psrc=ip)


# ---------------------------------------------------------------------------
# ThreatFinding model
# ---------------------------------------------------------------------------

class TestThreatFinding:
    """ThreatFinding dataclass basics."""

    def test_default_fields(self):
        f = ThreatFinding(
            detector="test", severity="info", title="T", description="D",
        )
        assert f.source_ip is None
        assert f.dest_ip is None
        assert f.metadata == {}
        assert f.timestamp is None
        assert f.packet_indices == []

    def test_severity_order_completeness(self):
        expected = {"critical", "high", "medium", "low", "info"}
        assert set(SEVERITY_ORDER.keys()) == expected
        # critical is the lowest number (first in sort)
        assert SEVERITY_ORDER["critical"] < SEVERITY_ORDER["info"]


# ---------------------------------------------------------------------------
# Port scan detector
# ---------------------------------------------------------------------------

class TestPortScanDetector:
    """Tests for detect_port_scan."""

    def test_detects_scan_above_threshold(self):
        """25 unique ports from one source → finding returned."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.1", "10.0.0.2", dport=port)
            for port in range(1, 26)
        ])
        findings = detect_port_scan(pkts)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].source_ip == "10.0.0.1"
        assert "25" in findings[0].description
        assert findings[0].detector == "port_scan"
        # All 25 packets should be indexed
        assert len(findings[0].packet_indices) == 25

    def test_no_finding_below_threshold(self):
        """5 unique ports → no finding."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.1", "10.0.0.2", dport=port)
            for port in range(1, 6)
        ])
        findings = detect_port_scan(pkts)
        assert findings == []

    def test_custom_threshold(self):
        """Threshold from config is respected."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.1", "10.0.0.2", dport=port)
            for port in range(1, 6)
        ])
        findings = detect_port_scan(pkts, config={"port_scan_threshold": 3})
        assert len(findings) == 1

    def test_boundary_at_threshold_no_trigger(self):
        """Exactly 20 ports (default threshold) should NOT trigger."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.1", "10.0.0.2", dport=port)
            for port in range(1, 21)  # 20 ports
        ])
        findings = detect_port_scan(pkts)
        assert findings == []

    def test_boundary_above_threshold_triggers(self):
        """21 ports should trigger (> 20)."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.1", "10.0.0.2", dport=port)
            for port in range(1, 22)  # 21 ports
        ])
        findings = detect_port_scan(pkts)
        assert len(findings) == 1

    def test_empty_packetlist(self):
        findings = detect_port_scan(PacketList())
        assert findings == []


# ---------------------------------------------------------------------------
# SYN flood detector
# ---------------------------------------------------------------------------

class TestSynFloodDetector:
    """Tests for detect_syn_flood."""

    def test_detects_flood_above_threshold(self):
        """150 SYN packets from one source → finding."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.99", "10.0.0.1", dport=80)
            for _ in range(150)
        ])
        findings = detect_syn_flood(pkts)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].source_ip == "10.0.0.99"
        assert "150" in findings[0].description
        assert findings[0].detector == "syn_flood"

    def test_no_finding_below_threshold(self):
        """10 SYN packets → no finding."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.99", "10.0.0.1", dport=80)
            for _ in range(10)
        ])
        findings = detect_syn_flood(pkts)
        assert findings == []

    def test_synack_not_counted(self):
        """SYN-ACK packets should not count as SYN-only."""
        pkts = PacketList([
            _make_tcp_synack("10.0.0.99", "10.0.0.1", dport=80)
            for _ in range(200)
        ])
        findings = detect_syn_flood(pkts)
        assert findings == []

    def test_custom_threshold(self):
        pkts = PacketList([
            _make_tcp_syn("10.0.0.99", "10.0.0.1", dport=80)
            for _ in range(15)
        ])
        findings = detect_syn_flood(pkts, config={"syn_flood_threshold": 10})
        assert len(findings) == 1

    def test_boundary_at_threshold_no_trigger(self):
        """Exactly 100 SYNs (default threshold) should NOT trigger."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.99", "10.0.0.1", dport=80)
            for _ in range(100)
        ])
        findings = detect_syn_flood(pkts)
        assert findings == []

    def test_boundary_above_threshold_triggers(self):
        """101 SYNs should trigger (> 100)."""
        pkts = PacketList([
            _make_tcp_syn("10.0.0.99", "10.0.0.1", dport=80)
            for _ in range(101)
        ])
        findings = detect_syn_flood(pkts)
        assert len(findings) == 1

    def test_empty_packetlist(self):
        findings = detect_syn_flood(PacketList())
        assert findings == []


# ---------------------------------------------------------------------------
# ARP spoof detector
# ---------------------------------------------------------------------------

class TestArpSpoofDetector:
    """Tests for detect_arp_spoof."""

    def test_detects_mac_claiming_multiple_ips(self):
        """One MAC claiming 2 IPs → finding."""
        pkts = PacketList([
            _make_arp_reply("aa:bb:cc:dd:ee:01", "10.0.0.1"),
            _make_arp_reply("aa:bb:cc:dd:ee:01", "10.0.0.2"),
        ])
        findings = detect_arp_spoof(pkts)
        assert len(findings) >= 1
        mac_findings = [f for f in findings if "MAC" in f.description and "multiple IPs" in f.description]
        assert len(mac_findings) == 1
        assert mac_findings[0].severity == "critical"

    def test_detects_ip_with_multiple_macs(self):
        """One IP associated with 2 MACs → finding."""
        pkts = PacketList([
            _make_arp_reply("aa:bb:cc:dd:ee:01", "10.0.0.1"),
            _make_arp_reply("aa:bb:cc:dd:ee:02", "10.0.0.1"),
        ])
        findings = detect_arp_spoof(pkts)
        ip_findings = [f for f in findings if "IP" in f.description and "multiple MACs" in f.description]
        assert len(ip_findings) == 1
        assert ip_findings[0].severity == "critical"

    def test_normal_arp_no_finding(self):
        """Unique MAC↔IP mappings → no finding."""
        pkts = PacketList([
            _make_arp_reply("aa:bb:cc:dd:ee:01", "10.0.0.1"),
            _make_arp_reply("aa:bb:cc:dd:ee:02", "10.0.0.2"),
        ])
        findings = detect_arp_spoof(pkts)
        assert findings == []

    def test_arp_request_ignored(self):
        """ARP requests (op=1) should be ignored, only replies analysed."""
        # Default ARP op is 1 (request)
        pkts = PacketList([
            Ether() / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.1"),
            Ether() / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="10.0.0.2"),
        ])
        findings = detect_arp_spoof(pkts)
        assert findings == []

    def test_empty_packetlist(self):
        findings = detect_arp_spoof(PacketList())
        assert findings == []


# ---------------------------------------------------------------------------
# ThreatEngine
# ---------------------------------------------------------------------------

class TestThreatEngine:
    """Tests for the ThreatEngine orchestrator."""

    def test_analyze_mixed_threats_sorted(self):
        """Engine with mixed traffic returns findings from all detectors, sorted by severity."""
        pkts_list = []

        # Port scan: 25 unique ports from one source
        for port in range(1, 26):
            pkts_list.append(_make_tcp_syn("10.1.1.1", "10.2.2.2", dport=port))

        # SYN flood: 110 SYNs from another source
        for _ in range(110):
            pkts_list.append(_make_tcp_syn("10.3.3.3", "10.4.4.4", dport=80))

        # ARP spoof: one MAC, two IPs
        pkts_list.append(_make_arp_reply("aa:bb:cc:dd:ee:ff", "10.5.5.5"))
        pkts_list.append(_make_arp_reply("aa:bb:cc:dd:ee:ff", "10.6.6.6"))

        engine = ThreatEngine()
        findings = engine.analyze(PacketList(pkts_list))

        assert len(findings) >= 3
        # Critical findings (SYN flood, ARP) should come before high (port scan)
        severities = [f.severity for f in findings]
        assert severities[0] == "critical"
        # Port scan (high) should come after all criticals
        high_indices = [i for i, s in enumerate(severities) if s == "high"]
        crit_indices = [i for i, s in enumerate(severities) if s == "critical"]
        if high_indices and crit_indices:
            assert min(high_indices) > max(crit_indices)

    def test_analyze_empty_packetlist(self):
        engine = ThreatEngine()
        findings = engine.analyze(PacketList())
        assert findings == []

    def test_detector_exception_does_not_block_others(self):
        """A detector that raises should be skipped; others still run."""
        engine = ThreatEngine()

        def _bad_detector(packets, config):
            raise RuntimeError("I always fail")

        # Prepend the bad detector so it runs first
        engine._detectors.insert(0, _bad_detector)

        # Build traffic that triggers port scan
        pkts = PacketList([
            _make_tcp_syn("10.0.0.1", "10.0.0.2", dport=port)
            for port in range(1, 26)
        ])

        findings = engine.analyze(pkts)
        # The good detectors should still produce findings
        assert len(findings) >= 1
        assert any(f.detector == "port_scan" for f in findings)

    def test_config_passed_to_detectors(self):
        """Config dict is forwarded to each detector."""
        engine = ThreatEngine()
        pkts = PacketList([
            _make_tcp_syn("10.0.0.1", "10.0.0.2", dport=port)
            for port in range(1, 6)
        ])
        # Default threshold (20) → no finding
        assert engine.analyze(pkts) == []

        # Override threshold → finding
        findings = engine.analyze(pkts, config={"port_scan_threshold": 3})
        assert len(findings) >= 1

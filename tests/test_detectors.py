"""Tests for threat detection engine, model, and network-layer detectors."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.plist import PacketList

from wirenose.detectors import (
    SEVERITY_ORDER,
    ThreatEngine,
    ThreatFinding,
    detect_arp_spoof,
    detect_cleartext_creds,
    detect_dns_tunnel,
    detect_icmp_anomaly,
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

    def test_engine_registers_all_six_detectors(self):
        """ThreatEngine registers all 6 built-in detectors."""
        engine = ThreatEngine()
        names = [getattr(d, "__name__", "") for d in engine._detectors]
        assert "detect_port_scan" in names
        assert "detect_syn_flood" in names
        assert "detect_arp_spoof" in names
        assert "detect_dns_tunnel" in names
        assert "detect_icmp_anomaly" in names
        assert "detect_cleartext_creds" in names


# ---------------------------------------------------------------------------
# DNS tunnel detector helpers
# ---------------------------------------------------------------------------

def _make_dns_query(qname: str | bytes, qtype: int = 1) -> Ether:
    """Build a DNS query packet with the given qname and qtype."""
    if isinstance(qname, str):
        qname = qname.encode() + b"."
    return (
        Ether()
        / IP(src="10.0.0.1", dst="8.8.8.8")
        / TCP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )


# ---------------------------------------------------------------------------
# DNS tunnel detector
# ---------------------------------------------------------------------------

class TestDnsTunnelDetector:
    """Tests for detect_dns_tunnel."""

    def test_long_subdomain_label_triggers(self):
        """A label with 31 chars (> default 30) → finding."""
        long_label = "a" * 31
        qname = f"{long_label}.evil.com"
        pkts = PacketList([_make_dns_query(qname)])
        findings = detect_dns_tunnel(pkts)
        label_findings = [f for f in findings if "Long Subdomain" in f.title]
        assert len(label_findings) == 1
        assert label_findings[0].severity == "high"
        assert label_findings[0].detector == "dns_tunnel"

    def test_label_at_boundary_no_trigger(self):
        """A label of exactly 30 chars (== default max) should NOT trigger."""
        label = "a" * 30
        qname = f"{label}.example.com"
        pkts = PacketList([_make_dns_query(qname)])
        findings = detect_dns_tunnel(pkts)
        label_findings = [f for f in findings if "Long Subdomain" in f.title]
        assert label_findings == []

    def test_normal_dns_no_finding(self):
        """Standard queries to well-known domains → no findings."""
        pkts = PacketList([
            _make_dns_query("www.google.com"),
            _make_dns_query("api.github.com"),
        ])
        findings = detect_dns_tunnel(pkts)
        assert findings == []

    def test_high_query_volume_triggers(self):
        """More than 20 queries to the same base domain → finding."""
        pkts = PacketList([
            _make_dns_query(f"sub{i}.evil.com")
            for i in range(25)
        ])
        findings = detect_dns_tunnel(pkts)
        vol_findings = [f for f in findings if "High Query Volume" in f.title]
        assert len(vol_findings) == 1
        assert vol_findings[0].severity == "medium"

    def test_query_volume_at_threshold_no_trigger(self):
        """Exactly 20 queries (== threshold) should NOT trigger."""
        pkts = PacketList([
            _make_dns_query(f"sub{i}.evil.com")
            for i in range(20)
        ])
        findings = detect_dns_tunnel(pkts)
        vol_findings = [f for f in findings if "High Query Volume" in f.title]
        assert vol_findings == []

    def test_suspicious_record_type_txt(self):
        """TXT query (qtype=16) → suspicious record type finding."""
        pkts = PacketList([_make_dns_query("tunnel.evil.com", qtype=16)])
        findings = detect_dns_tunnel(pkts)
        type_findings = [f for f in findings if "Suspicious Record" in f.title]
        assert len(type_findings) == 1
        assert "TXT" in type_findings[0].description

    def test_custom_label_threshold(self):
        """Config override for dns_label_max_length."""
        label = "a" * 11
        qname = f"{label}.evil.com"
        pkts = PacketList([_make_dns_query(qname)])
        # Default (30) → no trigger
        assert detect_dns_tunnel(pkts) == [] or not any(
            "Long Subdomain" in f.title for f in detect_dns_tunnel(pkts)
        )
        # Override to 10 → trigger
        findings = detect_dns_tunnel(pkts, config={"dns_label_max_length": 10})
        label_findings = [f for f in findings if "Long Subdomain" in f.title]
        assert len(label_findings) == 1

    def test_malformed_qname_handled(self):
        """DNS packet with non-UTF8 qname bytes → handled gracefully."""
        pkts = PacketList([_make_dns_query(b"\xff\xfe\x80.evil.com.")])
        # Should not raise
        findings = detect_dns_tunnel(pkts)
        assert isinstance(findings, list)

    def test_empty_packetlist(self):
        findings = detect_dns_tunnel(PacketList())
        assert findings == []


# ---------------------------------------------------------------------------
# ICMP anomaly detector helpers
# ---------------------------------------------------------------------------

def _make_icmp(src: str = "10.0.0.1", size: int = 64) -> Ether:
    """Build an ICMP echo request packet of approximately *size* bytes.

    We pad the Raw layer to reach the desired total packet length.
    The Ether(14) + IP(20) + ICMP(8) headers consume 42 bytes minimum.
    """
    header_overhead = 42  # Ether + IP + ICMP
    pad = max(0, size - header_overhead)
    return Ether() / IP(src=src, dst="10.0.0.2") / ICMP() / Raw(load=b"\x00" * pad)


# ---------------------------------------------------------------------------
# ICMP anomaly detector
# ---------------------------------------------------------------------------

class TestIcmpAnomalyDetector:
    """Tests for detect_icmp_anomaly."""

    def test_oversized_icmp_triggers(self):
        """ICMP packet > 800 bytes → finding."""
        pkt = _make_icmp(size=801)
        pkts = PacketList([pkt])
        findings = detect_icmp_anomaly(pkts)
        oversize = [f for f in findings if "Oversized" in f.title]
        assert len(oversize) == 1
        assert oversize[0].severity == "medium"
        assert oversize[0].detector == "icmp_anomaly"

    def test_icmp_at_threshold_no_trigger(self):
        """ICMP packet of exactly 800 bytes should NOT trigger."""
        pkt = _make_icmp(size=800)
        pkts = PacketList([pkt])
        findings = detect_icmp_anomaly(pkts)
        oversize = [f for f in findings if "Oversized" in f.title]
        assert oversize == []

    def test_normal_ping_no_finding(self):
        """Standard 64-byte ping → no findings."""
        pkts = PacketList([_make_icmp(size=64)])
        findings = detect_icmp_anomaly(pkts)
        assert findings == []

    def test_icmp_flood_triggers(self):
        """51 ICMP packets from one source (> default 50) → flood finding."""
        pkts = PacketList([_make_icmp(src="10.9.9.9") for _ in range(51)])
        findings = detect_icmp_anomaly(pkts)
        flood = [f for f in findings if "Flood" in f.title]
        assert len(flood) == 1
        assert flood[0].severity == "high"
        assert flood[0].source_ip == "10.9.9.9"

    def test_icmp_flood_at_threshold_no_trigger(self):
        """Exactly 50 ICMP packets (== threshold) should NOT trigger flood."""
        pkts = PacketList([_make_icmp(src="10.9.9.9") for _ in range(50)])
        findings = detect_icmp_anomaly(pkts)
        flood = [f for f in findings if "Flood" in f.title]
        assert flood == []

    def test_custom_size_threshold(self):
        """Config override for icmp_size_threshold."""
        pkt = _make_icmp(size=201)
        pkts = PacketList([pkt])
        findings = detect_icmp_anomaly(pkts, config={"icmp_size_threshold": 200})
        oversize = [f for f in findings if "Oversized" in f.title]
        assert len(oversize) == 1

    def test_empty_packetlist(self):
        findings = detect_icmp_anomaly(PacketList())
        assert findings == []


# ---------------------------------------------------------------------------
# Cleartext credentials detector helpers
# ---------------------------------------------------------------------------

def _make_tcp_with_payload(
    src: str, dst: str, dport: int, payload: bytes,
) -> Ether:
    """Build a TCP packet with a Raw payload."""
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport) / Raw(load=payload)


# ---------------------------------------------------------------------------
# Cleartext credentials detector
# ---------------------------------------------------------------------------

class TestCleartextCredsDetector:
    """Tests for detect_cleartext_creds."""

    def test_ftp_user_command(self):
        """FTP USER command on port 21 → critical finding."""
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 21, b"USER admin\r\n",
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert len(findings) >= 1
        assert findings[0].severity == "critical"
        assert findings[0].detector == "cleartext_creds"
        assert "FTP" in findings[0].title or "FTP" in findings[0].description

    def test_ftp_pass_command(self):
        """FTP PASS command on port 21 → critical finding."""
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 21, b"PASS secretpassword123\r\n",
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert len(findings) >= 1
        assert findings[0].severity == "critical"

    def test_http_basic_auth_raw(self):
        """HTTP Basic Auth header in raw payload → critical finding."""
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 8080,
            b"GET /api HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert len(findings) >= 1
        assert findings[0].severity == "critical"
        assert "Basic Auth" in findings[0].title

    def test_smtp_auth_command(self):
        """SMTP AUTH LOGIN on port 25 → critical finding."""
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 25, b"AUTH LOGIN\r\n",
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert len(findings) >= 1
        assert findings[0].severity == "critical"

    def test_pop3_user_command(self):
        """POP3 USER command on port 110 → critical finding."""
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 110, b"USER mailuser\r\n",
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert len(findings) >= 1
        assert findings[0].severity == "critical"

    def test_telnet_traffic(self):
        """Any payload on port 23 → critical finding."""
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 23, b"root\r\n",
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert len(findings) >= 1
        assert "Telnet" in findings[0].title

    def test_credential_truncation(self):
        """Credential values longer than 20 chars are truncated in description."""
        long_cred = "A" * 40
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 21,
            f"USER {long_cred}\r\n".encode(),
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert len(findings) >= 1
        # The full 40-char value should not appear; truncated version should
        assert long_cred not in findings[0].description
        assert "…" in findings[0].description

    def test_encrypted_traffic_no_finding(self):
        """TCP traffic on port 443 without credential patterns → no finding."""
        pkt = _make_tcp_with_payload(
            "10.0.0.1", "10.0.0.2", 443, b"\x16\x03\x01\x00\x05",
        )
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert findings == []

    def test_missing_raw_layer_no_crash(self):
        """TCP packet without Raw layer on FTP port → no crash, no finding."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=21)
        pkts = PacketList([pkt])
        findings = detect_cleartext_creds(pkts)
        assert findings == []

    def test_empty_packetlist(self):
        findings = detect_cleartext_creds(PacketList())
        assert findings == []

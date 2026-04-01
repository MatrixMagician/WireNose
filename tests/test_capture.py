"""Tests for wirenose.capture — CaptureEngine pcap I/O and error handling."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from wirenose.capture import CaptureEngine
from wirenose.errors import CapturePermissionError, InvalidFilterError


# ---------------------------------------------------------------------------
# read_pcap tests
# ---------------------------------------------------------------------------


class TestReadPcap:
    """Tests for CaptureEngine.read_pcap()."""

    def test_read_pcap_returns_correct_stats(self, sample_pcap: Path) -> None:
        """Read the fixture pcap and verify protocol counts, IP counts, byte total."""
        engine = CaptureEngine()
        result = engine.read_pcap(sample_pcap)

        # sample_pcap fixture: 3 TCP, 2 UDP, 1 ICMP, 1 ARP = 7 packets
        assert result.stats.packet_count == 7
        assert result.packets is not None
        assert len(result.packets) == 7

        # Protocol counts — TCP/UDP/ICMP each contribute an IP count too
        assert result.stats.protocol_counts["TCP"] == 3
        assert result.stats.protocol_counts["UDP"] == 2
        assert result.stats.protocol_counts["ICMP"] == 1
        assert result.stats.protocol_counts["ARP"] == 1
        assert result.stats.protocol_counts["IP"] == 6  # all except ARP

        # IP address counts
        assert result.stats.src_ips["10.0.0.1"] == 2  # 2 TCP packets
        assert result.stats.dst_ips["10.0.0.3"] == 2  # TCP + UDP

        # Total bytes > 0
        assert result.stats.total_bytes > 0

        # Metadata
        assert result.metadata.interface is None
        assert result.metadata.bpf_filter is None
        assert result.metadata.packet_count == 7
        assert result.metadata.pcap_path == sample_pcap

    def test_read_pcap_missing_file_raises(self) -> None:
        """Passing a nonexistent path should raise FileNotFoundError."""
        engine = CaptureEngine()
        with pytest.raises(FileNotFoundError, match="Pcap file not found"):
            engine.read_pcap(Path("/nonexistent/phantom.pcap"))


# ---------------------------------------------------------------------------
# write and read roundtrip
# ---------------------------------------------------------------------------


class TestWriteReadRoundtrip:
    """Verify pcap write → read roundtrip preserves stats."""

    def test_write_and_read_roundtrip(self, tmp_path: Path) -> None:
        """Write packets to pcap, read back, verify stats match."""
        packets = [
            Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1111, dport=80),
            Ether() / IP(src="192.168.1.3", dst="192.168.1.4") / UDP(sport=2222, dport=53),
            Ether() / IP(src="192.168.1.5", dst="192.168.1.6") / ICMP(),
        ]
        pcap_path = tmp_path / "roundtrip.pcap"
        wrpcap(str(pcap_path), packets)

        engine = CaptureEngine()
        result = engine.read_pcap(pcap_path)

        assert result.stats.packet_count == 3
        assert result.stats.protocol_counts["TCP"] == 1
        assert result.stats.protocol_counts["UDP"] == 1
        assert result.stats.protocol_counts["ICMP"] == 1
        assert result.stats.src_ips["192.168.1.1"] == 1
        assert result.stats.src_ips["192.168.1.3"] == 1
        assert result.stats.src_ips["192.168.1.5"] == 1


# ---------------------------------------------------------------------------
# Error handling (mocked sniff)
# ---------------------------------------------------------------------------


class TestCaptureErrors:
    """Tests for error handling in capture_live()."""

    @patch("wirenose.capture.sniff")
    def test_invalid_bpf_filter(self, mock_sniff) -> None:
        """Scapy_Exception from sniff() should raise InvalidFilterError."""
        mock_sniff.side_effect = Scapy_Exception("bad filter expression")

        engine = CaptureEngine()
        with pytest.raises(InvalidFilterError, match="Invalid BPF filter: 'bogus'"):
            engine.capture_live(iface="lo", bpf_filter="bogus", count=10)

    @patch("wirenose.capture.sniff")
    def test_permission_error_handling(self, mock_sniff) -> None:
        """PermissionError from sniff() should raise CapturePermissionError."""
        mock_sniff.side_effect = PermissionError("Operation not permitted")

        engine = CaptureEngine()
        with pytest.raises(CapturePermissionError, match="Permission denied capturing on 'eth0'"):
            engine.capture_live(iface="eth0", count=10)

    @patch("wirenose.capture.sniff")
    def test_scapy_exception_without_filter_reraises(self, mock_sniff) -> None:
        """Scapy_Exception without a BPF filter should re-raise as-is."""
        mock_sniff.side_effect = Scapy_Exception("some other scapy error")

        engine = CaptureEngine()
        with pytest.raises(Scapy_Exception, match="some other scapy error"):
            engine.capture_live(iface="lo", count=10)


# ---------------------------------------------------------------------------
# Packet callback direct testing
# ---------------------------------------------------------------------------


class TestPacketCallback:
    """Test _packet_callback directly for stats accumulation."""

    def test_packet_callback_accumulates_stats(self) -> None:
        """Directly calling _packet_callback with crafted packets should accumulate stats."""
        engine = CaptureEngine()

        tcp_pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=111, dport=222)
        udp_pkt = Ether() / IP(src="9.10.11.12", dst="13.14.15.16") / UDP(sport=333, dport=444)
        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="1.2.3.4")

        engine._packet_callback(tcp_pkt)
        engine._packet_callback(udp_pkt)
        engine._packet_callback(arp_pkt)

        assert engine._stats.packet_count == 3
        assert engine._stats.protocol_counts["TCP"] == 1
        assert engine._stats.protocol_counts["UDP"] == 1
        assert engine._stats.protocol_counts["ARP"] == 1
        assert engine._stats.src_ips["1.2.3.4"] == 1
        assert engine._stats.src_ips["9.10.11.12"] == 1
        assert engine._stats.total_bytes > 0

        # Packets stored in memory
        assert len(engine._packets) == 3

    def test_no_store_callback_accumulates_stats_only(self) -> None:
        """_packet_callback_no_store should update stats but not store packets."""
        engine = CaptureEngine()

        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()
        engine._packet_callback_no_store(pkt)

        assert engine._stats.packet_count == 1
        assert len(engine._packets) == 0


# ---------------------------------------------------------------------------
# capture_live defaults
# ---------------------------------------------------------------------------


class TestCaptureLiveDefaults:
    """Verify default parameter handling in capture_live()."""

    @patch("wirenose.capture.sniff")
    def test_defaults_count_100_when_no_count_no_timeout(self, mock_sniff) -> None:
        """When both count=0 and timeout=None, should default to count=100."""
        engine = CaptureEngine()
        engine.capture_live(iface="lo")

        call_kwargs = mock_sniff.call_args[1]
        assert call_kwargs["count"] == 100
        assert "timeout" not in call_kwargs

    @patch("wirenose.capture.sniff")
    def test_explicit_count_preserved(self, mock_sniff) -> None:
        """Explicit count should be passed through to sniff()."""
        engine = CaptureEngine()
        engine.capture_live(iface="lo", count=50)

        call_kwargs = mock_sniff.call_args[1]
        assert call_kwargs["count"] == 50

    @patch("wirenose.capture.sniff")
    def test_timeout_without_count_no_default(self, mock_sniff) -> None:
        """When timeout is specified but count=0, count should not be passed."""
        engine = CaptureEngine()
        engine.capture_live(iface="lo", timeout=5)

        call_kwargs = mock_sniff.call_args[1]
        assert "count" not in call_kwargs
        assert call_kwargs["timeout"] == 5

    @patch("wirenose.capture.sniff")
    def test_bpf_filter_passed_to_sniff(self, mock_sniff) -> None:
        """BPF filter should be forwarded to sniff()."""
        engine = CaptureEngine()
        engine.capture_live(iface="lo", bpf_filter="tcp port 80", count=10)

        call_kwargs = mock_sniff.call_args[1]
        assert call_kwargs["filter"] == "tcp port 80"

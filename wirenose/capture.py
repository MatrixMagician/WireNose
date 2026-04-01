"""Capture engine — live sniffing and pcap I/O wrapping Scapy."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS, DNSQR  # noqa: F401 — load dissectors for pcap reading
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.plist import PacketList
from scapy.sendrecv import sniff
from scapy.utils import rdpcap, wrpcap

from wirenose.errors import CapturePermissionError, InvalidFilterError
from wirenose.models import CaptureMetadata, CaptureResult, PacketStats

logger = logging.getLogger(__name__)


class CaptureEngine:
    """Core packet capture and pcap I/O engine.

    Wraps Scapy's sniff/rdpcap/wrpcap APIs. Accumulates per-packet
    statistics via a thread-safe PacketStats instance.
    """

    def __init__(self) -> None:
        self._stats = PacketStats()
        self._packets: list = []

    def _packet_callback(self, packet) -> None:  # noqa: ANN001 — Scapy Packet
        """Per-packet callback invoked by sniff(). Accumulates stats and stores packet."""
        self._stats.update(packet)
        self._packets.append(packet)

    def _packet_callback_no_store(self, packet) -> None:  # noqa: ANN001
        """Per-packet callback when store=False — stats only, no memory retention."""
        self._stats.update(packet)

    def capture_live(
        self,
        iface: str,
        bpf_filter: str | None = None,
        count: int = 0,
        timeout: int | None = None,
        output: Path | None = None,
        store: bool = True,
        stop_event: threading.Event | None = None,
    ) -> CaptureResult:
        """Capture packets from a live network interface.

        Args:
            iface: Network interface name (e.g. "lo", "eth0").
            bpf_filter: Optional BPF filter expression (e.g. "tcp port 80").
            count: Number of packets to capture. 0 means unlimited (but see below).
            timeout: Capture timeout in seconds. None means no timeout.
            output: Path to save captured packets as .pcap. Auto-generated if None.
            store: If False, packets aren't retained in memory — only stats accumulate.
            stop_event: Optional threading.Event for external stop signalling. When
                provided, sniff() is called in a retry loop with timeout=1 so the
                stop_filter gets checked even on quiet interfaces with no traffic.
                When None, behavior is unchanged (backward compatible).

        Returns:
            CaptureResult with packets (or None if store=False), stats, and metadata.

        Raises:
            CapturePermissionError: If libpcap denies access (needs sudo).
            InvalidFilterError: If the BPF filter is syntactically invalid.
        """
        # Reset state for this capture session
        self._stats = PacketStats()
        self._packets = []

        # Default to count=100 when neither count nor timeout is specified
        if count == 0 and timeout is None and stop_event is None:
            count = 100

        start_time = datetime.now(tz=timezone.utc)

        callback = self._packet_callback if store else self._packet_callback_no_store

        sniff_kwargs: dict = {
            "iface": iface,
            "prn": callback,
            "store": False,  # We handle storage ourselves via callback
        }
        if bpf_filter is not None:
            sniff_kwargs["filter"] = bpf_filter
        if count > 0:
            sniff_kwargs["count"] = count
        if timeout is not None:
            sniff_kwargs["timeout"] = timeout

        # When stop_event is provided, use stop_filter and a 1-second timeout
        # retry loop so the filter gets checked even on quiet interfaces.
        if stop_event is not None:
            sniff_kwargs["stop_filter"] = lambda pkt: stop_event.is_set()
            if timeout is None:
                sniff_kwargs["timeout"] = 1

        try:
            if stop_event is not None and timeout is None:
                # Retry loop: sniff with timeout=1 until stop_event is set or
                # count is reached. Without this, sniff() blocks forever on
                # quiet interfaces because stop_filter only fires per-packet.
                remaining = count if count > 0 else 0
                while True:
                    loop_kwargs = dict(sniff_kwargs)
                    if remaining > 0:
                        loop_kwargs["count"] = remaining
                    sniff(**loop_kwargs)
                    if stop_event.is_set():
                        break
                    if remaining > 0:
                        remaining = count - self._stats.packet_count
                        if remaining <= 0:
                            break
            else:
                sniff(**sniff_kwargs)
        except PermissionError as exc:
            raise CapturePermissionError(interface=iface, original=exc) from exc
        except Scapy_Exception as exc:
            # Scapy raises Scapy_Exception for invalid BPF filters
            if bpf_filter is not None:
                raise InvalidFilterError(bpf_filter=bpf_filter, original=exc) from exc
            raise  # Re-raise if it's not filter-related

        end_time = datetime.now(tz=timezone.utc)

        packets_list = PacketList(self._packets) if store and self._packets else None

        # Determine output path
        if output is None:
            output = Path(f"wirenose_{start_time.strftime('%Y%m%d_%H%M%S')}.pcap")

        # Write pcap if we have stored packets
        if packets_list is not None and len(packets_list) > 0:
            wrpcap(str(output), packets_list)
            logger.info("Saved %d packets to %s", len(packets_list), output)

        metadata = CaptureMetadata(
            interface=iface,
            bpf_filter=bpf_filter,
            start_time=start_time,
            end_time=end_time,
            packet_count=self._stats.packet_count,
            pcap_path=output,
        )

        return CaptureResult(
            packets=packets_list,
            stats=self._stats,
            metadata=metadata,
        )

    def read_pcap(self, path: Path) -> CaptureResult:
        """Read packets from a pcap file and accumulate stats.

        Args:
            path: Path to the .pcap file.

        Returns:
            CaptureResult with packets, stats, and metadata.

        Raises:
            FileNotFoundError: If the pcap file does not exist.
        """
        if not path.exists():
            raise FileNotFoundError(f"Pcap file not found: {path}")

        # Reset state
        self._stats = PacketStats()

        start_time = datetime.now(tz=timezone.utc)
        packets = rdpcap(str(path))

        for packet in packets:
            self._stats.update(packet)

        end_time = datetime.now(tz=timezone.utc)

        metadata = CaptureMetadata(
            interface=None,
            bpf_filter=None,
            start_time=start_time,
            end_time=end_time,
            packet_count=self._stats.packet_count,
            pcap_path=path,
        )

        return CaptureResult(
            packets=packets,
            stats=self._stats,
            metadata=metadata,
        )

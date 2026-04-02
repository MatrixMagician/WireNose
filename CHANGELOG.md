# Changelog

All notable changes to WireNose will be documented in this file.

## [1.0.0] — 2026-04-02

### 🎉 Initial Release

WireNose v1.0 — a Python CLI packet sniffer built for SOC analysts.

### Features

#### Packet Capture & Analysis
- **Live capture** from any network interface via Scapy with configurable packet count, timeout, and BPF filter expressions
- **Pcap file analysis** — read captures from tcpdump, Wireshark, or any standard pcap source
- **Traffic summary** — protocol distribution, top source/destination IPs, byte totals
- **Pcap export** — save captured traffic as .pcap for Wireshark deep-dive

#### Threat Detection (6 Detectors)
- **Port scan detection** — flags sources probing >20 unique destination ports
- **SYN flood detection** — flags >100 SYN-without-ACK packets per source
- **ARP spoofing detection** — identifies MAC↔IP address conflicts in ARP replies
- **DNS tunneling detection** — flags long subdomain labels (>30 chars), high query volume (>20/domain), and suspicious record types (TXT/NULL)
- **ICMP anomaly detection** — flags oversized packets (>800 bytes) and ICMP floods (>50/source)
- **Cleartext credential detection** — catches passwords in FTP, SMTP, POP3, Telnet, and HTTP Basic Auth

#### Live TUI Dashboard
- Real-time Rich terminal dashboard during capture
- Protocol breakdown, top source/destination IPs, bandwidth rate, elapsed time
- Live threat alert panel with severity-colored findings as detectors fire
- Graceful Ctrl+C shutdown preserving partial results

#### Reporting & Export
- **HTML reports** — self-contained with inline CSS and embedded traffic charts (protocol distribution, traffic volume over time, top talkers, alert timeline)
- **JSON export** — structured output with stable schema for SIEM ingestion
- **Pcap copy** — source pcap bundled alongside report for Wireshark analysis

#### Configuration & Usability
- **Zero-config** — works out of the box with sensible defaults for all thresholds
- **Optional YAML config** — tune detection thresholds, set interface defaults, BPF filters, and report settings
- **CLI merging** — command-line flags always override config file values
- **Privilege handling** — user-friendly error message when sudo is missing for live capture; pcap analysis works as normal user

### Technical Details
- Python 3.12+ with Scapy, Rich, matplotlib, PyYAML
- 198 passing tests across 8 test modules
- Thread-safe packet stats for concurrent capture + TUI rendering
- Per-detector error isolation — one failing detector never blocks the others
- Configurable detection thresholds via YAML config

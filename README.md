# 🐽 WireNose

A Python-based packet sniffer built for SOC analysts. Capture live network traffic or read existing pcap files, run rule-based threat detection, view a real-time terminal dashboard, and generate HTML reports with traffic visualizations.

## Features

- **Live packet capture** — sniff traffic from any network interface via Scapy
- **Pcap analysis** — read captures from tcpdump, Wireshark, or other tools
- **6 threat detectors** — port scans, SYN floods, ARP spoofing, DNS tunneling, ICMP anomalies, cleartext credentials
- **Real-time TUI dashboard** — Rich-based terminal UI with protocol breakdown, top talkers, bandwidth stats, and live threat alerts
- **HTML reports** — self-contained reports with severity-colored findings and embedded traffic charts
- **JSON export** — structured output for SIEM ingestion and automation
- **Pcap export** — copy captures alongside reports for Wireshark deep-dive
- **Zero-config** — works out of the box with sensible defaults; optional YAML config for tuning

## Requirements

- Python 3.12+
- Linux (primary), macOS/Windows support planned
- Root/sudo privileges for live capture (pcap analysis works as normal user)

## Installation

### From source (recommended)

```bash
# Clone the repository
git clone https://github.com/MatrixMagician/WireNose.git
cd WireNose

# Install with uv (recommended)
uv sync

# Or install with pip
pip install -e .
```

### Verify installation

```bash
wirenose --help
# or, if installed via uv:
uv run wirenose --help
```

## Quick Start

```bash
# Analyze an existing pcap file
wirenose analyze capture.pcap

# Capture 100 packets from eth0 (requires sudo)
sudo wirenose capture -i eth0

# Capture with live dashboard for 60 seconds
sudo wirenose capture -i eth0 -d 60

# Analyze and generate an HTML report
wirenose analyze capture.pcap --report -o ./output
```

## Usage

### Capture Live Traffic

Capture packets from a network interface. Requires root/sudo privileges.

```bash
sudo wirenose capture -i <interface> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--interface` | Network interface (e.g. `eth0`, `lo`, `wlan0`) | **required** |
| `-c`, `--count` | Number of packets to capture | `100` |
| `-d`, `--duration` | Capture timeout in seconds | unlimited |
| `-f`, `--filter` | BPF filter expression | none |
| `-o`, `--output` | Output pcap file path | auto-generated |
| `-C`, `--config` | Path to YAML config file | none |
| `--no-dashboard` | Disable the live TUI dashboard | dashboard on |

**Examples:**

```bash
# Capture 500 packets from eth0
sudo wirenose capture -i eth0 -c 500

# Capture HTTP traffic only for 30 seconds
sudo wirenose capture -i eth0 -f "tcp port 80" -d 30

# Capture to a specific file, no dashboard
sudo wirenose capture -i eth0 -o /tmp/capture.pcap --no-dashboard

# Capture with custom config
sudo wirenose capture -i eth0 -C config.yaml
```

Press **Ctrl+C** to stop capture gracefully at any time. Partial results are preserved.

### Analyze Pcap Files

Analyze an existing pcap file. No elevated privileges required.

```bash
wirenose analyze <pcap_file> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--report` | Generate HTML report, JSON export, and pcap copy | off |
| `-o`, `--output-dir` | Output directory for report files | current dir |
| `-C`, `--config` | Path to YAML config file for detection settings | none |

**Examples:**

```bash
# Print traffic summary and threat findings
wirenose analyze capture.pcap

# Generate a full report bundle
wirenose analyze capture.pcap --report -o ./report-output

# Analyze with custom detection thresholds
wirenose analyze capture.pcap --report -C config.yaml
```

When `--report` is used, the output directory will contain:

```
report-output/
├── report.html    # Self-contained HTML report with charts
├── report.json    # Structured JSON for SIEM ingestion
└── capture.pcap   # Copy of the source pcap
```

### Live Dashboard

When capturing on a TTY, WireNose displays a live Rich TUI dashboard showing:

- **Protocol distribution** — packet counts by protocol (TCP, UDP, ICMP, ARP, etc.)
- **Top source IPs** — most active source addresses
- **Top destination IPs** — most targeted addresses
- **Bandwidth stats** — packets/sec, bytes/sec, elapsed time
- **Threat alerts** — severity-colored findings as detectors fire in real-time

Disable with `--no-dashboard` for headless or scripted usage.

## Threat Detection

WireNose runs six rule-based detectors against captured traffic:

| Detector | What it finds | Default threshold |
|----------|--------------|-------------------|
| **Port Scan** | Single source probing many destination ports | >20 unique ports |
| **SYN Flood** | High volume of SYN packets without ACK | >100 SYN-only packets/src |
| **ARP Spoofing** | MAC↔IP address conflicts in ARP replies | any conflict |
| **DNS Tunneling** | Long subdomain labels, high query volume, suspicious record types | label >30 chars, >20 queries/domain |
| **ICMP Anomaly** | Oversized ICMP packets and ICMP floods | >800 bytes, >50 packets/src |
| **Cleartext Credentials** | Passwords in FTP, SMTP, POP3, Telnet, HTTP Basic Auth | any match |

Findings are sorted by severity: **critical** → **high** → **medium** → **low** → **info**.

All thresholds are configurable via YAML config file.

## Configuration

WireNose works without any configuration file. All settings have sensible defaults.

For tuning, create a YAML config file:

```yaml
# wirenose.yaml

# Capture defaults
interface: eth0
bpf_filter: "not port 22"
count: 500
timeout: 120
output_dir: ./captures

# Dashboard refresh rate (Hz)
dashboard_refresh_rate: 4.0

# Detection thresholds
detection:
  port_scan_threshold: 30        # unique dst ports to flag (default: 20)
  syn_flood_threshold: 200       # SYN-without-ACK count (default: 100)
  dns_label_length: 40           # max subdomain label length (default: 30)
  dns_query_threshold: 30        # queries per domain (default: 20)
  icmp_size_threshold: 1000      # ICMP packet size in bytes (default: 800)
  icmp_flood_threshold: 100      # ICMP packets per source (default: 50)

# Report settings (passed through to report generator)
report: {}
```

Use it with either subcommand:

```bash
sudo wirenose capture -i eth0 -C wirenose.yaml
wirenose analyze capture.pcap -C wirenose.yaml --report
```

CLI arguments always override config file values.

## Report Output

### HTML Report

The HTML report is fully self-contained (no external dependencies) and includes:

- **Capture metadata** — source file, duration, packet count
- **Traffic summary** — protocol distribution, top source/destination IPs, byte totals
- **Threat findings table** — severity-colored, with detector name, source/dest IPs, and descriptions
- **Traffic charts** (embedded as images):
  - Protocol distribution bar chart
  - Traffic volume over time line chart
  - Top talkers horizontal bar chart
  - Alert timeline scatter chart

### JSON Export

The JSON export provides a stable schema for SIEM integration:

```json
{
  "wirenose_version": "0.1.0",
  "generated_at": "2026-04-02T10:00:00Z",
  "capture": {
    "source": "capture.pcap",
    "duration_seconds": 60.0,
    "packet_count": 1500
  },
  "stats": {
    "protocol_counts": { "TCP": 800, "UDP": 500, "ICMP": 200 },
    "top_src_ips": { "10.0.0.1": 400, "10.0.0.2": 300 },
    "top_dst_ips": { "192.168.1.1": 600 }
  },
  "findings": [
    {
      "detector": "port_scan",
      "severity": "high",
      "title": "Port Scan Detected",
      "description": "Host 10.0.0.1 probed 25 unique destination ports",
      "source_ip": "10.0.0.1",
      "dest_ip": null,
      "timestamp": "2026-04-02T10:00:30Z"
    }
  ],
  "finding_summary": {
    "total": 5,
    "by_severity": { "critical": 1, "high": 2, "medium": 2 }
  }
}
```

## Development

```bash
# Clone and set up
git clone https://github.com/MatrixMagician/WireNose.git
cd WireNose
uv sync

# Run tests (198 tests)
uv run pytest tests/ -v

# Run a specific test file
uv run pytest tests/test_detectors.py -v

# Run the tool locally
uv run wirenose analyze tests/fixtures/threats.pcap
uv run wirenose analyze tests/fixtures/threats.pcap --report -o /tmp/report
```

### Project Structure

```
wirenose/
├── __init__.py          # Package version
├── __main__.py          # python -m wirenose entry point
├── capture.py           # CaptureEngine — live capture + pcap reading
├── cli.py               # argparse CLI — capture & analyze subcommands
├── config.py            # YAML config loading with dataclass defaults
├── dashboard.py         # Rich TUI dashboard with live threat alerts
├── errors.py            # Custom exceptions (CapturePermissionError, etc.)
├── export.py            # JSON export + pcap copy
├── models.py            # Core data model (CaptureResult, PacketStats, etc.)
├── output.py            # Console output formatting
├── report.py            # HTML report generation with matplotlib charts
└── detectors/
    ├── __init__.py      # Public API — ThreatEngine, ThreatFinding, all detectors
    ├── models.py        # ThreatFinding dataclass
    ├── engine.py        # ThreatEngine orchestrator
    ├── port_scan.py     # Port scan detector
    ├── syn_flood.py     # SYN flood detector
    ├── arp_spoof.py     # ARP spoof detector
    ├── dns_tunnel.py    # DNS tunneling detector
    ├── icmp_anomaly.py  # ICMP anomaly detector
    └── cleartext_creds.py  # Cleartext credentials detector

tests/
├── conftest.py          # Shared fixtures
├── test_capture.py      # Capture engine tests
├── test_cli.py          # CLI integration tests
├── test_config.py       # Configuration tests
├── test_dashboard.py    # Dashboard + alert panel tests
├── test_detectors.py    # All 6 detector unit tests
├── test_export.py       # JSON export + pcap copy tests
├── test_models.py       # Data model tests
├── test_report.py       # HTML report + chart tests
└── fixtures/
    ├── sample.pcap      # 10-packet mixed-protocol fixture
    ├── threats.pcap     # 168-packet fixture triggering all 6 detectors
    └── generate_fixtures.py  # Script to regenerate fixtures
```

## License

[MIT](LICENSE)

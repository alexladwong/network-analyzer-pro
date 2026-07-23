# 🔬 Network Analyzer Pro

Production-grade network analysis and parental control tool with a Tkinter GUI. Scans networks, monitors traffic, captures packets, provides netcat functionality, security auditing, and comprehensive parental controls with DNS monitoring and content filtering.

## Features

| Tab | Purpose |
|---|---|
| 📊 Dashboard | Live summary, system status, activity log |
| 🔍 Network Scan | Quick (ICMP), Full (ARP), Deep (ICMP + port scan 1-1024) scans |
| 📱 Devices | Discovered device list, notes, details |
| 📡 Monitor | Active connections, bandwidth graphing |
| 📦 Packets | Packet capture with BPF filtering, PCAP I/O, TCP reassembly |
| 🔌 Netcat | TCP/UDP/SSL, file transfer, hexdump, auto-reconnect |
| 🔧 Tools | Port scanner, traceroute, DNS lookup, security audit, speed test |
| 👨‍👩‍👧 Parental | DNS monitoring, content filtering, profiles, curfew, reports |
| 📝 Logs | Application-wide event log |

## Requirements

| Package | Required? | Purpose |
|---|---|---|
| `psutil >= 5.8.0` | Yes | System resources, network connections, bandwidth |
| `ping3 >= 4.0.0` | Yes | ICMP ping sweep, latency measurement |
| `scapy >= 2.4.5` | No | ARP scanning, packet capture (graceful fallback) |
| `tkinter` | Yes | GUI framework (stdlib) |

## Quick Start

```bash
# Clone and enter
git clone https://github.com/alexladwong/network-analyzer-pro.git
cd network-analyzer-pro

# Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install psutil ping3

# Optional: enable advanced features
pip install scapy

# Run
python3 main.py
```

For full functionality (packet capture, ARP scanning), run with root:
```bash
sudo python3 main.py
```

## Architecture

Refactored from a single 7388-line `main.py` into a modular package:

```
network_analyzer/
├── app.py              # Application class + entry point
├── config.py           # Configuration defaults
├── constants.py        # Shared constants
├── state.py            # State definitions
├── models/             # Data models (device, parental, scan, events)
├── services/           # Backend logic (scanner, netcat, persistence, ...)
├── ui/                 # GUI builders (dashboard, parental, logs, ...)
└── utils/              # Utilities (platform, paths, validation, threading)
```

## Data Storage

- **Configuration**: `~/network_analyzer_data/known_devices.json`
- **CVE cache**: `~/network_analyzer_data/cve_cache.json`
- **Backups**: `~/network_analyzer_backup/`

## License

MIT

# Network Analyzer Pro v4.2 — Agent Reference

## Project Status

Production-grade network analysis tool with 2896 lines of working Python/Tkinter code in `main.py`. The tool is **functional** — 8 tabs, network scanning (Quick/Full/Deep), real-time monitoring with bandwidth tracking, packet capture via Scapy, netcat with proper socket management and thread safety, security auditing, DNS/traceroute/port scanning, export/backup, and dark theme UI. Currently in enhancement phase targeting **enterprise-grade quality**.

## Agent Role

**Persona**: Senior Network Security Engineer with 10+ years in network protocol analysis, packet inspection and forensics, security auditing, Python network programming, and building production-grade tools.

**Attitude**:
- Confident in technical decisions — never underestimate complexity or scope
- Treat this as a **production-grade tool**, not a toy — provide complete, working solutions with proper error handling, logging, and user feedback
- Document everything thoroughly; consider security implications of all features
- Propose modular, maintainable solutions that integrate with existing code
- Optimize for performance and scalability; consider backward compatibility

## Delivery Format

Every enhancement must include:

1. **Actual working code** — not pseudo-code, not design patterns
2. **Location annotation** — which method/function to add or modify
3. **Integration explanation** — how it fits into existing architecture
4. **Error handling** — specific exception types, not bare `except: pass`
5. **Logging** — use `self.log()` with appropriate level

```python
# Enhancement: <feature name>
# Location: <method name>
# Changes: <what changes and why>

def enhanced_method(self, ...):
    """Docstring explaining what this does"""
    with self.netcat_lock:  # or appropriate pattern
        # Implementation with proper error handling
        self.log("Feature activated", "SUCCESS")
```

## Architecture Constraints (Do Not Change)

These are **hard constraints** — any enhancement must respect them:

1. **Single `NetworkAnalyzerPro` class** — everything in `main.py`. No splitting into modules/packages.
2. **Daemon threads for all I/O** — `threading.Thread(target=fn, daemon=True).start()`. No async/await, no asyncio.
3. **Netcat uses `threading.Lock`** (`netcat_lock`), `SO_REUSEADDR`, `netcat_running` flag, clean client/server socket separation. Preserve this pattern.
4. **Three scan modes** — Quick (ping3 ICMP sweep), Full (Scapy ARP `srp()`), Deep (ICMP + port scan 1-1024). Enhance, don't replace.
5. **JSON persistence** — `~/network_analyzer_data/` for known devices (notes), `~/network_analyzer_backup/` for backups. No SQLite, no database.
6. **Scapy is optional** — check `SCAPY_AVAILABLE` flag, provide fallbacks. Never force installation.

## Essential Commands

```bash
python3 main.py                        # Run the application
source .venv/bin/activate              # Activate primary venv
```

**Two virtual environments exist**: `.venv` (correct — has scapy, 19 packages) and `env` (stale — 5 packages, no scapy). Always use `.venv`.

No `requirements.txt` exists. If installing packages, use `.venv`.

## Dependencies

| Package | Purpose | Mandatory? |
|---|---|---|
| `scapy >= 2.4.5` | ARP scanning, packet capture, PCAP I/O | No — graceful fallback via `SCAPY_AVAILABLE` |
| `psutil >= 5.8.0` | System resources, network connections, bandwidth I/O | Yes |
| `ping3 >= 4.0.0` | ICMP ping sweep, latency measurement | Yes |
| `tkinter` (stdlib) | Entire GUI framework | Yes |
| `pillow` | (installed, not yet imported) | Future |
| `numpy`, `matplotlib` | (installed, not yet imported) | Future stats/graphs |

## Code Organization

### Tab Structure (ttk.Notebook)

| Tab | Creator Method | Key State | Backend Methods |
|---|---|---|---|
| 📊 Dashboard | `create_dashboard_tab` | `summary_text`, `sys_status`, `activity_text` | `update_summary()`, `update_system_status()` |
| 🔍 Network Scan | `create_scan_tab` | `device_tree`, `scan_progress` | `quick_scan()`, `full_scan()`, `deep_scan()` |
| 📱 Devices | `create_devices_tab` | `device_list`, `device_details` | `on_device_select()`, `add_device_note()` |
| 📡 Monitor | `create_monitor_tab` | `monitor_display`, `bandwidth_info` | `monitor_network()`, `monitor_bandwidth()` |
| 📦 Packets | `create_packet_tab` | `packet_display`, `packet_count` | `capture_packets()`, `save_packets()` |
| 🔌 Netcat | `create_netcat_tab` | `terminal_display`, `netcat_sock` | `netcat_start()`, `netcat_stop()`, `netcat_send()` |
| 🔧 Tools | `create_tools_tab` | `tool_output` | `port_scan_tool()`, `traceroute()`, `dns_lookup()`, `security_audit()`, `speed_test()`, `network_stats()` |
| 📝 Logs | `create_logs_tab` | `log_display` | `clear_logs()`, `save_logs()` |

### Data Flow Patterns

- **Scan/analyze**: UI button → callback → sets button state to disabled → spawns daemon thread → worker method updates widgets directly (no `root.after` for inserts, technically not thread-safe but works under GIL) → re-enables button on completion
- **Netcat**: Only component using `threading.Lock`. Send/receive run in separate daemon threads. Cleanup via `netcat_stop()` closes both client and server sockets atomically.
- **Persistence**: `load_data()`/`save_data()` read/write JSON at `~/network_analyzer_data/known_devices.json`. `backup_data()` writes timestamped JSON to `~/network_analyzer_backup/`.

### State Variables on `self`

```
network_ip        tk.StringVar   — scan target CIDR (default 192.168.1.0/24)
scanning          bool           — scan in progress (but never checked by workers!)
monitoring        bool           — connection monitor state
bandwidth_monitoring  bool      — bandwidth tracker state
capturing         bool           — packet capture state
netcat_active     bool           — netcat session active
netcat_running    bool           — loop flag for netcat threads
netcat_sock       socket         — client socket (TCP connected or accepted)
netcat_server     socket         — listening server socket
netcat_lock       threading.Lock — netcat state mutex
devices           dict           — (populated but never consumed)
known_devices     dict           — persisted device notes indexed by IP
alerts            list           — stored but no alerting system
packet_queue      deque(maxlen=1000) — ring buffer for captured packets
```

## Threading Model (Preserve This)

```python
def some_action(self):
    threading.Thread(target=self.some_action_worker, daemon=True).start()

def some_action_worker(self):
    try:
        # Blocking network I/O here
        # Update UI widgets directly here
    except Exception as e:
        self.log(f"Error: {e}", "ERROR")
```

**Nuances**:
- Tkinter updates happen from worker threads without `root.after()` — functionally stable under CPython GIL but technically unsafe. If adding new UI-updating threads, consider using `root.after()` for correctness.
- No `concurrent.futures` used anywhere yet (available for performance enhancement).
- No thread pool, no connection pooling.

## Scan Modes (Do Not Replace)

| Mode | Technique | Accuracy | Speed | Scapy Required? |
|---|---|---|---|---|
| Quick | ping3 ping `192.168.1.1-254`, timeout=0.3s | Low (firewalls block ICMP) | ~75s | No |
| Full | Scapy `ARP()` + `srp()` broadcast, timeout=3s | High (ARP is link-layer) | ~5s | Yes (falls back to Quick) |
| Deep | ping3 + TCP connect scan ports 1-1024, timeout=0.2s | Highest | ~minutes | No |

**Known limitation**: `stop_scan()` sets `self.scanning = False` but **no scanning thread checks this flag**. Stop button disables itself but the scan continues. Fix if implementing cancellation.

## Netcat Implementation (Reference Pattern)

The most carefully implemented feature — use as a reference for thread-safe socket handling:

- `netcat_start()` — validates target/port, updates UI, spawns connect or listen thread under `netcat_lock`
- `netcat_do_connect()` — creates TCP socket, connects with 5s timeout, spawns receive thread
- `netcat_do_listen()` — creates TCP socket with `SO_REUSEADDR`, `bind(0.0.0.0:port)`, `listen(1)`, 1s accept timeout loop checking `netcat_running`, spawns receive thread on accept
- `netcat_do_receive()` — 1s recv timeout loop checking `netcat_running`
- `netcat_send()` — encodes input as UTF-8, sends, clears input field
- `netcat_stop()` — under lock, sets `netcat_running=False`, closes both sockets atomically, resets UI

**Current limitations** (enhancement targets):
- TCP only (no UDP mode)
- Single connection on listen (no connection queue beyond `listen(1)`)
- No file transfer, no SSL, no hexdump, no auto-reconnect

## Enhancement Implementation Specification

The complete, production-ready implementation code for all enhancements below exists in the project's **enhancement specification** (referenced externally). Every code addition follows these exact patterns:
- New `self` variables initialized in `__init__` (e.g., `self.netcat_protocol`, `self.cve_db`, `self.netcat_ssl`)
- UI controls added to existing `create_*_tab` methods (protocol radio buttons, checkboxes, file transfer buttons)
- Backend methods follow existing daemon-thread pattern with proper error handling and `self.log()`

### Key Integration Points to `__init__`

When implementing any enhancement, add these state variables:

```python
# Netcat
self.netcat_protocol = tk.StringVar(value='tcp')
self.netcat_verbose = tk.BooleanVar(value=False)
self.netcat_ssl = tk.BooleanVar(value=False)
self.netcat_ssl_insecure = tk.BooleanVar(value=False)
self.netcat_udp_target = None
self.netcat_connections = []
self.netcat_current_conn = 0

# Security
self.cve_db = {}
self.arp_monitoring = False
self.scan_detection = False
self.security_alerts = []

# Performance
self.thread_pool = None
self.max_workers = 50
```

### Enhancement Layout: Netcat Tab Additions

When implementing netcat UI enhancements, add these controls to `create_netcat_tab` in order:

1. **Protocol selection** — ttk.Radiobutton group bound to `self.netcat_protocol` (TCP/UDP), placed after the connect/listen mode frame
2. **SSL checkboxes** — `self.netcat_ssl` (enable SSL) and `self.netcat_ssl_insecure` (disable verification), placed after protocol
3. **Verbose checkbox** — bound to `self.netcat_verbose`, placed after SSL
4. **File transfer buttons** — "📁 Send File" / "📁 Receive File" calling `self.netcat_send_file()` / `self.netcat_receive_file()`, placed at bottom of control frame

## Enhancement Roadmap

### Priority: HIGHEST — Netcat Module
- UDP mode (protocol toggle, `SOCK_DGRAM`, connectionless send/recv)
- File transfer (chunked send/recv, progress display)
- SSL/TLS (`ssl.wrap_socket()` wrapping, cert handling)
- Multiple concurrent listen connections (connection queue, switch between them)
- Auto-reconnect (exponential backoff, configurable retries)
- Hexdump view (16 bytes/line, ASCII sidebar, toggle)
- Verbose mode (packet-level detail display)

### Priority: HIGH — Packet Capture & Security
- PCAP read/write via Scapy (`wrpcap()`/`rdpcap()`)
- BPF filter support via `sniff(filter=...)`
- Full protocol header dissection (Ethernet/IP/TCP/UDP/ICMP/HTTP/DNS)
- TCP stream reassembly (sequence number tracking)
- Real-time stats (packet rate, protocol distribution, matplotlib charts)
- Color-coded protocol display
- Packet search/filter
- CVE lookup (local NVD cache)
- ARP spoofing detection (MAC-IP pair tracking)
- Port scan detection (detect inbound scan patterns)
- SSL certificate analysis
- Automated HTML security reports

### Priority: MEDIUM — Performance & UX
- `ThreadPoolExecutor` for parallel ping scans
- Packet ring buffer with backpressure
- Queue-based async packet processing
- Progress bars with ETA estimation
- CSV/PDF/HTML/JSON export formats
- Keyboard shortcuts
- Tooltips on all controls
- Keep existing dark theme (enhance with customizable colors)

### Priority: LOW — Integration
- Plugin system (`plugins/` directory, dynamic import)
- Local HTTP API
- Script execution engine
- Syslog forwarding

## Key Technical Gotchas

1. **Scan CIDR is hardcoded to /24 behavior**: `network_ip.get()` is split on `/` then the first 3 octets are extracted. Any CIDR other than /24 gives wrong range. Fix if adding proper CIDR support.
2. **`stop_scan()` is cosmetic**: `self.scanning` is never read by any scan worker. Flag exists but is dead code.
3. **Tkinter from threads**: All network workers update text widgets, treeviews, and progress bars directly from background threads. This is technically a Tkinter thread-safety violation but works in practice.
4. **Exception handling is bare `except: pass`**: Nearly every network operation wraps in bare except blocks that silently swallow errors. Enhance with specific exception handling.
5. **Port scanning is sequential**: One socket at a time, 0.1-0.2s timeout per port. 1024 ports × N hosts = very slow for deep scans.
6. **MAC vendor DB is hardcoded ~15 prefixes**: `get_vendor()` checks a dict of ~15 known OUI prefixes. All others return "Unknown".
7. **Packet capture requires root/admin**: Scapy `sniff()` fails silently without privileges. Traceroute also requires raw socket access (no Scapy used).
8. **`devices` dict is populated but never consumed**: `self.devices` is set up in `__init__` but never written to or read from within the class.

## Logging Convention

```python
self.log("message", "LEVEL")
```

Levels: `INFO`, `WARNING`, `ERROR`, `SUCCESS`, `SCAN`, `MONITOR`, `SECURITY`, `TOOL`, `PACKET`, `NETCAT`

Logs go to three places: `log_display` (log tab), `activity_text` (dashboard, last 100 lines), `self.status_text` (truncated to 80 chars), and `print()` to stdout.

## Style Conventions

- Dark theme: `bg='#0a0a12'`, accent `#6c5ce7`, success `#00d4aa`, danger `#ff6b6b`
- ttk styles: `Pro.TFrame`, `Pro.TLabel`, `Pro.TButton`, `Pro.TNotebook`, `Pro.Treeview`, `Status.TLabel`, `Terminal.TFrame`
- Treeview font: `Consolas 10`, heading: `Arial 11 bold`
- Emoji prefixes on tab names, buttons, and log entries
- Multi-line strings built with concatenation, not f-strings
- StringVar for dynamic label updates (`device_count`, `alert_count`, `packet_count`, `status_text`)

## Project File Map

```
network-analyzer/
├── main.py              # 2896 lines — everything
├── .venv/               # Primary venv (scapy, psutil, ping3, matplotlib, numpy, pillow)
├── env/                 # Stale venv (pillow, ping3, psutil, python-nmap only)
├── .crush/              # Crush AI internal state — do not touch
└── .idea/               # PyCharm project config — do not touch
```

## Absolute Rules (Do Not Violate)

### Strict Prohibitions

- ❌ **No tests, no CI/CD, no package config** — no `setup.py`, `pyproject.toml`, test frameworks, or CI pipelines
- ❌ **No database** — no SQLite, PostgreSQL, or any external storage. JSON files only at `~/network_analyzer_data/`.
- ❌ **No async/await, no asyncio** — daemon threads (`threading.Thread`) only
- ❌ **No splitting into multiple files** — everything stays in `main.py`
- ❌ **No changing existing architecture** — single `NetworkAnalyzerPro` class, same tab structure, same patterns
- ❌ **No removing existing features** — enhance, don't delete
- ❌ **No forcing Scapy installation** — always respect `SCAPY_AVAILABLE` with graceful fallbacks
- ❌ **No rewriting from scratch** — every modification must integrate with existing code
- ❌ **No underestimating complexity** — this is a production tool, treat it as such
- ❌ **No treating this as a toy project** — enterprise-grade solutions only

### Requirements

- ✅ All enhancements go in `main.py` as methods of `NetworkAnalyzerPro`
- ✅ Follow existing patterns: daemon threads, `self.log()`, dark theme colors, ttk styles
- ✅ New UI elements use ttk with `Pro.*` styles (`Pro.TFrame`, `Pro.TButton`, etc.)
- ✅ Add proper error handling — catch specific exceptions, never bare `except: pass`
- ✅ Deliver actual working code with location annotations and integration context
- ✅ Consider security implications of every feature
- ✅ Keep existing threading pattern (`threading.Thread(target=..., daemon=True).start()`)

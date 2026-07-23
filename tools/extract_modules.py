#!/usr/bin/env python3
"""
Extract methods from main.py into network_analyzer package modules.
Generates module files with standalone functions + app.py that assembles the class.

Usage: python3 tools/extract_modules.py
"""

import ast
import os
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'main.py.pre_refactor_backup')
PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'network_analyzer')

# ---------------------------------------------------------------------------
# 1. Read original source (from backup!)
# ---------------------------------------------------------------------------
with open(SRC) as f:
    source = f.read()
    lines = source.splitlines(keepends=True)

tree = ast.parse(source)

class_node = None
for node in ast.walk(tree):
    if isinstance(node, ast.ClassDef) and node.name == 'NetworkAnalyzerPro':
        class_node = node
        break

if not class_node:
    print("ERROR: Could not find NetworkAnalyzerPro class")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 2. Gather methods with line ranges
# ---------------------------------------------------------------------------
methods = []
for item in class_node.body:
    if isinstance(item, ast.FunctionDef):
        name = item.name
        start = item.lineno - 1
        end = item.end_lineno
        docstring = ast.get_docstring(item) or ''
        methods.append((name, start, end, docstring))

method_map = {name: (s, e) for name, s, e, d in methods}
print(f"Found {len(methods)} methods in NetworkAnalyzerPro")

# ---------------------------------------------------------------------------
# 3. Method → module mapping
# ---------------------------------------------------------------------------
METHOD_MODULE = {
    # Utils / Platform
    '_check_root': 'utils/platform.py',
    '_restart_with_sudo': 'utils/platform.py',

    # Services - Logging
    'log': 'services/logging_service.py',

    # Services - Persistence
    'save_data': 'services/persistence.py',
    'load_data': 'services/persistence.py',
    'backup_data': 'services/persistence.py',
    'ensure_data_directory': 'services/persistence.py',
    'export_csv': 'services/persistence.py',
    'export_pdf': 'services/persistence.py',
    'export_report': 'services/persistence.py',

    # Services - Network Discovery
    'get_local_ip': 'services/network_discovery.py',
    'get_gateway': 'services/network_discovery.py',
    '_is_gateway': 'services/network_discovery.py',
    'discover_networks': 'services/network_discovery.py',

    # Services - Scanner
    'quick_scan': 'services/scanner.py',
    'run_quick_scan': 'services/scanner.py',
    'full_scan': 'services/scanner.py',
    'run_full_scan': 'services/scanner.py',
    'deep_scan': 'services/scanner.py',
    'run_deep_scan': 'services/scanner.py',
    'get_mac_address': 'services/scanner.py',
    'scan_common_ports': 'services/scanner.py',
    'scan_ports': 'services/scanner.py',
    'get_hostname': 'services/scanner.py',
    'classify_device': 'services/scanner.py',
    'get_vendor': 'services/scanner.py',
    '_init_oui_db': 'services/scanner.py',
    'run_quick_scan_threadpool': 'services/scanner.py',
    'ping_ip': 'services/scanner.py',
    'run_ping': 'services/scanner.py',
    'ping_tool': 'services/scanner.py',
    'port_scan_tool': 'services/scanner.py',
    'run_port_scan': 'services/scanner.py',
    'traceroute': 'services/scanner.py',
    'run_traceroute': 'services/scanner.py',

    # Services - Monitor
    'monitor_network': 'services/monitor.py',
    'arp_monitor': 'services/monitor.py',
    'network_stats': 'services/monitor.py',
    'speed_test': 'services/monitor.py',
    'run_speed_test': 'services/monitor.py',

    # Services - Bandwidth
    'toggle_bandwidth': 'services/bandwidth.py',
    'monitor_bandwidth': 'services/bandwidth.py',
    '_update_bandwidth_graph': 'services/bandwidth.py',
    '_draw_bandwidth_graph_empty': 'services/bandwidth.py',
    'draw_line': 'services/bandwidth.py',

    # Services - Packet Capture / Security
    'start_capture': 'services/packet_capture.py',
    'stop_capture': 'services/packet_capture.py',
    'capture_packets': 'services/packet_capture.py',
    'packet_callback': 'services/packet_capture.py',
    'save_packets': 'services/packet_capture.py',
    'load_pcap': 'services/packet_capture.py',
    'save_pcap': 'services/packet_capture.py',
    'clear_packets': 'services/packet_capture.py',
    'tcp_stream_reassembly': 'services/packet_capture.py',
    'arp_spoofing_detection': 'services/packet_capture.py',
    'port_scan_detection': 'services/packet_capture.py',
    'scan_detector': 'services/packet_capture.py',
    'analyze_ssl_certificate': 'services/packet_capture.py',
    '_show_tool_message': 'services/packet_capture.py',
    'load_cve_database': 'services/packet_capture.py',
    'check_device_vulnerabilities': 'services/packet_capture.py',
    'dns_lookup': 'services/packet_capture.py',
    'lookup': 'services/packet_capture.py',
    'do_lookup': 'services/packet_capture.py',

    # Services - Netcat
    'netcat_start': 'services/netcat.py',
    'netcat_do_connect': 'services/netcat.py',
    'netcat_do_connect_ssl': 'services/netcat.py',
    'netcat_do_connect_udp': 'services/netcat.py',
    'netcat_do_listen_udp': 'services/netcat.py',
    'netcat_do_receive_udp': 'services/netcat.py',
    'netcat_do_listen_multi': 'services/netcat.py',
    'netcat_do_receive_multi': 'services/netcat.py',
    'netcat_do_receive': 'services/netcat.py',
    'netcat_send': 'services/netcat.py',
    'netcat_send_udp': 'services/netcat.py',
    'netcat_send_file': 'services/netcat.py',
    'netcat_receive_file': 'services/netcat.py',
    'netcat_auto_reconnect': 'services/netcat.py',
    'show_hexdump': 'services/netcat.py',
    'netcat_stop': 'services/netcat.py',

    # Services - DNS Monitor
    'toggle_dns_monitoring': 'services/dns_monitor.py',
    'capture_dns_queries': 'services/dns_monitor.py',
    'dns_callback': 'services/dns_monitor.py',

    # Services - Content Filter
    'toggle_content_filter': 'services/content_filter.py',
    '_block_via_hosts': 'services/content_filter.py',

    # Services - Parental Control
    'get_remaining_time': 'services/parental_control.py',
    'is_curfew_active': 'services/parental_control.py',
    'parental_filter_activity': 'services/parental_control.py',
    'parental_clear_activity': 'services/parental_control.py',
    'save_assignment': 'services/parental_control.py',
    '_update_parental_settings_display': 'services/parental_control.py',
    '_get_activity_stats': 'services/parental_control.py',
    'parental_daily_report': 'services/parental_control.py',
    'parental_weekly_report': 'services/parental_control.py',
    '_build_report': 'services/parental_control.py',
    '_show_report': 'services/parental_control.py',
    '_save_report': 'services/parental_control.py',
    'parental_export_report': 'services/parental_control.py',
    '_report_to_html': 'services/parental_control.py',
    'periodic_parental_check': 'services/parental_control.py',
    'save_infrastructure': 'services/parental_control.py',

    # Services - Infrastructure / Discovery
    'discover_routers': 'services/parental_control.py',
    'discover_dhcp_servers': 'services/parental_control.py',
    '_is_port_open': 'services/parental_control.py',
    'wireless_scan': 'services/parental_control.py',
    'discover_topology': 'services/parental_control.py',
    '_is_same_subnet': 'services/parental_control.py',
    '_get_device_subnet': 'services/parental_control.py',
    'detect_rogue_dhcp': 'services/parental_control.py',
    'detect_rogue_ssid': 'services/parental_control.py',
    'detect_nat_boundary': 'services/parental_control.py',
    'track_device_session': 'services/parental_control.py',
    'close_device_session': 'services/parental_control.py',
    '_is_managed_network': 'services/parental_control.py',
    'detect_network_transition': 'services/parental_control.py',
    'verify_infrastructure': 'services/parental_control.py',
    'update_topology': 'services/parental_control.py',
    'periodic_infrastructure_check': 'services/parental_control.py',

    # Services - Reporting
    'generate_security_report': 'services/reporting.py',
    'security_audit': 'services/reporting.py',
    'run_security_audit': 'services/reporting.py',

    # UI - Theme
    'setup_styles': 'ui/theme.py',

    # UI - Main Window
    'create_widgets': 'ui/main_window.py',
    'create_header': 'ui/main_window.py',
    '_create_card': 'ui/main_window.py',
    '_brighten': 'ui/main_window.py',
    'create_menu': 'ui/main_window.py',
    'create_status_bar': 'ui/main_window.py',
    'show_status_progress': 'ui/main_window.py',
    'hide_status_progress': 'ui/main_window.py',
    'setup_keyboard_shortcuts': 'ui/main_window.py',
    'auto_refresh': 'ui/main_window.py',
    'update_status_time': 'ui/main_window.py',
    'show_about': 'ui/main_window.py',
    'show_docs': 'ui/main_window.py',

    # UI - Dashboard
    'create_dashboard_tab': 'ui/dashboard.py',
    'update_summary': 'ui/dashboard.py',
    'update_system_status': 'ui/dashboard.py',
    'add_alert': 'ui/dashboard.py',

    # UI - Network Scan
    'create_scan_tab': 'ui/network_scan.py',
    'start_scan': 'ui/network_scan.py',
    'stop_scan': 'ui/network_scan.py',
    'update_scan_stats': 'ui/network_scan.py',
    'update_progress_with_eta': 'ui/network_scan.py',
    'update_network_combo': 'ui/network_scan.py',
    'refresh_networks': 'ui/network_scan.py',
    '_validate_cidr_input': 'ui/network_scan.py',
    '_get_scan_targets': 'ui/network_scan.py',
    '_ips_from_targets': 'ui/network_scan.py',

    # UI - Devices
    'create_devices_tab': 'ui/devices.py',
    'on_device_select': 'ui/devices.py',
    'refresh_devices': 'ui/devices.py',
    'analyze_devices': 'ui/devices.py',
    'add_device_note': 'ui/devices.py',
    'export_device_data': 'ui/devices.py',
    'save_note': 'ui/devices.py',

    # UI - Monitor
    'create_monitor_tab': 'ui/monitor.py',
    'start_monitoring': 'ui/monitor.py',
    'stop_monitoring': 'ui/monitor.py',
    'update_monitor_display': 'ui/monitor.py',

    # UI - Packets
    'create_packet_tab': 'ui/packets.py',

    # UI - Netcat
    'create_netcat_tab': 'ui/netcat.py',

    # UI - Tools
    'create_tools_tab': 'ui/tools.py',

    # UI - Parental (includes infrastructure UI)
    'create_parental_tab': 'ui/parental.py',
    'refresh_parental_display': 'ui/parental.py',
    'update_parental_stats': 'ui/parental.py',
    'on_parental_device_select': 'ui/parental.py',
    'parental_assign_profile': 'ui/parental.py',
    'parental_toggle_block': 'ui/parental.py',
    'parental_edit_device': 'ui/parental.py',
    'parental_view_profile': 'ui/parental.py',
    'parental_settings_dialog': 'ui/parental.py',
    'parental_clear_activity': 'ui/parental.py',
    'parental_filter_activity': 'ui/parental.py',
    '_get_alert_count_by_severity': 'ui/parental.py',
    'infrastructure_add_dialog': 'ui/parental.py',
    'infrastructure_edit_dialog': 'ui/parental.py',
    'infrastructure_remove': 'ui/parental.py',
    'rogue_investigate': 'ui/parental.py',
    'rogue_acknowledge': 'ui/parental.py',
    'rogue_clear_all': 'ui/parental.py',
    'refresh_infrastructure_display': 'ui/parental.py',
    'refresh_rogue_alerts_display': 'ui/parental.py',
    'refresh_child_transitions_display': 'ui/parental.py',
    'refresh_topology_display': 'ui/parental.py',
    'refresh_timeline_display': 'ui/parental.py',
    'toggle_infrastructure_monitoring': 'ui/parental.py',
    '_on_infra_tree_double_click': 'ui/parental.py',
    '_infra_remove_selected': 'ui/parental.py',

    # UI - Logs
    'create_logs_tab': 'ui/logs.py',
    'clear_logs': 'ui/logs.py',
    'save_logs': 'ui/logs.py',
}

# ---------------------------------------------------------------------------
# 4. Group methods by target module
# ---------------------------------------------------------------------------
module_methods = {}
unmapped = []
for name, s, e, d in methods:
    target = METHOD_MODULE.get(name)
    if target:
        module_methods.setdefault(target, []).append((name, s, e, d))
    elif name != '__init__':
        unmapped.append(name)

if unmapped:
    print(f"WARNING: {len(unmapped)} unmapped methods: {unmapped}")
else:
    print("All non-__init__ methods mapped successfully")

# ---------------------------------------------------------------------------
# 5. Helper: extract method source and dedent
# ---------------------------------------------------------------------------
def get_method_source(name):
    """Return dedented source for a given method name."""
    s, e = method_map[name]
    method_lines = lines[s:e]
    # Find indentation of 'def' line
    first = method_lines[0]
    indent = len(first) - len(first.lstrip())
    result = []
    for i, line in enumerate(method_lines):
        if line.strip() == '':
            result.append('\n')
        else:
            result.append(line[indent:] if len(line) > indent else line)
    return ''.join(result)

# ---------------------------------------------------------------------------
# 6. Helper: build module-level imports block
# ---------------------------------------------------------------------------
IMPORTS_BLOCK = """\
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import socket
import ipaddress
import time
import psutil
import ping3
from datetime import datetime
import json
import os
import sys
import platform
import re
from collections import deque
import struct
import binascii
import select
import errno
import ssl
import csv
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile

# Try importing advanced libraries
try:
    import scapy.all as scapy
    from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
"""

# ---------------------------------------------------------------------------
# 7. Write module files
# ---------------------------------------------------------------------------
def write_module(module_path, methods_list):
    full_path = os.path.join(PKG, module_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    
    name = os.path.splitext(os.path.basename(module_path))[0]
    
    with open(full_path, 'w') as f:
        f.write('"""\n')
        f.write(f'{name} module — extracted from main.py\n')
        f.write('"""\n\n')
        f.write(IMPORTS_BLOCK)
        f.write('\n')
        
        for fn_name, start, end, doc in sorted(methods_list, key=lambda x: x[1]):
            src = get_method_source(fn_name)
            f.write(src)
            f.write('\n')
    
    print(f"  wrote {full_path} ({len(methods_list)} methods)")

for module_path, meths in sorted(module_methods.items()):
    write_module(module_path, meths)

# ---------------------------------------------------------------------------
# 8. Write __init__.py files
# ---------------------------------------------------------------------------
for dirpath, dirnames, filenames in os.walk(PKG):
    if '__init__.py' in filenames:
        fpath = os.path.join(dirpath, '__init__.py')
        rel = os.path.relpath(dirpath, PKG)
        if rel == '.':
            continue
        section = rel.replace(os.sep, '.')
        with open(fpath, 'w') as f:
            f.write(f'"""network_analyzer.{section} package"""\n')

# Top-level __init__.py
with open(os.path.join(PKG, '__init__.py'), 'w') as f:
    f.write('"""network_analyzer - Network Analyzer Pro package"""\n')

# ---------------------------------------------------------------------------
# 9. Write app.py — class definition with __init__ + method imports
# ---------------------------------------------------------------------------
app_path = os.path.join(PKG, 'app.py')

# Get __init__ source and re-indent it for class body
init_src = get_method_source('__init__')
# dedent_method already stripped all leading whitespace
# Must re-indent: def line gets 4 spaces, body gets 8
init_lines = init_src.splitlines(keepends=True)
indented = []
for i, line in enumerate(init_lines):
    stripped = line
    if line.strip() == '':
        indented.append('    \n')
    else:
        # Add 4 spaces
        indented.append('    ' + line)

# Build method import groups per module
import_groups = {}
for module_path, meths in sorted(module_methods.items()):
    module_key = module_path.replace('/', '.').replace('.py', '')
    for fn_name, s, e, d in meths:
        import_groups.setdefault(module_key, []).append(fn_name)

with open(app_path, 'w') as f:
    f.write('"""\n')
    f.write('Network Analyzer Pro — main application class\n')
    f.write('Assembles the class from extracted module functions.\n')
    f.write('"""\n\n')
    f.write(IMPORTS_BLOCK)
    f.write('\n')
    
    f.write('class NetworkAnalyzerPro:\n')
    f.write('    """Network Analyzer Pro — complete application class"""\n')
    f.write('\n')
    
    # Write __init__ (already indented with 4 extra spaces)
    for line in indented:
        f.write(line)
    
    f.write('\n')
    
    # Import methods from submodules using inline class-body imports
    for module_key, fn_names in sorted(import_groups.items()):
        import_from = 'network_analyzer.' + module_key
        names_sorted = sorted(fn_names)
        chunks = [names_sorted[i:i+10] for i in range(0, len(names_sorted), 10)]
        for chunk in chunks:
            names_str = ', '.join(chunk)
            f.write(f'    from {import_from} import {names_str}\n')
    
    f.write('\n')
    
    # main() function
    f.write('\ndef main():\n')
    f.write('    """Main entry point"""\n')
    f.write('    try:\n')
    f.write('        root = tk.Tk()\n')
    f.write('        app = NetworkAnalyzerPro(root)\n')
    f.write('        root.mainloop()\n')
    f.write('    except Exception as e:\n')
    f.write('        print(f"Error: {e}")\n')
    f.write('        import traceback\n')
    f.write('        traceback.print_exc()\n')

print(f"\nWrote {app_path}")

# ---------------------------------------------------------------------------
# 10. Write main.py entry point
# ---------------------------------------------------------------------------
main_out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'main.py')
with open(main_out, 'w') as f:
    f.write('#!/usr/bin/env python3\n')
    f.write('"""\n')
    f.write('Network Analyzer Pro — entry point\n')
    f.write('Refactored into network_analyzer/ package\n')
    f.write('"""\n\n')
    f.write('from network_analyzer.app import main\n\n')
    f.write('if __name__ == "__main__":\n')
    f.write('    main()\n')

print(f"Wrote {main_out} (entry point)")
print("\nDone!")

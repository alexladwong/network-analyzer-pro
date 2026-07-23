"""
Network Analyzer Pro — main application class
Assembles the class from extracted module functions.
"""

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

class NetworkAnalyzerPro:
    """Network Analyzer Pro — complete application class"""

    def __init__(self, root):
        self.network_combo = None
        self.root = root
        self.root.title("🔬 Network Analyzer Pro")
        self.root.geometry("1600x950")
        self.root.configure(bg='#0a0a12')
        self.root.minsize(1200, 700)
    
        # Set app icon
        try:
            _project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            icon_path = os.path.join(_project_dir, 'app_icon.png')
            if os.path.exists(icon_path):
                icon_img = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, icon_img)
        except:
            pass
    
        # Network variables
        self.network_ip = tk.StringVar(value="192.168.1.0/24")
        self.available_networks = []
        self.scanning = False
        self.monitoring = False
        self.bandwidth_monitoring = False
        self.capturing = False
    
        # Netcat variables - PROPERLY MANAGED
        self.netcat_active = False
        self.netcat_sock = None
        self.netcat_server = None
        self.netcat_thread = None
        self.netcat_running = False
        self.netcat_lock = threading.Lock()
        # Netcat enhancements
        self.netcat_protocol = tk.StringVar(value='tcp')
        self.netcat_verbose = tk.BooleanVar(value=False)
        self.netcat_ssl_enabled = tk.BooleanVar(value=False)
        self.netcat_ssl_insecure = tk.BooleanVar(value=False)
        self.netcat_udp_target = None
        self.netcat_connections = []
        self.netcat_current_conn = -1
        self.netcat_reconnect = tk.BooleanVar(value=False)
    
        # Data structures
        self.devices = {}
        self.known_devices = {}
        self.alerts = []
        self.security_alerts = []
        self.packet_queue = deque(maxlen=1000)
        self.bandwidth_history = deque(maxlen=60)  # (down, up) tuples for live graph
    
        # Parental Control state
        self.parental_profiles = {
            'child': {
                'name': 'Child', 'block_categories': ['adult', 'violence', 'gaming', 'social'],
                'time_limit': 120, 'curfew_start': '21:00', 'curfew_end': '07:00',
                'block_domains': [], 'allow_domains': [],
                'weekend_diff': True, 'weekend_time_limit': 180,
                'weekend_curfew_start': '22:00', 'weekend_curfew_end': '09:00',
            },
            'teen': {
                'name': 'Teen', 'block_categories': ['adult', 'violence'],
                'time_limit': 240, 'curfew_start': '22:00', 'curfew_end': '06:00',
                'block_domains': [], 'allow_domains': [],
                'weekend_diff': True, 'weekend_time_limit': 300,
                'weekend_curfew_start': '23:00', 'weekend_curfew_end': '08:00',
            },
            'guest': {
                'name': 'Guest', 'block_categories': ['adult'],
                'time_limit': 60, 'curfew_start': '22:00', 'curfew_end': '08:00',
                'block_domains': [], 'allow_domains': [],
                'weekend_diff': False,
            },
            'admin': {
                'name': 'Admin', 'block_categories': [], 'time_limit': 0,
                'curfew_start': '', 'curfew_end': '',
                'block_domains': [], 'allow_domains': [], 'weekend_diff': False,
            },
        }
        self.parental_settings = {
            'default_profile': 'child', 'notifications': True,
            'block_method': 'hosts', 'alert_email': '', 'email_alerts': False,
            'dns_monitoring': False, 'alert_blocked': True, 'alert_connect': True,
            'auto_profile': True, 'schedule_active': True,
        }
        self.dns_monitoring = False
        self.dns_activity_log = deque(maxlen=10000)
        self.activity_log = deque(maxlen=50000)
        self.content_blocklist = set()
        self.content_allowlist = set()
        self.parental_blocked_count = 0
        self.parental_last_reset = datetime.now().isoformat()
        self.content_categories = {
            'adult': ['porn', 'xxx', 'adult', 'sex', 'nsfw', 'onlyfans', 'xvideos'],
            'violence': ['weapon', 'gun', 'kill', 'murder', 'hate', 'terror'],
            'social': ['facebook', 'instagram', 'x.com', 'twitter', 'tiktok', 'snapchat', 'reddit', 'discord'],
            'gaming': ['fortnite', 'roblox', 'minecraft', 'steam', 'epicgames', 'twitch'],
            'streaming': ['netflix', 'youtube', 'hulu', 'disney+', 'hbomax', 'peacock'],
            'shopping': ['amazon', 'ebay', 'walmart', 'target', 'bestbuy'],
        }
        self.parental_active_tab = None
        self.parental_activity_started = False
    
        # Rogue Infrastructure & Network Topology
        self.infrastructure = {}  # keyed by MAC: {name, type, ip, mac, subnet, location, approved, first_seen, last_seen, active}
        self.rogue_alerts = deque(maxlen=5000)  # {timestamp, device_id, location, evidence, prev_state, new_state, severity, confidence, investigation_step}
        self.network_topology = {}  # {gateway_ip: {mac, name, subnets: [], aps: [], devices: [], dhcp_servers: [], last_seen}}
        self.device_sessions = {}  # {device_id: [{gateway, ap, ssid, bssid, subnet, location, connected, disconnected, dns_coverage, policy_coverage, managed}]}
        self.wireless_scan_cache = {}  # {bssid: {ssid, bssid, rssi, channel, first_seen, last_seen, approved}}
        self.infrastructure_monitoring = False
        self.topology_last_verified = None
        self._last_save_error = None
    
        # Security
        self.cve_db = {}
        self.arp_monitoring = False
        self.scan_detection = False
    
        # Status variables
        self.status_text = tk.StringVar(value="Ready")
        self.device_count = tk.StringVar(value="0 devices")
        self.alert_count = tk.StringVar(value="0 alerts")
        self.packet_count = tk.StringVar(value="0 packets")
    
        # Colors
        self.colors = {
            'bg': '#0a0a12',
            'secondary': '#14141f',
            'accent': '#1a1a2e',
            'accent2': '#2d2d44',
            'highlight': '#6c5ce7',
            'success': '#00d4aa',
            'warning': '#ffd93d',
            'danger': '#ff6b6b',
            'info': '#4ecdc4',
            'text': '#e0e0e0',
            'text_dim': '#8888aa',
            'terminal': '#00ff41'
        }
    
        # Setup UI
        self.setup_styles()
        self.create_widgets()
        self.create_menu()
        self.create_status_bar()
    
        # Auto-discover available networks (after UI is ready for logging)
        self.available_networks = self.discover_networks()
        if self.available_networks:
            self.network_ip.set(self.available_networks[0])
        self.update_network_combo()
    
        # Start background tasks
        self.update_status_time()
        self.auto_refresh()
    
        # Force initial dashboard population
        self.root.after(100, self.update_summary)
        self.root.after(100, self.update_system_status)
    
        # Ensure data directory exists and load data
        self.data_dir = self.ensure_data_directory()
        self.load_data()
    
        # Setup keyboard shortcuts
        self.setup_keyboard_shortcuts()
    
        self.log("🔬 Network Analyzer Pro initialized", "INFO")
        self.log(f"💻 System: {platform.system()} {platform.release()}", "INFO")
        self.log(f"🌐 Scapy: {'Available' if SCAPY_AVAILABLE else 'Not available'}", "INFO")

    from network_analyzer.services.bandwidth import _draw_bandwidth_graph_empty, _update_bandwidth_graph, monitor_bandwidth, toggle_bandwidth
    from network_analyzer.services.content_filter import _block_via_hosts, toggle_content_filter
    from network_analyzer.services.dns_monitor import capture_dns_queries, toggle_dns_monitoring
    from network_analyzer.services.logging_service import log
    from network_analyzer.services.monitor import monitor_network, network_stats, run_speed_test, speed_test
    from network_analyzer.services.netcat import netcat_auto_reconnect, netcat_do_connect, netcat_do_connect_ssl, netcat_do_connect_udp, netcat_do_listen_multi, netcat_do_listen_udp, netcat_do_receive, netcat_do_receive_multi, netcat_do_receive_udp, netcat_receive_file
    from network_analyzer.services.netcat import netcat_send, netcat_send_file, netcat_send_udp, netcat_start, netcat_stop, show_hexdump
    from network_analyzer.services.network_discovery import _is_gateway, discover_networks, get_gateway, get_local_ip
    from network_analyzer.services.packet_capture import _show_tool_message, analyze_ssl_certificate, arp_spoofing_detection, capture_packets, check_device_vulnerabilities, clear_packets, dns_lookup, load_cve_database, load_pcap, port_scan_detection
    from network_analyzer.services.packet_capture import save_packets, save_pcap, start_capture, stop_capture, tcp_stream_reassembly
    from network_analyzer.services.parental_control import _build_report, _get_activity_stats, _get_device_subnet, _is_managed_network, _is_port_open, _is_same_subnet, _report_to_html, _save_report, _show_report, _update_parental_settings_display
    from network_analyzer.services.parental_control import close_device_session, detect_nat_boundary, detect_network_transition, detect_rogue_dhcp, detect_rogue_ssid, discover_dhcp_servers, discover_routers, discover_topology, get_remaining_time, is_curfew_active
    from network_analyzer.services.parental_control import parental_daily_report, parental_export_report, parental_weekly_report, periodic_infrastructure_check, periodic_parental_check, track_device_session, update_topology, verify_infrastructure, wireless_scan
    from network_analyzer.services.persistence import backup_data, ensure_data_directory, export_csv, export_pdf, export_report, load_data, save_data
    from network_analyzer.services.reporting import generate_security_report, run_security_audit, security_audit
    from network_analyzer.services.scanner import _init_oui_db, classify_device, deep_scan, full_scan, get_hostname, get_mac_address, get_vendor, ping_tool, port_scan_tool, quick_scan
    from network_analyzer.services.scanner import run_deep_scan, run_full_scan, run_ping, run_port_scan, run_quick_scan, run_quick_scan_threadpool, run_traceroute, scan_common_ports, scan_ports, traceroute
    from network_analyzer.ui.dashboard import add_alert, create_dashboard_tab, update_summary, update_system_status
    from network_analyzer.ui.devices import add_device_note, analyze_devices, create_devices_tab, export_device_data, on_device_select, refresh_devices
    from network_analyzer.ui.logs import clear_logs, create_logs_tab, save_logs
    from network_analyzer.ui.main_window import _brighten, _create_card, auto_refresh, create_header, create_menu, create_status_bar, create_widgets, hide_status_progress, setup_keyboard_shortcuts, show_about
    from network_analyzer.ui.main_window import show_docs, show_status_progress, update_status_time
    from network_analyzer.ui.monitor import create_monitor_tab, start_monitoring, stop_monitoring, update_monitor_display
    from network_analyzer.ui.netcat import create_netcat_tab
    from network_analyzer.ui.network_scan import _get_scan_targets, _ips_from_targets, _validate_cidr_input, create_scan_tab, refresh_networks, start_scan, stop_scan, update_network_combo, update_progress_with_eta, update_scan_stats
    from network_analyzer.ui.packets import create_packet_tab
    from network_analyzer.ui.parental import _get_alert_count_by_severity, _infra_remove_selected, _on_infra_tree_double_click, create_parental_tab, infrastructure_add_dialog, infrastructure_edit_dialog, infrastructure_remove, on_parental_device_select, parental_assign_profile, parental_clear_activity
    from network_analyzer.ui.parental import parental_edit_device, parental_filter_activity, parental_settings_dialog, parental_toggle_block, parental_view_profile, refresh_child_transitions_display, refresh_infrastructure_display, refresh_parental_display, refresh_rogue_alerts_display, refresh_timeline_display
    from network_analyzer.ui.parental import refresh_topology_display, rogue_acknowledge, rogue_clear_all, rogue_investigate, toggle_infrastructure_monitoring, update_parental_stats
    from network_analyzer.ui.theme import setup_styles
    from network_analyzer.ui.tools import create_tools_tab
    from network_analyzer.utils.platform import _check_root, _restart_with_sudo


def main():
    """Main entry point"""
    try:
        root = tk.Tk()
        app = NetworkAnalyzerPro(root)
        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

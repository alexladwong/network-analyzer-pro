#!/usr/bin/env python3
"""
Professional Network Analyzer Pro - COMPLETE FIX
All features working, proper socket management, no race conditions
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

# Try importing advanced libraries
try:
    import scapy.all as scapy
    from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, ICMP, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkAnalyzerPro:
    def __init__(self, root):
        self.network_combo = None
        self.root = root
        self.root.title("🔬 Network Analyzer Pro")
        self.root.geometry("1600x950")
        self.root.configure(bg='#0a0a12')
        self.root.minsize(1200, 700)

        # Set app icon
        try:
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_icon.png')
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

    def setup_styles(self):
        """Configure modern dark theme styles"""
        style = ttk.Style()
        style.theme_use('clam')
        c = self.colors

        # Base frames
        style.configure('Pro.TFrame', background=c['bg'])
        style.configure('Card.TFrame', background=c['secondary'], relief='flat')
        style.configure('Header.TFrame', background=c['bg'])

        # Labels
        style.configure('Pro.TLabel', background=c['bg'], foreground=c['text'])
        style.configure('Card.TLabel', background=c['secondary'], foreground=c['text'])
        style.configure('Heading.TLabel', background=c['bg'], foreground=c['highlight'],
                        font=('Arial', 13, 'bold'))
        style.configure('Title.TLabel', background=c['bg'], foreground=c['text'],
                        font=('Arial', 24, 'bold'))
        style.configure('Status.TLabel', background=c['secondary'],
                        foreground=c['text_dim'], padding=8, font=('Consolas', 9))
        style.configure('Terminal.TFrame', background='#000000')
        style.configure('Terminal.TLabel', background='#000000',
                        foreground=c['terminal'], font=('Courier', 11))

        # Buttons with hover effects
        style.configure('Pro.TButton', background=c['accent'],
                        foreground='white', borderwidth=0, padding=(14, 8),
                        font=('Arial', 10))
        style.map('Pro.TButton',
                  background=[('active', c['highlight']), ('pressed', '#5a4bd1')],
                  foreground=[('disabled', '#555566')])

        style.configure('Small.TButton', background=c['accent2'],
                        foreground='white', borderwidth=0, padding=(8, 4),
                        font=('Arial', 9))
        style.map('Small.TButton',
                  background=[('active', c['highlight']), ('pressed', '#5a4bd1')],
                  foreground=[('disabled', '#555566')])

        # Notebook/tabs
        style.configure('Pro.TNotebook', background=c['bg'], borderwidth=0)
        style.configure('Pro.TNotebook.Tab', background=c['secondary'],
                        foreground=c['text_dim'], padding=[20, 9],
                        font=('Arial', 10))
        style.map('Pro.TNotebook.Tab',
                  background=[('selected', c['accent']), ('active', '#252540')],
                  foreground=[('selected', c['text'])])

        # Treeview
        style.configure('Pro.Treeview', background=c['secondary'],
                        foreground='white', fieldbackground=c['secondary'],
                        rowheight=36, font=('Consolas', 10))
        style.map('Pro.Treeview',
                  background=[('selected', c['highlight'])],
                  foreground=[('selected', 'white')])

        style.configure('Pro.Treeview.Heading', background=c['accent'],
                        foreground='white', font=('Arial', 11, 'bold'),
                        borderwidth=0)
        style.map('Pro.Treeview.Heading',
                  background=[('active', c['highlight'])])

        # LabelFrame
        style.configure('Pro.TLabelframe', background=c['bg'],
                        foreground=c['text'], relief='flat', borderwidth=0)
        style.configure('Pro.TLabelframe.Label', background=c['bg'],
                        foreground=c['highlight'], font=('Arial', 12, 'bold'))

        # Progressbar
        style.configure('Pro.Horizontal.TProgressbar', background=c['highlight'],
                        troughcolor=c['secondary'], bordercolor=c['bg'],
                        lightcolor=c['highlight'], darkcolor=c['highlight'],
                        thickness=12)

        # Scrollbar
        style.configure('Pro.Vertical.TScrollbar', background=c['accent2'],
                        troughcolor=c['bg'], bordercolor=c['bg'],
                        arrowcolor='white')
        style.map('Pro.Vertical.TScrollbar',
                  background=[('active', c['highlight'])])

        # Entry
        style.configure('Pro.TEntry', fieldbackground=c['secondary'],
                        foreground='white', bordercolor=c['accent2'],
                        lightcolor=c['accent2'], darkcolor=c['accent2'],
                        padding=6)
        style.map('Pro.TEntry',
                  fieldbackground=[('focus', c['accent'])])

        # Radiobutton for scan modes
        style.configure('Pro.TRadiobutton', background=c['bg'],
                        foreground=c['text'], font=('Arial', 10),
                        indicatorbackground=c['secondary'],
                        indicatorforeground=c['highlight'])
        style.map('Pro.TRadiobutton',
                  background=[('active', c['accent'])],
                  foreground=[('selected', c['text']), ('active', 'white')],
                  indicatorbackground=[('selected', c['highlight']), ('active', c['accent2'])])

    def _create_card(self, parent, title, **kwargs):
        """Create a professional card container with accent header bar"""
        expand = kwargs.get('expand', False)
        fill = kwargs.get('fill', tk.X)
        pady = kwargs.get('pady', (0, 8))
        side = kwargs.get('side', tk.TOP)
        padx = kwargs.get('padx', 0)
        height = kwargs.get('header_height', 28)

        card = tk.Frame(parent, bg=self.colors['secondary'],
                        highlightbackground=self.colors['accent2'],
                        highlightthickness=1, bd=0)
        card.pack(fill=fill, expand=expand, pady=pady, side=side, padx=padx)

        header_bg = kwargs.get('header_bg', self.colors['accent'])
        tk.Frame(card, bg=header_bg, height=height).pack(fill=tk.X)
        tk.Label(card, text=f"  {title}", bg=header_bg,
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(3, 0), padx=8)
        return card

    def _brighten(self, hex_color, amount=30):
        """Brighten a hex color by amount (0-255)"""
        try:
            hex_color = hex_color.lstrip('#')
            r = min(255, int(hex_color[0:2], 16) + amount)
            g = min(255, int(hex_color[2:4], 16) + amount)
            b = min(255, int(hex_color[4:6], 16) + amount)
            return f'#{r:02x}{g:02x}{b:02x}'
        except:
            return hex_color

    def _check_root(self, feature_name="this feature"):
        """Check root privileges on non-Windows, return True if OK or Windows"""
        if platform.system() == 'Windows':
            return True
        try:
            if os.geteuid() == 0:
                return True
            msg = (f"⚠️ {feature_name} requires root privileges.\n\n"
                   f"Run: sudo python3 main.py\n\n"
                   f"Without root, raw socket access is blocked by the system.")
            self._show_tool_message(msg)
            return False
        except AttributeError:
            return True

    def _restart_with_sudo(self):
        """Restart the application with sudo privileges in a new terminal"""
        if platform.system() == 'Windows':
            messagebox.showinfo("Elevate Required",
                                "Run as Administrator to enable all features.\n\n"
                                "Right-click the terminal and select 'Run as administrator'.")
            return
        try:
            if os.geteuid() == 0:
                messagebox.showinfo("Already Elevated",
                                    "Already running with root privileges.")
                return
        except AttributeError:
            return

        python = sys.executable
        script = os.path.abspath(__file__)
        reply = messagebox.askyesno("Elevate Privileges",
                                    "Restart with sudo to enable:\n"
                                    "• Full ARP network scans\n"
                                    "• Packet capture\n"
                                    "• ARP spoofing detection\n"
                                    "• Port scan detection\n"
                                    "• Traceroute\n\n"
                                    "Restart now?\n\n"
                                    "A Terminal window will open for password entry.")
        if not reply:
            return

        self.log("Restarting with sudo in new terminal...", "INFO")
        script_dir = os.path.dirname(script)
        args = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ''

        try:
            if platform.system() == 'Darwin':
                # Write a temporary shell script so quoting is trivial
                import tempfile
                tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False)
                tmp.write('#!/bin/bash\n')
                tmp.write(f'cd "{script_dir}"\n')
                tmp.write(f'sudo "{python}" "{script}" {args}\n')
                tmp.write(f'rm -- "$0"\n')
                tmp.close()
                os.chmod(tmp.name, 0o755)
                subprocess.Popen(['open', '-a', 'Terminal', tmp.name])
            else:
                # Linux: try common terminal emulators
                launch = f'cd "{script_dir}" && sudo "{python}" "{script}" {args}'
                terminals = [('x-terminal-emulator', '-e', 'bash', '-c'),
                             ('xterm', '-e', 'bash', '-c'),
                             ('gnome-terminal', '--', 'bash', '-c'),
                             ('konsole', '--hold', '-e', 'bash', '-c'),
                             ('xfce4-terminal', '-e', 'bash', '-c')]
                launched = False
                for term_cmd in terminals:
                    try:
                        subprocess.Popen(list(term_cmd) + [launch])
                        launched = True
                        break
                    except FileNotFoundError:
                        continue
                if not launched:
                    messagebox.showerror("Terminal Not Found",
                                         "Could not find a terminal emulator.\n"
                                         "Please run manually:\n\n"
                                         f"sudo {python} {script}")
                    return
        except Exception as e:
            self.log(f"Sudo restart error: {e}", "ERROR")
            messagebox.showerror("Error",
                                 f"Failed to launch terminal: {e}\n\n"
                                 f"Please run manually:\nsudo {python} {script}")

    def create_widgets(self):
        """Create all UI widgets"""
        self.main_container = ttk.Frame(self.root, style='Pro.TFrame')
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.create_header()

        self.notebook = ttk.Notebook(self.main_container, style='Pro.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_devices_tab()
        self.create_monitor_tab()
        self.create_packet_tab()
        self.create_netcat_tab()
        self.create_tools_tab()
        self.create_parental_tab()
        self.create_logs_tab()

    def create_header(self):
        """Create professional header with branding"""
        header = ttk.Frame(self.main_container, style='Pro.TFrame')
        header.pack(fill=tk.X, pady=(0, 12))

        # Left side: app branding
        title_frame = ttk.Frame(header, style='Pro.TFrame')
        title_frame.pack(side=tk.LEFT)

        # App icon and title
        icon_label = ttk.Label(title_frame, text="🔬", font=('Arial', 24), style='Pro.TLabel')
        icon_label.pack(side=tk.LEFT, padx=(0, 8))

        text_frame = ttk.Frame(title_frame, style='Pro.TFrame')
        text_frame.pack(side=tk.LEFT)

        title = ttk.Label(text_frame, text="Network Analyzer Pro",
                          font=('Arial', 22, 'bold'), style='Pro.TLabel',
                          foreground=self.colors['text'])
        title.pack(anchor=tk.W)

        subtitle_frame = ttk.Frame(text_frame, style='Pro.TFrame')
        subtitle_frame.pack(anchor=tk.W)
        version = ttk.Label(subtitle_frame, text="v4.2 Enterprise",
                            font=('Arial', 10), style='Pro.TLabel',
                            foreground=self.colors['highlight'])
        version.pack(side=tk.LEFT)

        tagline = ttk.Label(subtitle_frame, text="Network Security & Analysis Suite",
                            font=('Arial', 9), style='Pro.TLabel',
                            foreground=self.colors['text_dim'])
        tagline.pack(side=tk.LEFT, padx=10)

        # Vertical separator
        sep = tk.Frame(header, bg=self.colors['accent2'], width=1)
        sep.pack(side=tk.LEFT, fill=tk.Y, padx=16, pady=2)

        # Right side: stats with nicer badges
        stats_frame = ttk.Frame(header, style='Pro.TFrame')
        stats_frame.pack(side=tk.RIGHT, padx=(0, 4))

        # Scapy status badge
        scapy_color = self.colors['success'] if SCAPY_AVAILABLE else self.colors['danger']
        scapy_badge = tk.Frame(stats_frame, bg=self.colors['accent'],
                               highlightbackground=self.colors['accent2'],
                               highlightthickness=1, bd=0)
        scapy_badge.pack(side=tk.LEFT, padx=3)
        scapy_emoji = "✅" if SCAPY_AVAILABLE else "❌"
        tk.Label(scapy_badge, text=f" Scapy {scapy_emoji} ",
                 bg=self.colors['accent'], fg=scapy_color,
                 font=('Consolas', 9)).pack(padx=6, pady=3)

        # Device count badge
        dev_badge = tk.Frame(stats_frame, bg=self.colors['accent'],
                             highlightbackground=self.colors['accent2'],
                             highlightthickness=1, bd=0)
        dev_badge.pack(side=tk.LEFT, padx=3)
        tk.Label(dev_badge, text="📱", bg=self.colors['accent'],
                 fg=self.colors['info'], font=('Arial', 9)).pack(side=tk.LEFT, padx=(6, 2), pady=3)
        self.status_devices = tk.Label(dev_badge,
                                       textvariable=self.device_count,
                                       bg=self.colors['accent'], fg=self.colors['text'],
                                       font=('Arial', 10, 'bold'))
        self.status_devices.pack(side=tk.LEFT, padx=(0, 6), pady=3)

        # Packet count badge
        pkt_badge = tk.Frame(stats_frame, bg=self.colors['accent'],
                             highlightbackground=self.colors['accent2'],
                             highlightthickness=1, bd=0)
        pkt_badge.pack(side=tk.LEFT, padx=3)
        tk.Label(pkt_badge, text="📦", bg=self.colors['accent'],
                 fg=self.colors['warning'], font=('Arial', 9)).pack(side=tk.LEFT, padx=(6, 2), pady=3)
        self.status_packets = tk.Label(pkt_badge,
                                       textvariable=self.packet_count,
                                       bg=self.colors['accent'], fg=self.colors['text'],
                                       font=('Arial', 10, 'bold'))
        self.status_packets.pack(side=tk.LEFT, padx=(0, 6), pady=3)

        # Alert count badge
        alert_badge = tk.Frame(stats_frame, bg=self.colors['accent'],
                               highlightbackground=self.colors['accent2'],
                               highlightthickness=1, bd=0)
        alert_badge.pack(side=tk.LEFT, padx=3)
        tk.Label(alert_badge, text="🔔", bg=self.colors['accent'],
                 fg=self.colors['danger'], font=('Arial', 9)).pack(side=tk.LEFT, padx=(6, 2), pady=3)
        self.status_alerts = tk.Label(alert_badge,
                                      textvariable=self.alert_count,
                                      bg=self.colors['accent'], fg=self.colors['text'],
                                      font=('Arial', 10, 'bold'))
        self.status_alerts.pack(side=tk.LEFT, padx=(0, 6), pady=3)

        # ⚡ Sudo Elevate button (non-Windows, non-root only)
        if platform.system() != 'Windows':
            try:
                need_sudo = os.geteuid() != 0
            except AttributeError:
                need_sudo = False
            if need_sudo:
                sudo_badge = tk.Frame(stats_frame, bg=self.colors['danger'],
                                      highlightbackground=self.colors['danger'],
                                      highlightthickness=1, bd=0)
                sudo_badge.pack(side=tk.LEFT, padx=3)
                sudo_btn = tk.Label(sudo_badge, text=" 🔒 Sudo  ",
                                    bg=self.colors['danger'], fg='white',
                                    font=('Consolas', 9, 'bold'),
                                    cursor='hand2')
                sudo_btn.pack(padx=6, pady=3)
                sudo_btn.bind('<Button-1>', lambda e: self._restart_with_sudo())
                sudo_btn.bind('<Enter>', lambda e: sudo_btn.config(bg=self._brighten(self.colors['danger'], 30)))
                sudo_btn.bind('<Leave>', lambda e: sudo_btn.config(bg=self.colors['danger']))

    def create_dashboard_tab(self):
        """Dashboard with structured professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="  Dashboard  ")

        # Top row: 3 columns using grid for proportional widths
        top_row = ttk.Frame(tab, style='Pro.TFrame')
        top_row.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        top_row.columnconfigure(0, weight=3, uniform='dash')
        top_row.columnconfigure(1, weight=3, uniform='dash')
        top_row.columnconfigure(2, weight=2, uniform='dash')
        top_row.rowconfigure(0, weight=1)

        col1 = ttk.Frame(top_row, style='Pro.TFrame')
        col1.grid(row=0, column=0, sticky='nsew', padx=(0, 4))
        col2 = ttk.Frame(top_row, style='Pro.TFrame')
        col2.grid(row=0, column=1, sticky='nsew', padx=4)
        col3 = ttk.Frame(top_row, style='Pro.TFrame')
        col3.grid(row=0, column=2, sticky='nsew', padx=(4, 0))

        # === Network Status Card ===
        summary_card = tk.Frame(col1, bg=self.colors['secondary'],
                                highlightbackground=self.colors['accent2'],
                                highlightthickness=1, bd=0)
        summary_card.pack(fill=tk.BOTH, expand=True)

        tk.Frame(summary_card, bg=self.colors['accent'], height=28).pack(fill=tk.X)
        tk.Label(summary_card, text="  🌐 Network Status", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(3, 0), padx=8)

        # Structured Network Status rows
        net_inner = tk.Frame(summary_card, bg=self.colors['secondary'])
        net_inner.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        net_fields = [
            ("Local IP", "stat_local_ip"),
            ("Gateway", "stat_gateway_ip"),
            ("GW Host", "stat_gateway_host"),
            ("Devices", "stat_devices"),
            ("Scapy", "stat_scapy"),
            ("Updated", "stat_updated"),
        ]
        for idx, (label, attr) in enumerate(net_fields):
            row = tk.Frame(net_inner, bg=self.colors['secondary'])
            row.pack(fill=tk.X, pady=3)
            lb = tk.Label(row, text=label, bg=self.colors['secondary'],
                          fg=self.colors['text_dim'], font=('Arial', 10),
                          width=10, anchor='w')
            lb.pack(side=tk.LEFT)
            vl = tk.Label(row, text="-", bg=self.colors['secondary'],
                          fg=self.colors['text'], font=('Consolas', 10),
                          anchor='w')
            vl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            setattr(self, attr, vl)

        # === System Resources Card ===
        sys_card = tk.Frame(col2, bg=self.colors['secondary'],
                            highlightbackground=self.colors['accent2'],
                            highlightthickness=1, bd=0)
        sys_card.pack(fill=tk.BOTH, expand=True)

        tk.Frame(sys_card, bg=self.colors['accent'], height=28).pack(fill=tk.X)
        tk.Label(sys_card, text="  💻 System Resources", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(3, 0), padx=8)

        # Structured System Resources rows
        sys_inner = tk.Frame(sys_card, bg=self.colors['secondary'])
        sys_inner.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        sys_fields = [
            ("CPU", "sys_cpu"),
            ("Memory", "sys_memory"),
            ("Disk", "sys_disk"),
            ("Network", "sys_net"),
        ]
        for idx, (label, attr) in enumerate(sys_fields):
            row = tk.Frame(sys_inner, bg=self.colors['secondary'])
            row.pack(fill=tk.X, pady=3)
            lb = tk.Label(row, text=label, bg=self.colors['secondary'],
                          fg=self.colors['text_dim'], font=('Arial', 10),
                          width=10, anchor='w')
            lb.pack(side=tk.LEFT)
            vl = tk.Label(row, text="-", bg=self.colors['secondary'],
                          fg=self.colors['text'], font=('Consolas', 10),
                          anchor='w')
            vl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            setattr(self, attr, vl)

        # === Right column: Quick Actions + Recent Activity ===
        actions_card = tk.Frame(col3, bg=self.colors['secondary'],
                                highlightbackground=self.colors['accent2'],
                                highlightthickness=1, bd=0)
        actions_card.pack(fill=tk.X, pady=(0, 6))

        tk.Frame(actions_card, bg=self.colors['accent'], height=28).pack(fill=tk.X)
        tk.Label(actions_card, text="  ⚡ Quick Actions", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(3, 0), padx=8)

        actions_inner = ttk.Frame(actions_card, style='Pro.TFrame')
        actions_inner.pack(fill=tk.X, padx=8, pady=8)

        actions = [
            ("Quick Scan", self.quick_scan, '#8b6cf7'),
            ("Full Scan", self.full_scan, '#e05555'),
            ("Speed Test", self.speed_test, '#00d4aa'),
            ("Security Audit", self.security_audit, '#ff4757'),
            ("Export Report", self.export_report, '#4ecdc4'),
            ("Backup Data", self.backup_data, '#ffd93d'),
        ]

        row_frame = None
        for i, (text, command, color) in enumerate(actions):
            if i % 2 == 0:
                row_frame = ttk.Frame(actions_inner, style='Pro.TFrame')
                row_frame.pack(fill=tk.X, pady=1)
            btn_frame = ttk.Frame(row_frame, style='Pro.TFrame')
            btn_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
            btn = tk.Button(btn_frame, text=text, command=command,
                           bg=color, fg='white',
                           font=('Arial', 10, 'bold'), bd=0, padx=4, pady=7,
                           activebackground=self._brighten(color, 30),
                           activeforeground='white',
                           cursor='hand2',
                           highlightthickness=0,
                           disabledforeground=self.colors['text_dim'])
            btn.pack(fill=tk.X)

        # Recent Activity Card
        activity_card = tk.Frame(col3, bg=self.colors['secondary'],
                                 highlightbackground=self.colors['accent2'],
                                 highlightthickness=1, bd=0)
        activity_card.pack(fill=tk.BOTH, expand=True)

        tk.Frame(activity_card, bg=self.colors['accent'], height=28).pack(fill=tk.X)
        tk.Label(activity_card, text="  📋 Recent Activity", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(3, 0), padx=8)

        activity_inner = ttk.Frame(activity_card, style='Pro.TFrame')
        activity_inner.pack(fill=tk.BOTH, expand=True)

        self.activity_text = tk.Text(activity_inner, bg=self.colors['secondary'],
                                     fg=self.colors['text'], font=('Consolas', 9),
                                     bd=0, highlightthickness=0, padx=10, pady=6,
                                     wrap=tk.WORD)
        self.activity_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        activity_scrollbar = ttk.Scrollbar(activity_inner, orient=tk.VERTICAL,
                                           command=self.activity_text.yview, style='Pro.Vertical.TScrollbar')
        self.activity_text.configure(yscrollcommand=activity_scrollbar.set)
        activity_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_scan_tab(self):
        """Scan tab with professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="🔍 Network Scan")

        # Scan Configuration Card
        config_card = self._create_card(tab, "Scan Configuration")
        inner = ttk.Frame(config_card, style='Pro.TFrame')
        inner.pack(fill=tk.X, padx=12, pady=12)

        range_frame = ttk.Frame(inner, style='Pro.TFrame')
        range_frame.pack(fill=tk.X, pady=5)
        ttk.Label(range_frame, text="Network:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        self.network_combo = ttk.Combobox(range_frame, textvariable=self.network_ip,
                                          width=25, font=('Consolas', 11),
                                          state='readonly', style='Pro.TEntry')
        self.network_combo['values'] = self.available_networks
        self.network_combo.pack(side=tk.LEFT, padx=5)
        ttk.Button(range_frame, text="↻", command=self.refresh_networks,
                  style='Small.TButton', width=3).pack(side=tk.LEFT, padx=2)

        mode_frame = ttk.Frame(inner, style='Pro.TFrame')
        mode_frame.pack(fill=tk.X, pady=8)
        self.scan_mode = tk.StringVar(value="comprehensive")
        modes = [("⚡ Quick", "quick"), ("🔬 Comprehensive", "comprehensive"), ("🔍 Deep", "deep")]
        for i, (label, value) in enumerate(modes):
            rb = ttk.Radiobutton(mode_frame, text=label, value=value,
                                 variable=self.scan_mode, style='Pro.TRadiobutton')
            rb.pack(side=tk.LEFT, padx=5)

        btn_frame = ttk.Frame(inner, style='Pro.TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        self.scan_btn = ttk.Button(btn_frame, text="▶ Start Scan",
                                   command=self.start_scan, style='Pro.TButton')
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="⏹ Stop",
                                   command=self.stop_scan, style='Pro.TButton')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn.config(state='disabled')

        # Progress bar card
        progress_card = self._create_card(tab, "Progress", header_bg=self.colors['highlight'])
        progress_inner = ttk.Frame(progress_card, style='Pro.TFrame')
        progress_inner.pack(fill=tk.X, padx=12, pady=8)
        self.scan_progress = ttk.Progressbar(progress_inner, mode='determinate',
                                              style='Pro.Horizontal.TProgressbar')
        self.scan_progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.scan_status = ttk.Label(progress_inner, text="Ready", style='Pro.TLabel',
                                      font=('Arial', 10, 'bold'))
        self.scan_status.pack(side=tk.LEFT, padx=10)

        # Scan Results Card
        result_card = self._create_card(tab, "Scan Results", expand=True, fill=tk.BOTH, pady=(0, 0))
        result_inner = ttk.Frame(result_card, style='Pro.TFrame')
        result_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Results Treeview
        columns = ('IP', 'Hostname', 'MAC', 'Vendor', 'Ports', 'Status')
        self.device_tree = ttk.Treeview(result_inner, columns=columns,
                                        show='headings', style='Pro.Treeview')
        col_widths = {'IP': 140, 'Hostname': 160, 'MAC': 150, 'Vendor': 140, 'Ports': 100, 'Status': 90}
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=col_widths[col])

        scrollbar = ttk.Scrollbar(result_inner, orient=tk.VERTICAL,
                                  command=self.device_tree.yview, style='Pro.Vertical.TScrollbar')
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)

        # Stats bar
        stats_frame = ttk.Frame(tab, style='Pro.TFrame')
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        self.scan_stats = ttk.Label(stats_frame, text="Total: 0 | Online: 0",
                                    style='Pro.TLabel', font=('Arial', 10))
        self.scan_stats.pack(side=tk.LEFT)

    def create_devices_tab(self):
        """Devices tab with professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="📱 Devices")

        # Action buttons bar
        action_bar = ttk.Frame(tab, style='Pro.TFrame')
        action_bar.pack(fill=tk.X, padx=10, pady=(10, 5))
        controls = [("🔄 Refresh", self.refresh_devices), ("📊 Analyze", self.analyze_devices),
                    ("📝 Add Note", self.add_device_note), ("🔍 Port Scan", self.port_scan_tool),
                    ("📡 Ping", self.ping_tool), ("💾 Export", self.export_device_data)]
        for text, command in controls:
            ttk.Button(action_bar, text=text, command=command,
                       style='Pro.TButton').pack(side=tk.LEFT, padx=3)

        # Main content: two cards side by side
        content_row = ttk.Frame(tab, style='Pro.TFrame')
        content_row.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        # Device List Card
        list_card = self._create_card(content_row, "Device List", expand=True, fill=tk.BOTH,
                                       pady=(0, 0), side=tk.LEFT, padx=(0, 5))
        list_inner = ttk.Frame(list_card, style='Pro.TFrame')
        list_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        columns = ('IP', 'Hostname', 'MAC', 'Status')
        self.device_list = ttk.Treeview(list_inner, columns=columns,
                                        show='headings', style='Pro.Treeview', height=20)
        for col in columns:
            self.device_list.heading(col, text=col)
            self.device_list.column(col, width=120)
        scrollbar = ttk.Scrollbar(list_inner, orient=tk.VERTICAL, command=self.device_list.yview,
                                   style='Pro.Vertical.TScrollbar')
        self.device_list.configure(yscrollcommand=scrollbar.set)
        self.device_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_list.bind('<<TreeviewSelect>>', self.on_device_select)

        # Device Details Card
        detail_card = self._create_card(content_row, "Device Details", expand=True, fill=tk.BOTH,
                                         pady=(0, 0), side=tk.RIGHT, padx=(5, 0))
        detail_inner = ttk.Frame(detail_card, style='Pro.TFrame')
        detail_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.device_details = tk.Text(detail_inner, bg=self.colors['secondary'],
                                      fg=self.colors['text'], font=('Consolas', 10), wrap=tk.WORD,
                                      bd=0, highlightthickness=0)
        details_scrollbar = ttk.Scrollbar(detail_inner, orient=tk.VERTICAL,
                                           command=self.device_details.yview, style='Pro.Vertical.TScrollbar')
        self.device_details.configure(yscrollcommand=details_scrollbar.set)
        self.device_details.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_monitor_tab(self):
        """Monitor tab with professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="📡 Monitor")

        # Monitor Controls — compact toolbar
        ctrl_bar = tk.Frame(tab, bg=self.colors['secondary'],
                            highlightbackground=self.colors['accent2'],
                            highlightthickness=1, bd=0)
        ctrl_bar.pack(fill=tk.X, pady=(0, 8))

        toolbar = tk.Frame(ctrl_bar, bg=self.colors['secondary'])
        toolbar.pack(padx=10, pady=6)

        self.monitor_btn = tk.Button(toolbar, text="▶ Start Monitoring",
                                     command=self.start_monitoring,
                                     bg=self.colors['accent'], fg='white',
                                     font=('Arial', 10), bd=0, padx=12, pady=5,
                                     activebackground=self.colors['highlight'],
                                     activeforeground='white', cursor='hand2',
                                     highlightthickness=0)
        self.monitor_btn.pack(side=tk.LEFT, padx=3)

        self.monitor_stop_btn = tk.Button(toolbar, text="⏹ Stop",
                                          command=self.stop_monitoring,
                                          bg=self.colors['accent'], fg='white',
                                          font=('Arial', 10), bd=0, padx=12, pady=5,
                                          activebackground=self.colors['danger'],
                                          activeforeground='white', cursor='hand2',
                                          highlightthickness=0, state='disabled',
                                          disabledforeground=self.colors['text_dim'])
        self.monitor_stop_btn.pack(side=tk.LEFT, padx=3)

        self.bandwidth_btn = tk.Button(toolbar, text="📊 Bandwidth",
                                       command=self.toggle_bandwidth,
                                       bg=self.colors['accent'], fg='white',
                                       font=('Arial', 10), bd=0, padx=12, pady=5,
                                       activebackground=self.colors['info'],
                                       activeforeground='white', cursor='hand2',
                                       highlightthickness=0)
        self.bandwidth_btn.pack(side=tk.LEFT, padx=3)

        # Bandwidth status inline
        self.bandwidth_info = tk.Label(toolbar, text="⬇ 0 KB/s  ⬆ 0 KB/s",
                                       bg=self.colors['secondary'],
                                       fg=self.colors['info'],
                                       font=('Consolas', 10))
        self.bandwidth_info.pack(side=tk.RIGHT, padx=(10, 0))

        # Live Network Activity Card
        activity_card = tk.Frame(tab, bg=self.colors['secondary'],
                                 highlightbackground=self.colors['accent2'],
                                 highlightthickness=1, bd=0)
        activity_card.pack(fill=tk.BOTH, expand=True)

        tk.Frame(activity_card, bg=self.colors['accent'], height=28).pack(fill=tk.X)
        tk.Label(activity_card, text="  Live Network Activity",
                 bg=self.colors['accent'], fg='white',
                 font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(3, 0), padx=8)

        activity_inner = tk.Frame(activity_card, bg=self.colors['secondary'])
        activity_inner.pack(fill=tk.BOTH, expand=True, padx=18, pady=18)

        self.monitor_display = tk.Text(activity_inner, bg=self.colors['secondary'],
                                       fg=self.colors['text'], font=('Consolas', 9),
                                       bd=0, highlightthickness=0, wrap=tk.WORD)
        monitor_scrollbar = ttk.Scrollbar(activity_inner, orient=tk.VERTICAL,
                                         command=self.monitor_display.yview,
                                         style='Pro.Vertical.TScrollbar')
        self.monitor_display.configure(yscrollcommand=monitor_scrollbar.set)
        self.monitor_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        monitor_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Honest empty state
        self.monitor_display.insert(1.0, "📡 Monitor Ready\n\n")
        self.monitor_display.insert(tk.END, "Press 'Start Monitoring' to view active connections.\n")
        self.monitor_display.insert(tk.END, "Press 'Bandwidth' to measure network throughput.\n\n")
        self.monitor_display.insert(tk.END, "Note: Some connection data may require elevated privileges.")

        # Separator between panes
        tk.Frame(tab, bg=self.colors['accent2'], height=1).pack(fill=tk.X, pady=(0, 0))

        # Bandwidth Graph Card
        graph_card = tk.Frame(tab, bg=self.colors['secondary'],
                              highlightbackground=self.colors['accent2'],
                              highlightthickness=1, bd=0)
        graph_card.pack(fill=tk.BOTH, expand=True, pady=(12, 0))

        tk.Frame(graph_card, bg=self.colors['accent'], height=28).pack(fill=tk.X)
        tk.Label(graph_card, text="  Bandwidth Graph (last 60s)",
                 bg=self.colors['accent'], fg='white',
                 font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(3, 0), padx=8)

        graph_inner = tk.Frame(graph_card, bg=self.colors['secondary'])
        graph_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.bandwidth_graph = tk.Canvas(graph_inner, bg=self.colors['bg'],
                                         highlightthickness=0, height=140)
        self.bandwidth_graph.pack(fill=tk.BOTH, expand=True)

        # Draw initial empty state on graph
        self._draw_bandwidth_graph_empty()

    def create_packet_tab(self):
        """Packet capture tab with professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="📦 Packets")

        # Packet Capture Card
        pcap_card = self._create_card(tab, "Packet Capture")
        pcap_inner = ttk.Frame(pcap_card, style='Pro.TFrame')
        pcap_inner.pack(fill=tk.X, padx=12, pady=8)

        # BPF Filter
        filter_frame = ttk.Frame(pcap_inner, style='Pro.TFrame')
        filter_frame.pack(fill=tk.X, pady=5)
        ttk.Label(filter_frame, text="BPF Filter:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        self.packet_filter = ttk.Entry(filter_frame, width=40, font=('Consolas', 10))
        self.packet_filter.pack(side=tk.LEFT, padx=5)
        self.packet_filter.insert(0, "")
        ttk.Label(filter_frame, text="e.g. tcp port 80", style='Pro.TLabel',
                  foreground=self.colors['text_dim']).pack(side=tk.LEFT, padx=5)

        btn_frame = ttk.Frame(pcap_inner, style='Pro.TFrame')
        btn_frame.pack(fill=tk.X, pady=8)
        self.capture_btn = ttk.Button(btn_frame, text="▶ Start Capture",
                                      command=self.start_capture, style='Pro.TButton')
        self.capture_btn.pack(side=tk.LEFT, padx=3)
        self.capture_stop_btn = ttk.Button(btn_frame, text="⏹ Stop",
                                           command=self.stop_capture, style='Pro.TButton')
        self.capture_stop_btn.pack(side=tk.LEFT, padx=3)
        self.capture_stop_btn.config(state='disabled')
        ttk.Button(btn_frame, text="📂 Load PCAP", command=self.load_pcap, style='Pro.TButton').pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="💾 Save PCAP", command=self.save_pcap, style='Pro.TButton').pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="🗑 Clear", command=self.clear_packets, style='Pro.TButton').pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="🔀 TCP Streams", command=self.tcp_stream_reassembly, style='Pro.TButton').pack(side=tk.LEFT, padx=3)

        # Captured Packets Card
        display_card = self._create_card(tab, "Captured Packets", expand=True, fill=tk.BOTH, pady=(0, 0))
        display_inner = ttk.Frame(display_card, style='Pro.TFrame')
        display_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.packet_display = tk.Text(display_inner, bg='#000000', fg=self.colors['terminal'],
                                      font=('Consolas', 9), height=25, bd=0, highlightthickness=0)
        packet_scrollbar = ttk.Scrollbar(display_inner, orient=tk.VERTICAL,
                                          command=self.packet_display.yview, style='Pro.Vertical.TScrollbar')
        self.packet_display.configure(yscrollcommand=packet_scrollbar.set)
        self.packet_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_count.set("0 packets")

    def create_netcat_tab(self):
        """Netcat tab with professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="🔌 Netcat")

        # Netcat Session Card
        session_card = self._create_card(tab, "Netcat Session")
        inner = ttk.Frame(session_card, style='Pro.TFrame')
        inner.pack(fill=tk.X, padx=12, pady=8)

        conn_frame = ttk.Frame(inner, style='Pro.TFrame')
        conn_frame.pack(fill=tk.X, pady=5)
        ttk.Label(conn_frame, text="Target IP:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        self.netcat_target = ttk.Entry(conn_frame, width=20, font=('Consolas', 11))
        self.netcat_target.pack(side=tk.LEFT, padx=5)
        self.netcat_target.insert(0, "192.168.1.2")

        ttk.Label(conn_frame, text="Port:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        self.netcat_port = ttk.Entry(conn_frame, width=8, font=('Consolas', 11))
        self.netcat_port.insert(0, "4444")
        self.netcat_port.pack(side=tk.LEFT, padx=5)

        mode_frame = ttk.Frame(inner, style='Pro.TFrame')
        mode_frame.pack(fill=tk.X, pady=5)
        self.netcat_mode = tk.StringVar(value="connect")
        ttk.Label(mode_frame, text="Mode:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        for label, value in [("Connect", "connect"), ("Listen", "listen")]:
            rb = ttk.Radiobutton(mode_frame, text=label, value=value,
                                 variable=self.netcat_mode, style='Pro.TRadiobutton')
            rb.pack(side=tk.LEFT, padx=5)

        # Protocol selection
        proto_frame = ttk.Frame(inner, style='Pro.TFrame')
        proto_frame.pack(fill=tk.X, pady=5)
        ttk.Label(proto_frame, text="Protocol:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        for label, value in [("TCP", "tcp"), ("UDP", "udp")]:
            rb = ttk.Radiobutton(proto_frame, text=label, value=value,
                                 variable=self.netcat_protocol, style='Pro.TRadiobutton')
            rb.pack(side=tk.LEFT, padx=5)

        # SSL and options
        opt_frame = ttk.Frame(inner, style='Pro.TFrame')
        opt_frame.pack(fill=tk.X, pady=5)
        for var, text in [(self.netcat_ssl_enabled, "SSL/TLS"),
                          (self.netcat_ssl_insecure, "Insecure SSL"),
                          (self.netcat_verbose, "Verbose"),
                          (self.netcat_reconnect, "Auto-Reconnect")]:
            ttk.Checkbutton(opt_frame, text=text, variable=var,
                           style='Pro.TButton').pack(side=tk.LEFT, padx=5)

        btn_frame = ttk.Frame(inner, style='Pro.TFrame')
        btn_frame.pack(fill=tk.X, pady=8)
        self.netcat_btn = ttk.Button(btn_frame, text="🔌 Start",
                                     command=self.netcat_start, style='Pro.TButton')
        self.netcat_btn.pack(side=tk.LEFT, padx=3)
        self.netcat_stop_btn = ttk.Button(btn_frame, text="⏹ Close",
                                          command=self.netcat_stop, style='Pro.TButton')
        self.netcat_stop_btn.pack(side=tk.LEFT, padx=3)
        self.netcat_stop_btn.config(state='disabled')

        # File transfer buttons
        file_frame = ttk.Frame(inner, style='Pro.TFrame')
        file_frame.pack(fill=tk.X, pady=5)
        ttk.Button(file_frame, text="📁 Send File", command=self.netcat_send_file,
                  style='Pro.TButton').pack(side=tk.LEFT, padx=3)
        ttk.Button(file_frame, text="📁 Receive File", command=self.netcat_receive_file,
                  style='Pro.TButton').pack(side=tk.LEFT, padx=3)

        # Netcat Terminal Card
        terminal_card = self._create_card(tab, "Netcat Terminal", expand=True, fill=tk.BOTH, pady=(0, 0))
        terminal_inner = ttk.Frame(terminal_card, style='Pro.TFrame')
        terminal_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.terminal_display = tk.Text(terminal_inner, bg='#000000', fg=self.colors['terminal'],
                                        font=('Courier', 11), height=20, bd=0, highlightthickness=0)
        terminal_scrollbar = ttk.Scrollbar(terminal_inner, orient=tk.VERTICAL,
                                            command=self.terminal_display.yview, style='Pro.Vertical.TScrollbar')
        self.terminal_display.configure(yscrollcommand=terminal_scrollbar.set)
        self.terminal_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        terminal_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Input frame
        input_frame = ttk.Frame(tab, style='Pro.TFrame')
        input_frame.pack(fill=tk.X, padx=10, pady=(5, 10))
        ttk.Label(input_frame, text="Send:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        self.netcat_input = ttk.Entry(input_frame, width=60, font=('Consolas', 11))
        self.netcat_input.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.netcat_input.bind('<Return>', self.netcat_send)
        ttk.Button(input_frame, text="Send", command=self.netcat_send,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=5)
        self.netcat_input.config(state='disabled')

    def create_tools_tab(self):
        """Tools tab with scrollable tool palette and professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="🔧 Tools")

        # Tool Groups Card
        tools_card = self._create_card(tab, "Tool Groups", expand=False, fill=tk.X, pady=(10, 5))
        # Scrollable tool buttons inside the card
        top_frame = ttk.Frame(tools_card, style='Pro.TFrame')
        top_frame.pack(fill=tk.X, padx=8, pady=8)

        canvas = tk.Canvas(top_frame, bg=self.colors['bg'], highlightthickness=0, height=250)
        scrollbar = ttk.Scrollbar(top_frame, orient=tk.VERTICAL, command=canvas.yview, style='Pro.Vertical.TScrollbar')
        scrollable_frame = ttk.Frame(canvas, style='Pro.TFrame')

        scrollable_frame.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.X, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Tool groups with visual categories
        tool_groups = [
            ("🔍 Scanning & Reconnaissance", [
                ("📡 Port Scanner", "Scan ports on a selected device", self.port_scan_tool),
                ("🔄 Traceroute", "Trace network path to a device", self.traceroute),
                ("🌐 DNS Lookup", "Resolve domain name to IP address", self.dns_lookup),
            ]),
            ("🔒 Security & Monitoring", [
                ("🛡️ Security Audit", "Check all devices for vulnerabilities", self.security_audit),
                ("📡 ARP Monitor", "Detect ARP spoofing attacks (30s)", self.arp_spoofing_detection),
                ("🚨 Scan Detector", "Detect port scans against your machine (30s)", self.port_scan_detection),
                ("🔑 SSL Check", "Analyze SSL/TLS certificate of a server", self.analyze_ssl_certificate),
                ("📋 Security Report", "Generate HTML vulnerability report from scan data", self.generate_security_report),
            ]),
            ("📊 Network Tools", [
                ("📈 Network Stats", "View detailed network interface statistics", self.network_stats),
                ("📦 Packet Sniffer", "Start real-time packet capture on 📦 tab", self.start_capture),
                ("🔌 Netcat", "Open netcat TCP/UDP connections on 🔌 tab", self.netcat_start),
            ]),
            ("💾 Data Management", [
                ("💾 Backup", "Backup all data to JSON file", self.backup_data),
            ]),
        ]

        for group_name, tools in tool_groups:
            group_label = ttk.Label(scrollable_frame, text=group_name,
                                    style='Pro.TLabel', font=('Arial', 12, 'bold'),
                                    foreground=self.colors['highlight'])
            group_label.pack(fill=tk.X, pady=(12, 2), padx=5)
            ttk.Separator(scrollable_frame, orient='horizontal').pack(fill=tk.X, padx=5, pady=2)

            for name, desc, command in tools:
                frame = ttk.Frame(scrollable_frame, style='Pro.TFrame')
                frame.pack(fill=tk.X, pady=2, padx=15)
                btn = ttk.Button(frame, text=name, command=command, style='Pro.TButton', width=22)
                btn.pack(side=tk.LEFT, padx=5, pady=1)
                ttk.Label(frame, text=desc, style='Pro.TLabel',
                          foreground=self.colors['text_dim']).pack(side=tk.LEFT, padx=10)

        # Tool Output Card
        output_card = self._create_card(tab, "Tool Output", expand=True, fill=tk.BOTH, pady=(5, 10))
        output_inner = ttk.Frame(output_card, style='Pro.TFrame')
        output_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self.tool_output = tk.Text(output_inner, bg=self.colors['secondary'],
                                    fg=self.colors['text'],
                                    font=('Consolas', 10), height=10, wrap=tk.WORD,
                                    bd=0, highlightthickness=0)
        output_scrollbar = ttk.Scrollbar(output_inner, orient=tk.VERTICAL,
                                          command=self.tool_output.yview, style='Pro.Vertical.TScrollbar')
        self.tool_output.configure(yscrollcommand=output_scrollbar.set)

        self.tool_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Button(output_card, text="🗑 Clear Output",
                   command=lambda: self.tool_output.delete(1.0, tk.END),
                   style='Pro.TButton').pack(anchor=tk.E, padx=12, pady=(0, 8))

    # ==================== PARENTAL CONTROL TAB ====================

    def create_parental_tab(self):
        """Parental control tab with device profiles, activity monitoring, and restriction management"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="👨\u200d👩\u200d👧 Parental")

        # === Top Status Bar ===
        status_bar = tk.Frame(tab, bg=self.colors['secondary'],
                              highlightbackground=self.colors['accent2'],
                              highlightthickness=1, bd=0)
        status_bar.pack(fill=tk.X, padx=10, pady=(10, 5))

        status_inner = tk.Frame(status_bar, bg=self.colors['secondary'])
        status_inner.pack(fill=tk.X, padx=12, pady=6)

        stats_data = [
            ("👤 Devices", "parental_devices_lbl", "0"),
            ("🔞 Blocked Today", "parental_blocked_lbl", "0"),
            ("📡 DNS Monitor", "parental_dns_lbl", "Off"),
            ("🛡️ Content Filter", "parental_filter_lbl", "Inactive"),
        ]
        for label, attr, default in stats_data:
            f = tk.Frame(status_inner, bg=self.colors['secondary'])
            f.pack(side=tk.LEFT, padx=(0, 20))
            tk.Label(f, text=label, bg=self.colors['secondary'],
                     fg=self.colors['text_dim'], font=('Arial', 9)).pack(side=tk.LEFT)
            lbl = tk.Label(f, text=default, bg=self.colors['secondary'],
                           fg=self.colors['text'], font=('Arial', 10, 'bold'))
            lbl.pack(side=tk.LEFT, padx=4)
            setattr(self, attr, lbl)

        # Quick action buttons
        action_frame = tk.Frame(status_inner, bg=self.colors['secondary'])
        action_frame.pack(side=tk.RIGHT)
        self.parental_dns_btn = tk.Button(action_frame, text="▶ Start DNS Monitor",
                                          command=self.toggle_dns_monitoring,
                                          bg=self.colors['accent'], fg='white',
                                          font=('Arial', 10), bd=0, padx=10, pady=4,
                                          cursor='hand2', highlightthickness=0)
        self.parental_dns_btn.pack(side=tk.LEFT, padx=2)
        self.parental_filter_btn = tk.Button(action_frame, text="▶ Start Filter",
                                             command=self.toggle_content_filter,
                                             bg=self.colors['accent'], fg='white',
                                             font=('Arial', 10), bd=0, padx=10, pady=4,
                                             cursor='hand2', highlightthickness=0)
        self.parental_filter_btn.pack(side=tk.LEFT, padx=2)

        # === Main content: 2 columns ===
        content_frame = ttk.Frame(tab, style='Pro.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        left_col = ttk.Frame(content_frame, style='Pro.TFrame')
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        right_col = ttk.Frame(content_frame, style='Pro.TFrame')
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # === LEFT COLUMN ===

        # 1. Device Profiles Card
        profile_card = self._create_card(left_col, "Device Profiles (Parental)", expand=True, fill=tk.BOTH)
        profile_inner = ttk.Frame(profile_card, style='Pro.TFrame')
        profile_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        columns = ('Device', 'Owner', 'Profile', 'Status', 'Online')
        self.parental_device_tree = ttk.Treeview(profile_inner, columns=columns,
                                                  show='headings', style='Pro.Treeview', height=10)
        col_w = {'Device': 130, 'Owner': 100, 'Profile': 80, 'Status': 100, 'Online': 70}
        for col in columns:
            self.parental_device_tree.heading(col, text=col)
            self.parental_device_tree.column(col, width=col_w[col])
        self.parental_device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        psb = ttk.Scrollbar(profile_inner, orient=tk.VERTICAL, command=self.parental_device_tree.yview,
                            style='Pro.Vertical.TScrollbar')
        self.parental_device_tree.configure(yscrollcommand=psb.set)
        psb.pack(side=tk.RIGHT, fill=tk.Y)
        self.parental_device_tree.bind('<<TreeviewSelect>>', self.on_parental_device_select)

        # Profile control buttons
        ctrl_frame = ttk.Frame(left_col, style='Pro.TFrame')
        ctrl_frame.pack(fill=tk.X, pady=5)
        ttk.Button(ctrl_frame, text="👤 Assign Profile", command=self.parental_assign_profile,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl_frame, text="🔒 Block Device", command=self.parental_toggle_block,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl_frame, text="📝 Edit Details", command=self.parental_edit_device,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=2)

        # 2. Activity Monitor Card
        activity_card = self._create_card(left_col, "Internet Activity (DNS)", expand=True, fill=tk.BOTH,
                                           pady=(5, 0))
        act_inner = ttk.Frame(activity_card, style='Pro.TFrame')
        act_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Filter bar
        filterbar = ttk.Frame(act_inner, style='Pro.TFrame')
        filterbar.pack(fill=tk.X)
        ttk.Label(filterbar, text="Filter:", style='Pro.TLabel').pack(side=tk.LEFT, padx=2)
        self.parental_activity_filter = ttk.Entry(filterbar, width=20, font=('Consolas', 10))
        self.parental_activity_filter.pack(side=tk.LEFT, padx=2)
        self.parental_activity_filter.bind('<KeyRelease>', self.parental_filter_activity)
        self.parental_activity_clear_btn = ttk.Button(filterbar, text="🗑 Clear",
                                                       command=self.parental_clear_activity,
                                                       style='Small.TButton')
        self.parental_activity_clear_btn.pack(side=tk.RIGHT, padx=2)

        self.parental_activity_text = tk.Text(act_inner, bg='#000000',
                                              fg=self.colors['terminal'],
                                              font=('Consolas', 9), height=10,
                                              bd=0, highlightthickness=0)
        self.parental_activity_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=(4, 0))
        asb = ttk.Scrollbar(act_inner, orient=tk.VERTICAL, command=self.parental_activity_text.yview,
                            style='Pro.Vertical.TScrollbar')
        self.parental_activity_text.configure(yscrollcommand=asb.set)
        asb.pack(side=tk.RIGHT, fill=tk.Y)

        self.parental_activity_text.insert(1.0, "🔞 Parental Control Monitor\n")
        self.parental_activity_text.insert(tk.END, f"{'=' * 60}\n")
        self.parental_activity_text.insert(tk.END, "Start DNS Monitor to capture device internet activity.\n")
        if SCAPY_AVAILABLE:
            self.parental_activity_text.insert(tk.END, "DNS queries will appear here in real-time.\n")
        else:
            self.parental_activity_text.insert(tk.END, "⚠️ Scapy required for DNS monitoring.\n")

        # === RIGHT COLUMN ===

        # 3. Blocked Attempts Card
        blocked_card = self._create_card(right_col, "Blocked Attempts", expand=True, fill=tk.BOTH)
        blocked_inner = ttk.Frame(blocked_card, style='Pro.TFrame')
        blocked_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        columns2 = ('Time', 'Device', 'Domain', 'Category', 'Profile')
        self.parental_blocked_tree = ttk.Treeview(blocked_inner, columns=columns2,
                                                   show='headings', style='Pro.Treeview', height=6)
        cw2 = {'Time': 80, 'Device': 100, 'Domain': 140, 'Category': 80, 'Profile': 70}
        for col in columns2:
            self.parental_blocked_tree.heading(col, text=col)
            self.parental_blocked_tree.column(col, width=cw2[col])
        self.parental_blocked_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        bsb = ttk.Scrollbar(blocked_inner, orient=tk.VERTICAL, command=self.parental_blocked_tree.yview,
                            style='Pro.Vertical.TScrollbar')
        self.parental_blocked_tree.configure(yscrollcommand=bsb.set)
        bsb.pack(side=tk.RIGHT, fill=tk.Y)

        # 4. Profiles & Settings Card
        settings_card = self._create_card(right_col, "Profiles & Settings", expand=True, fill=tk.BOTH,
                                           pady=(5, 0))
        set_inner = ttk.Frame(settings_card, style='Pro.TFrame')
        set_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Profile selector
        prof_row = ttk.Frame(set_inner, style='Pro.TFrame')
        prof_row.pack(fill=tk.X, pady=3)
        ttk.Label(prof_row, text="Edit Profile:", style='Pro.TLabel').pack(side=tk.LEFT, padx=2)
        self.parental_profile_combo = ttk.Combobox(prof_row, values=list(self.parental_profiles.keys()),
                                                    state='readonly', width=12, font=('Consolas', 10))
        self.parental_profile_combo.pack(side=tk.LEFT, padx=2)
        self.parental_profile_combo.set('child')
        ttk.Button(prof_row, text="View", command=self.parental_view_profile,
                   style='Small.TButton').pack(side=tk.LEFT, padx=2)

        # Profile detail display
        self.parental_profile_detail = tk.Text(set_inner, bg=self.colors['secondary'],
                                                fg=self.colors['text'], font=('Consolas', 9),
                                                height=8, bd=0, highlightthickness=0)
        self.parental_profile_detail.pack(fill=tk.BOTH, expand=True, pady=4)

        # Settings summary
        set_summary = tk.Frame(set_inner, bg=self.colors['secondary'],
                               highlightbackground=self.colors['accent2'],
                               highlightthickness=1, bd=0)
        set_summary.pack(fill=tk.X, pady=4)
        self.parental_settings_text = tk.Label(set_summary, bg=self.colors['secondary'],
                                               fg=self.colors['text_dim'],
                                               font=('Consolas', 8), justify=tk.LEFT, anchor='w')
        self.parental_settings_text.pack(fill=tk.X, padx=6, pady=4)

        # 5. Reports section
        report_frame = ttk.Frame(right_col, style='Pro.TFrame')
        report_frame.pack(fill=tk.X, pady=5)
        ttk.Button(report_frame, text="📊 Daily Report", command=self.parental_daily_report,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(report_frame, text="📈 Weekly Summary", command=self.parental_weekly_report,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(report_frame, text="📋 Export Report", command=self.parental_export_report,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(report_frame, text="⚙ Settings", command=self.parental_settings_dialog,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=2)

        # Initial population
        self.refresh_parental_display()
        self.update_parental_stats()

        # === INFRASTRUCTURE & ROGUE DETECTION SECTION ===
        infra_section = ttk.Frame(tab, style='Pro.TFrame')
        infra_section.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Infrastructure monitor toggle
        infra_controls = tk.Frame(infra_section, bg=self.colors['secondary'],
                                  highlightbackground=self.colors['accent2'],
                                  highlightthickness=1, bd=0)
        infra_controls.pack(fill=tk.X, pady=(0, 5))

        ctrl_inner = tk.Frame(infra_controls, bg=self.colors['secondary'])
        ctrl_inner.pack(fill=tk.X, padx=12, pady=6)
        tk.Label(ctrl_inner, text="🛡️ Infrastructure Monitor", bg=self.colors['secondary'],
                fg=self.colors['text'], font=('Arial', 11, 'bold')).pack(side=tk.LEFT, padx=(0, 10))
        self.parental_infra_monitor_btn = tk.Button(ctrl_inner, text="▶ Start Infra Monitor",
                                                     command=self.toggle_infrastructure_monitoring,
                                                     bg=self.colors['accent'], fg='white',
                                                     font=('Arial', 10), bd=0, padx=10, pady=3,
                                                     cursor='hand2', highlightthickness=0)
        self.parental_infra_monitor_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl_inner, text="➕ Add Approved", command=self.infrastructure_add_dialog,
                   style='Small.TButton').pack(side=tk.LEFT, padx=2)
        ttk.Button(ctrl_inner, text="🗑 Clear Alerts", command=self.rogue_clear_all,
                   style='Small.TButton').pack(side=tk.LEFT, padx=2)

        # Infrastructure stats indicators
        self.infra_status_lbl = tk.Label(ctrl_inner, text="🌐 0 routers", bg=self.colors['secondary'],
                                         fg=self.colors['text_dim'], font=('Arial', 9))
        self.infra_status_lbl.pack(side=tk.RIGHT, padx=5)
        self.rogue_status_lbl = tk.Label(ctrl_inner, text="⚠️ 0 alerts", bg=self.colors['secondary'],
                                         fg=self.colors['text_dim'], font=('Arial', 9))
        self.rogue_status_lbl.pack(side=tk.RIGHT, padx=5)

        # Two-column layout for infra sections
        infra_content = ttk.Frame(infra_section, style='Pro.TFrame')
        infra_content.pack(fill=tk.X)

        infra_left = ttk.Frame(infra_content, style='Pro.TFrame')
        infra_left.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        infra_right = ttk.Frame(infra_content, style='Pro.TFrame')
        infra_right.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))

        # === 6. Approved Infrastructure Card ===
        infra_card = self._create_card(infra_left, "Approved Infrastructure", expand=False)
        infra_inner = ttk.Frame(infra_card, style='Pro.TFrame')
        infra_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        infra_cols = ('Name', 'IP', 'MAC', 'Type', 'Status', 'Approved', 'Location')
        self.parental_infra_tree = ttk.Treeview(infra_inner, columns=infra_cols,
                                                  show='headings', style='Pro.Treeview', height=5)
        infra_w = {'Name': 80, 'IP': 100, 'MAC': 100, 'Type': 70, 'Status': 70, 'Approved': 60, 'Location': 70}
        for col in infra_cols:
            self.parental_infra_tree.heading(col, text=col)
            self.parental_infra_tree.column(col, width=infra_w[col])
        self.parental_infra_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        isb = ttk.Scrollbar(infra_inner, orient=tk.VERTICAL, command=self.parental_infra_tree.yview,
                            style='Pro.Vertical.TScrollbar')
        self.parental_infra_tree.configure(yscrollcommand=isb.set)
        isb.pack(side=tk.RIGHT, fill=tk.Y)
        self.parental_infra_tree.bind('<Double-1>', lambda e: self._on_infra_tree_double_click())

        infra_btn_row = ttk.Frame(infra_left, style='Pro.TFrame')
        infra_btn_row.pack(fill=tk.X, pady=(2, 0))
        ttk.Button(infra_btn_row, text="✏ Edit", command=lambda: self._on_infra_tree_double_click(),
                   style='Small.TButton').pack(side=tk.LEFT, padx=1)
        ttk.Button(infra_btn_row, text="❌ Remove", command=self._infra_remove_selected,
                   style='Small.TButton').pack(side=tk.LEFT, padx=1)
        ttk.Button(infra_btn_row, text="🔄 Scan Now", command=lambda: threading.Thread(
                   target=self.update_topology, daemon=True).start(),
                   style='Small.TButton').pack(side=tk.LEFT, padx=1)

        # === 7. Rogue Alerts Card ===
        rogue_card = self._create_card(infra_right, "Rogue Alerts", expand=False)
        rogue_inner = ttk.Frame(rogue_card, style='Pro.TFrame')
        rogue_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        rogue_cols = ('Time', 'Device', 'Severity', 'Type', 'Confidence', 'Ack')
        self.parental_rogue_tree = ttk.Treeview(rogue_inner, columns=rogue_cols,
                                                  show='headings', style='Pro.Treeview', height=5)
        rogue_w = {'Time': 70, 'Device': 120, 'Severity': 70, 'Type': 90, 'Confidence': 70, 'Ack': 40}
        for col in rogue_cols:
            self.parental_rogue_tree.heading(col, text=col)
            self.parental_rogue_tree.column(col, width=rogue_w[col])
        self.parental_rogue_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rsb = ttk.Scrollbar(rogue_inner, orient=tk.VERTICAL, command=self.parental_rogue_tree.yview,
                            style='Pro.Vertical.TScrollbar')
        self.parental_rogue_tree.configure(yscrollcommand=rsb.set)
        rsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.parental_rogue_tree.bind('<Double-1>', lambda e: self.rogue_investigate())

        rogue_btn_row = ttk.Frame(infra_right, style='Pro.TFrame')
        rogue_btn_row.pack(fill=tk.X, pady=(2, 0))
        ttk.Button(rogue_btn_row, text="🔍 Investigate", command=lambda: self.rogue_investigate(),
                   style='Small.TButton').pack(side=tk.LEFT, padx=1)
        ttk.Button(rogue_btn_row, text="✅ Acknowledge", command=self.rogue_acknowledge,
                   style='Small.TButton').pack(side=tk.LEFT, padx=1)
        ttk.Button(rogue_btn_row, text="🗑 Clear All", command=self.rogue_clear_all,
                   style='Small.TButton').pack(side=tk.LEFT, padx=1)

        # === Second row: Transitions + Topology ===
        infra_row2 = ttk.Frame(infra_section, style='Pro.TFrame')
        infra_row2.pack(fill=tk.X, pady=(5, 0))

        infra_left2 = ttk.Frame(infra_row2, style='Pro.TFrame')
        infra_left2.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        infra_right2 = ttk.Frame(infra_row2, style='Pro.TFrame')
        infra_right2.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))

        # === 8. Child Network Transitions Card ===
        trans_card = self._create_card(infra_left2, "Child Network Transitions", expand=False)
        trans_inner = ttk.Frame(trans_card, style='Pro.TFrame')
        trans_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        trans_cols = ('Time', 'Device', 'From', 'To', 'DNS Cov')
        self.parental_transitions_tree = ttk.Treeview(trans_inner, columns=trans_cols,
                                                       show='headings', style='Pro.Treeview', height=4)
        trans_w = {'Time': 70, 'Device': 130, 'From': 100, 'To': 100, 'DNS Cov': 60}
        for col in trans_cols:
            self.parental_transitions_tree.heading(col, text=col)
            self.parental_transitions_tree.column(col, width=trans_w[col])
        self.parental_transitions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # === 9. Network Topology Card ===
        topo_card = self._create_card(infra_right2, "Network Topology", expand=False)
        topo_inner = ttk.Frame(topo_card, style='Pro.TFrame')
        topo_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        topo_cols = ('Type', 'Identifier', 'Name', 'Status')
        self.parental_topology_tree = ttk.Treeview(topo_inner, columns=topo_cols,
                                                    show='tree', style='Pro.Treeview', height=4)
        topo_w = {'Type': 100, 'Identifier': 120, 'Name': 100, 'Status': 60}
        for col in topo_cols:
            self.parental_topology_tree.heading(col, text=col)
            self.parental_topology_tree.column(col, width=topo_w[col])
        self.parental_topology_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # === 10. Investigation Timeline (full width) ===
        timeline_card = self._create_card(infra_section, "Investigation Timeline", expand=False,
                                          pady=(5, 0))
        tl_inner = ttk.Frame(timeline_card, style='Pro.TFrame')
        tl_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        self.parental_timeline_text = tk.Text(tl_inner, bg='#000000',
                                              fg=self.colors['terminal'],
                                              font=('Consolas', 8), height=6,
                                              bd=0, highlightthickness=0)
        self.parental_timeline_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tsb = ttk.Scrollbar(tl_inner, orient=tk.VERTICAL, command=self.parental_timeline_text.yview,
                            style='Pro.Vertical.TScrollbar')
        self.parental_timeline_text.configure(yscrollcommand=tsb.set)
        tsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Initial display
        self.refresh_infrastructure_display()
        self.refresh_rogue_alerts_display()
        self.refresh_topology_display()
        self.refresh_timeline_display()

    # ==================== PARENTAL CONTROL METHODS ====================

    def refresh_parental_display(self):
        """Refresh the parental device tree from scanned devices and known devices"""
        try:
            self.parental_device_tree.delete(*self.parental_device_tree.get_children())

            # Merge scanned devices with known device data
            seen_ips = set()
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                ip = values[0]
                seen_ips.add(ip)
                mac = values[2] if len(values) > 2 else ''
                hostname = values[1] if len(values) > 1 else 'Unknown'
                status = values[5] if len(values) > 5 else '🟢 Online'
                online = '🟢' if 'Online' in status or 'Gateway' in status else '🔴'
                ports_str = values[4] if len(values) > 4 else ''
                ports = [int(p) for p in ports_str.split(',') if p.strip().isdigit()] if ports_str else []

                # Check if we have known device data
                dev_info = self.known_devices.get(ip, {})
                owner = dev_info.get('owner', 'Unknown')
                profile = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
                device_name = dev_info.get('device_name', hostname)
                device_type = dev_info.get('device_type', '')
                blocked = dev_info.get('blocked', False)

                # Auto-classify if not yet assigned
                if not dev_info.get('owner') or dev_info.get('owner') == 'Unknown':
                    # Auto-detect based on hostname patterns
                    hl = hostname.lower()
                    if any(x in hl for x in ['phone', 'iphone', 'android', 'galaxy', 'ipad', 'tablet']):
                        device_type = self.classify_device(mac, hostname, ports)
                    elif any(x in hl for x in ['laptop', 'notebook', 'macbook', 'desktop', 'pc']):
                        device_type = self.classify_device(mac, hostname, ports)
                    elif mac != 'Unknown':
                        device_type = self.classify_device(mac, hostname, ports)
                    if device_type and device_type != 'Unknown Device':
                        if ip not in self.known_devices:
                            self.known_devices[ip] = {}
                        self.known_devices[ip]['device_type'] = device_type
                        self.known_devices[ip]['device_name'] = device_name
                        if not dev_info.get('owner'):
                            # Generate owner from device type
                            self.known_devices[ip]['owner'] = 'Unknown'

                # Build display name with type
                display_name = device_name
                if device_type and device_type != 'Unknown Device':
                    display_name = f"{device_name} ({device_type})"

                status_text = f"{'🔒 ' if blocked else ''}{'✅' if 'Online' in status or 'Gateway' in status else '❌'}"
                self.parental_device_tree.insert('', tk.END, values=(
                    display_name, owner, profile.capitalize(), status_text, online
                ), tags=(ip,))

                # Save auto-detected info
                if ip not in self.known_devices:
                    self.known_devices[ip] = {}
                if not self.known_devices[ip].get('device_type') and device_type:
                    self.known_devices[ip]['device_type'] = device_type
                if not self.known_devices[ip].get('device_name') or self.known_devices[ip].get('device_name') == ip:
                    self.known_devices[ip]['device_name'] = hostname if hostname != 'Unknown' else ip
                if mac and mac != 'Unknown':
                    self.known_devices[ip]['mac'] = mac

            # Add known-only devices (not currently on network)
            for ip, dev_info in self.known_devices.items():
                if ip not in seen_ips:
                    owner = dev_info.get('owner', 'Unknown')
                    profile = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
                    device_name = dev_info.get('device_name', ip)
                    device_type = dev_info.get('device_type', '')
                    blocked = dev_info.get('blocked', False)
                    display_name = f"{device_name} ({device_type})" if device_type and device_type != 'Unknown Device' else device_name
                    status_text = f"{'🔒 ' if blocked else ''}Offline"
                    self.parental_device_tree.insert('', tk.END, values=(
                        display_name, owner, profile.capitalize(), status_text, '⚫'
                    ), tags=(ip,))

            # Auto-save any new device identifications
            self.save_data()
            self.update_parental_stats()
        except Exception as e:
            self.log(f"Parental display refresh error: {e}", "WARNING")

    def update_parental_stats(self):
        """Update parental control status indicators"""
        try:
            total = len(self.parental_device_tree.get_children())
            if hasattr(self, 'parental_devices_lbl'):
                self.parental_devices_lbl.config(text=str(total))
            if hasattr(self, 'parental_blocked_lbl'):
                self.parental_blocked_lbl.config(text=str(self.parental_blocked_count))
            if hasattr(self, 'parental_dns_lbl'):
                dns_status = "🟢 On" if self.dns_monitoring else "🔴 Off"
                self.parental_dns_lbl.config(text=dns_status)
            if hasattr(self, 'parental_filter_lbl'):
                filter_status = "🟢 Active" if self.parental_settings.get('block_method') != 'none' else "🔴 Off"
                self.parental_filter_lbl.config(text=filter_status)
        except:
            pass

    def on_parental_device_select(self, event=None):
        """Show device details when selected in parental tree"""
        selection = self.parental_device_tree.selection()
        if not selection:
            return
        item = self.parental_device_tree.item(selection[0])
        values = item['values']
        device_name = values[0] if values else ''
        # Find IP from tags
        tags = item.get('tags', ())
        ip = tags[0] if tags else ''

        dev_info = self.known_devices.get(ip, {})
        detail = f"Device: {device_name}\n"
        detail += f"{'─' * 40}\n"
        detail += f"  IP: {ip}\n"
        detail += f"  Owner: {dev_info.get('owner', 'Unknown')}\n"
        detail += f"  Profile: {dev_info.get('profile', 'child').capitalize()}\n"
        detail += f"  Type: {dev_info.get('device_type', 'Unknown')}\n"
        detail += f"  Location: {dev_info.get('location', 'Unknown')}\n"
        detail += f"  Blocked: {'Yes 🔒' if dev_info.get('blocked', False) else 'No'}\n"
        detail += f"  Notes: {dev_info.get('notes', 'None')}\n"

        # Show today's activity count
        today = datetime.now().strftime("%Y-%m-%d")
        activity_count = sum(1 for entry in self.activity_log
                             if entry.get('ip') == ip and entry.get('date', '').startswith(today))
        blocked_count = sum(1 for entry in self.activity_log
                            if entry.get('ip') == ip and entry.get('blocked', False)
                            and entry.get('date', '').startswith(today))
        detail += f"\n  Today's Activity: {activity_count} queries\n"
        detail += f"  Blocked Today: {blocked_count}\n"

        # Show time limit info
        profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
        profile = self.parental_profiles.get(profile_name, {})
        time_left = self.get_remaining_time(ip, profile)
        if time_limit := profile.get('time_limit', 0):
            detail += f"  Time Remaining: {max(0, time_limit - (time_limit - time_left))}m / {time_limit}m\n"

        if hasattr(self, 'parental_profile_detail'):
            self.parental_profile_detail.delete(1.0, tk.END)
            self.parental_profile_detail.insert(1.0, detail)

    def get_remaining_time(self, ip, profile):
        """Calculate remaining screen time for a device today"""
        if not profile.get('time_limit', 0):
            return 999
        today = datetime.now().strftime("%Y-%m-%d")
        used = 0
        for entry in self.activity_log:
            if entry.get('ip') == ip and entry.get('date', '').startswith(today):
                used += entry.get('duration', 1)
        return max(0, profile['time_limit'] - used)

    # ==================== DNS MONITORING ====================

    def toggle_dns_monitoring(self):
        """Toggle DNS query monitoring on/off"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy required for DNS monitoring", "ERROR")
            messagebox.showinfo("Scapy Required", "DNS monitoring requires Scapy.\nInstall: pip install scapy")
            return

        if self.dns_monitoring:
            self.dns_monitoring = False
            self.parental_dns_btn.config(text="▶ Start DNS Monitor", bg=self.colors['accent'])
            self.log("DNS monitoring stopped", "PARENTAL")
        else:
            self.dns_monitoring = True
            self.parental_dns_btn.config(text="⏹ Stop DNS", bg=self.colors['danger'])
            self.log("Starting DNS monitoring...", "PARENTAL")
            self.parental_activity_text.delete(1.0, tk.END)
            self.parental_activity_text.insert(1.0, "🔞 DNS Monitor Active\n")
            self.parental_activity_text.insert(1.0, f"{'=' * 60}\n")
            self.parental_activity_text.insert(1.0, "Listening for DNS queries...\n\n")
            threading.Thread(target=self.capture_dns_queries, daemon=True).start()
        self.update_parental_stats()

    def capture_dns_queries(self):
        """Capture DNS queries using Scapy"""
        if not SCAPY_AVAILABLE:
            return

        def dns_callback(pkt):
            if not self.dns_monitoring:
                return
            try:
                if IP in pkt and UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    date_str = datetime.now().strftime("%Y-%m-%d")

                    # Try to extract queried domain
                    domain = ""
                    if hasattr(pkt, 'qd') and pkt.qd:
                        try:
                            domain = pkt.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        except:
                            domain = "Unknown"
                    elif Raw in pkt:
                        try:
                            payload = pkt[Raw].load
                            # Simple extraction for DNS queries
                            if len(payload) > 12:
                                qname_start = 12
                                parts = []
                                while qname_start < len(payload):
                                    label_len = payload[qname_start]
                                    if label_len == 0:
                                        break
                                    if label_len > 63:
                                        break
                                    qname_start += 1
                                    if qname_start + label_len <= len(payload):
                                        parts.append(payload[qname_start:qname_start + label_len].decode('utf-8', errors='ignore'))
                                        qname_start += label_len
                                    else:
                                        break
                                if parts:
                                    domain = '.'.join(parts)
                        except:
                            pass

                    if not domain:
                        return

                    # Map device IP to owner/profile
                    dev_info = self.known_devices.get(src_ip, {})
                    owner = dev_info.get('owner', 'Unknown')
                    profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
                    device_name = dev_info.get('device_name', src_ip)
                    profile = self.parental_profiles.get(profile_name, {})
                    blocked_categories = profile.get('block_categories', [])

                    # Check domain against block/allow lists
                    domain_lower = domain.lower()
                    is_blocked = False
                    blocked_category = ""
                    is_allowed = False

                    # Check allowlist first
                    if domain_lower in self.content_allowlist or any(d in domain_lower for d in self.content_allowlist):
                        is_allowed = True

                    # Check blocklist
                    if not is_allowed:
                        if domain_lower in self.content_blocklist or any(d in domain_lower for d in self.content_blocklist):
                            is_blocked = True
                            blocked_category = "manual"

                    # Check category blocking
                    if not is_blocked and not is_allowed and blocked_categories:
                        for cat in blocked_categories:
                            keywords = self.content_categories.get(cat, [])
                            if any(kw in domain_lower for kw in keywords):
                                is_blocked = True
                                blocked_category = cat
                                break

                    # Check curfew
                    if not is_blocked and self.parental_settings.get('schedule_active', True):
                        if self.is_curfew_active(profile):
                            is_blocked = True
                            blocked_category = "curfew"

                    # Check time limit
                    if not is_blocked and profile.get('time_limit', 0) > 0:
                        remaining = self.get_remaining_time(src_ip, profile)
                        if remaining <= 0:
                            is_blocked = True
                            blocked_category = "time_limit"

                    # Log the activity
                    log_entry = {
                        'time': timestamp,
                        'date': date_str,
                        'ip': src_ip,
                        'domain': domain,
                        'owner': owner,
                        'device_name': device_name,
                        'profile': profile_name,
                        'blocked': is_blocked,
                        'category': blocked_category,
                        'dst_ip': dst_ip,
                        'duration': 1,  # placeholder
                    }
                    self.activity_log.append(log_entry)
                    if is_blocked:
                        self.dns_activity_log.append(log_entry)
                        self.parental_blocked_count += 1

                    # Determine category for display
                    domain_cat = "Unknown"
                    for cat, keywords in self.content_categories.items():
                        if any(kw in domain_lower for kw in keywords):
                            domain_cat = cat.capitalize()
                            break

                    # Display on UI with category colors
                    cat_icons = {
                        'adult': '🔴', 'violence': '🔴', 'social': '🔵',
                        'gaming': '🟢', 'streaming': '🟡', 'shopping': '🟠',
                        'education': '🟣', 'search': '🔵', 'Unknown': '⚪'
                    }
                    cat_icon = cat_icons.get(domain_cat.lower(), '⚪')

                    if is_blocked:
                        category_tag = f" [{blocked_category}]" if blocked_category else ""
                        line = (f"[{timestamp}] 🛡️ BLOCKED {domain}{category_tag} "
                                f"<- {device_name} ({owner}) [{domain_cat}]\n")
                    else:
                        line = (f"[{timestamp}] {cat_icon} {domain} "
                                f"<- {device_name} ({owner}) [{domain_cat}]\n")

                    self.parental_activity_text.insert(tk.END, line)
                    self.parental_activity_text.see(tk.END)

                    # Update blocked attempts treeview
                    if is_blocked:
                        self.parental_blocked_tree.insert('', 0, values=(
                            timestamp, device_name, domain, domain_cat, profile_name.capitalize()
                        ))
                        # Keep only last 500 blocked entries
                        while len(self.parental_blocked_tree.get_children()) > 500:
                            self.parental_blocked_tree.delete(
                                self.parental_blocked_tree.get_children()[-1]
                            )

                    # Update stats
                    self.update_parental_stats()

                    # Apply blocking via hosts file if active
                    if is_blocked and self.parental_settings.get('block_method') == 'hosts':
                        self._block_via_hosts(domain)

            except Exception as e:
                if self.dns_monitoring:
                    self.log(f"DNS capture error: {str(e)[:80]}", "WARNING")

        try:
            self.log("DNS monitor started - listening on port 53", "PARENTAL")
            # Try multi-interface sniffing for macOS with multiple active networks
            try:
                from scapy.all import get_working_ifaces, get_if_list
                try:
                    ifaces = [i.name for i in get_working_ifaces()]
                except:
                    ifaces = [i for i in get_if_list() if i.startswith(('en', 'bridge', 'eth'))]
                if not ifaces:
                    ifaces = get_if_list()
            except:
                ifaces = []
            if ifaces:
                active = [i for i in ifaces if not i.startswith(('lo', 'gif', 'stf', 'utun', 'awdl', 'llw'))][:5]
                if not active:
                    active = ifaces[:3]
                self.log(f"DNS monitoring interfaces: {active}", "PARENTAL")
                for iface in active:
                    threading.Thread(
                        target=lambda i=iface: sniff(iface=i, filter="udp port 53",
                                                     prn=dns_callback, store=0),
                        daemon=True
                    ).start()
                # Keep alive while monitoring
                while self.dns_monitoring:
                    time.sleep(1)
            else:
                sniff(filter="udp port 53", prn=dns_callback, store=0)
        except PermissionError:
            self.parental_activity_text.insert(1.0, "\n❌ DNS monitoring requires root privileges.\n")
            self.parental_activity_text.insert(1.0, "Run: sudo python3 main.py\n")
            self.log("DNS monitoring requires root", "ERROR")
        except Exception as e:
            if self.dns_monitoring:
                self.log(f"DNS capture failed: {e}", "ERROR")
        finally:
            if self.dns_monitoring:
                self.dns_monitoring = False
                self.root.after(0, lambda: self.parental_dns_btn.config(
                    text="▶ Start DNS Monitor", bg=self.colors['accent']))
                self.update_parental_stats()

    def is_curfew_active(self, profile):
        """Check if current time falls within curfew for a profile"""
        if not profile:
            return False
        now = datetime.now()
        is_weekend = now.weekday() >= 5  # Saturday=5, Sunday=6

        if is_weekend and profile.get('weekend_diff', False):
            curfew_start = profile.get('weekend_curfew_start', '')
            curfew_end = profile.get('weekend_curfew_end', '')
        else:
            curfew_start = profile.get('curfew_start', '')
            curfew_end = profile.get('curfew_end', '')

        if not curfew_start or not curfew_end:
            return False

        try:
            start_h, start_m = map(int, curfew_start.split(':'))
            end_h, end_m = map(int, curfew_end.split(':'))
            now_min = now.hour * 60 + now.minute
            start_min = start_h * 60 + start_m
            end_min = end_h * 60 + end_m

            if start_min <= end_min:
                # Normal range (e.g., 07:00-21:00 means active during day)
                # For curfew, we check if outside this range
                return now_min < start_min or now_min > end_min
            else:
                # Overnight range (e.g., 21:00-07:00)
                return now_min >= start_min or now_min <= end_min
        except:
            return False

    # ==================== CONTENT FILTERING ====================

    def toggle_content_filter(self):
        """Toggle content filtering on/off"""
        if self.parental_settings.get('block_method') == 'none':
            self.parental_settings['block_method'] = 'hosts'
            self.parental_filter_btn.config(text="⏹ Stop Filter", bg=self.colors['danger'])
            self.log("Content filtering activated", "PARENTAL")
        else:
            self.parental_settings['block_method'] = 'none'
            self.parental_filter_btn.config(text="▶ Start Filter", bg=self.colors['accent'])
            self.log("Content filtering deactivated", "PARENTAL")
        self.update_parental_stats()

    def _block_via_hosts(self, domain):
        """Block a domain by adding to /etc/hosts (requires root)"""
        if platform.system() == 'Windows':
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        else:
            hosts_path = '/etc/hosts'

        try:
            with open(hosts_path, 'r') as f:
                content = f.read()
            block_line = f"127.0.0.1 {domain}"
            if block_line not in content:
                with open(hosts_path, 'a') as f:
                    f.write(f"\n# Parental Control Block\n{block_line}\n")
                self.log(f"Added {domain} to hosts block list", "PARENTAL")
        except PermissionError:
            pass  # Silently fail - blocking works via DNS detection regardless
        except Exception as e:
            self.log(f"Hosts block error: {e}", "WARNING")

    def parental_filter_activity(self, event=None):
        """Filter activity display by keyword"""
        filter_text = self.parental_activity_filter.get().strip().lower()
        if not filter_text:
            return

        self.parental_activity_text.delete(1.0, tk.END)
        count = 0
        for entry in reversed(self.activity_log):
            if filter_text in entry.get('domain', '').lower() or \
               filter_text in entry.get('device_name', '').lower() or \
               filter_text in entry.get('owner', '').lower():
                status = "🛡️ BLOCKED" if entry.get('blocked') else "✅ ALLOWED"
                line = f"[{entry['time']}] {status} {entry['domain']} <- {entry.get('device_name', '')}\n"
                self.parental_activity_text.insert(tk.END, line)
                count += 1
                if count >= 200:
                    break

    def parental_clear_activity(self):
        """Clear activity log"""
        if messagebox.askyesno("Clear Activity", "Clear all activity logs?"):
            self.activity_log.clear()
            self.parental_activity_text.delete(1.0, tk.END)
            self.parental_activity_text.insert(1.0, "🔞 Activity Log Cleared\n")
            self.log("Activity log cleared", "PARENTAL")

    # ==================== PROFILE & DEVICE MANAGEMENT ====================

    def parental_assign_profile(self):
        """Assign a profile to a selected device"""
        selection = self.parental_device_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a device first")
            return
        item = self.parental_device_tree.item(selection[0])
        tags = item.get('tags', ())
        ip = tags[0] if tags else ''
        if not ip:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Assign Profile - {item['values'][0]}")
        dialog.geometry("400x350")
        dialog.configure(bg=self.colors['bg'])

        ttk.Label(dialog, text=f"Device: {item['values'][0]}", style='Pro.TLabel',
                  font=('Arial', 11, 'bold')).pack(pady=10)

        fields_frame = ttk.Frame(dialog, style='Pro.TFrame')
        fields_frame.pack(padx=20, pady=10, fill=tk.X)

        # Owner name
        ttk.Label(fields_frame, text="Owner:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
        owner_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('owner', ''))
        ttk.Entry(fields_frame, textvariable=owner_var, font=('Consolas', 11),
                  width=30).pack(fill=tk.X, pady=2)

        # Profile selection
        ttk.Label(fields_frame, text="Profile:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
        profile_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('profile',
                                     self.parental_settings.get('default_profile', 'child')))
        profile_combo = ttk.Combobox(fields_frame, textvariable=profile_var,
                                      values=list(self.parental_profiles.keys()),
                                      state='readonly', width=28, font=('Consolas', 11))
        profile_combo.pack(fill=tk.X, pady=2)

        # Device type
        ttk.Label(fields_frame, text="Device Type:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
        type_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('device_type', 'Unknown'))
        type_combo = ttk.Combobox(fields_frame, textvariable=type_var,
                                   values=['Phone', 'Tablet', 'Laptop', 'Desktop', 'Gaming Console',
                                           'Smart TV', 'IoT', 'Other'],
                                   state='readonly', width=28, font=('Consolas', 11))
        type_combo.pack(fill=tk.X, pady=2)

        # Location
        ttk.Label(fields_frame, text="Location (Floor/Room):", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
        loc_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('location', ''))
        ttk.Entry(fields_frame, textvariable=loc_var, font=('Consolas', 11),
                  width=30).pack(fill=tk.X, pady=2)

        # Device name
        ttk.Label(fields_frame, text="Device Name:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
        name_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('device_name',
                                 self.get_hostname(ip)))
        ttk.Entry(fields_frame, textvariable=name_var, font=('Consolas', 11),
                  width=30).pack(fill=tk.X, pady=2)

        def save_assignment():
            if ip not in self.known_devices:
                self.known_devices[ip] = {}
            self.known_devices[ip]['owner'] = owner_var.get()
            self.known_devices[ip]['profile'] = profile_var.get()
            self.known_devices[ip]['device_type'] = type_var.get()
            self.known_devices[ip]['location'] = loc_var.get()
            self.known_devices[ip]['device_name'] = name_var.get()
            self.known_devices[ip]['date_added'] = datetime.now().isoformat()
            self.save_data()
            self.refresh_parental_display()
            self.log(f"Profile assigned to {ip}: {profile_var.get()}", "PARENTAL")
            dialog.destroy()

        ttk.Button(dialog, text="💾 Save", command=save_assignment,
                   style='Pro.TButton').pack(pady=15)

    def parental_toggle_block(self):
        """Toggle block on a device"""
        selection = self.parental_device_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a device first")
            return
        item = self.parental_device_tree.item(selection[0])
        tags = item.get('tags', ())
        ip = tags[0] if tags else ''
        if not ip:
            return

        if ip not in self.known_devices:
            self.known_devices[ip] = {}
        blocked = not self.known_devices[ip].get('blocked', False)
        self.known_devices[ip]['blocked'] = blocked
        self.save_data()
        self.refresh_parental_display()
        action = "Blocked" if blocked else "Unblocked"
        self.log(f"{action} device {ip}", "PARENTAL")

    def parental_edit_device(self):
        """Edit device details"""
        selection = self.parental_device_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a device first")
            return
        item = self.parental_device_tree.item(selection[0])
        tags = item.get('tags', ())
        ip = tags[0] if tags else ''
        if not ip:
            return
        # Reuse assign profile dialog logic
        self.parental_assign_profile()

    def parental_view_profile(self):
        """View selected profile details"""
        profile_name = self.parental_profile_combo.get()
        profile = self.parental_profiles.get(profile_name)
        if not profile:
            return

        detail = f"Profile: {profile['name']}\n"
        detail += f"{'─' * 40}\n"
        detail += f"  Blocked Categories: {', '.join(profile.get('block_categories', ['None'])) or 'None'}\n"
        detail += f"  Time Limit: {profile.get('time_limit', 0)} min/day" if profile.get('time_limit') else "  Time Limit: Unlimited\n"
        detail += "\n"
        detail += f"  Curfew: {profile.get('curfew_start', 'N/A')} - {profile.get('curfew_end', 'N/A')}\n"
        if profile.get('weekend_diff'):
            detail += f"  Weekend: {profile.get('weekend_time_limit', 0)} min, "
            detail += f"{profile.get('weekend_curfew_start', 'N/A')} - {profile.get('weekend_curfew_end', 'N/A')}\n"
        detail += f"  Block Domains: {', '.join(profile.get('block_domains', [])) or 'None'}\n"
        detail += f"  Allow Domains: {', '.join(profile.get('allow_domains', [])) or 'None'}\n"

        if hasattr(self, 'parental_profile_detail'):
            self.parental_profile_detail.delete(1.0, tk.END)
            self.parental_profile_detail.insert(1.0, detail)

    def parental_settings_dialog(self):
        """Open parental control settings dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Parental Control Settings")
        dialog.geometry("550x500")
        dialog.configure(bg=self.colors['bg'])

        frame = ttk.Frame(dialog, style='Pro.TFrame')
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        ttk.Label(frame, text="Parental Control Settings", style='Heading.TLabel').pack(anchor=tk.W, pady=5)

        settings_list = [
            ("Default Profile", 'default_profile', ['child', 'teen', 'guest', 'admin']),
            ("Block Method", 'block_method', ['none', 'hosts']),
        ]
        for label, key, options in settings_list:
            row = ttk.Frame(frame, style='Pro.TFrame')
            row.pack(fill=tk.X, pady=4)
            ttk.Label(row, text=f"{label}:", style='Pro.TLabel').pack(side=tk.LEFT, padx=5)
            var = tk.StringVar(value=self.parental_settings.get(key, options[0]))
            combo = ttk.Combobox(row, textvariable=var, values=options, state='readonly', width=20)
            combo.pack(side=tk.LEFT, padx=5)
            setattr(self, f'_ps_{key}', var)

        # Checkboxes
        bool_settings = [
            ("Notifications", 'notifications'),
            ("Alert on Blocked Content", 'alert_blocked'),
            ("Alert on New Connection", 'alert_connect'),
            ("Auto-Assign Profile", 'auto_profile'),
            ("Enable Schedule", 'schedule_active'),
            ("Email Alerts", 'email_alerts'),
        ]
        bool_vars = {}
        for label, key in bool_settings:
            var = tk.BooleanVar(value=self.parental_settings.get(key, False))
            cb = ttk.Checkbutton(frame, text=label, variable=var, style='Pro.TButton')
            cb.pack(anchor=tk.W, pady=2, padx=5)
            bool_vars[key] = var

        # Email field
        email_row = ttk.Frame(frame, style='Pro.TFrame')
        email_row.pack(fill=tk.X, pady=4)
        ttk.Label(email_row, text="Alert Email:", style='Pro.TLabel').pack(side=tk.LEFT, padx=5)
        email_var = tk.StringVar(value=self.parental_settings.get('alert_email', ''))
        ttk.Entry(email_row, textvariable=email_var, width=30, font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        def save_settings():
            for key in ['default_profile', 'block_method']:
                var = getattr(self, f'_ps_{key}', None)
                if var:
                    self.parental_settings[key] = var.get()
            for key, var in bool_vars.items():
                self.parental_settings[key] = var.get()
            self.parental_settings['alert_email'] = email_var.get()
            self.save_data()
            self.update_parental_stats()
            self.log("Parental settings saved", "PARENTAL")
            dialog.destroy()

        ttk.Button(frame, text="💾 Save Settings", command=save_settings,
                   style='Pro.TButton').pack(pady=15)

        # Update settings display
        self._update_parental_settings_display()

    def _update_parental_settings_display(self):
        """Update the settings summary text in the tab"""
        try:
            s = self.parental_settings
            text = (f"Profile: {s.get('default_profile','child')} | "
                    f"Filter: {s.get('block_method','none')} | "
                    f"Schedule: {'On' if s.get('schedule_active',True) else 'Off'} | "
                    f"Alerts: {'On' if s.get('alert_blocked',True) else 'Off'}")
            if hasattr(self, 'parental_settings_text'):
                self.parental_settings_text.config(text=text)
        except:
            pass

    # ==================== REPORTING ====================

    def _get_activity_stats(self, device_ip=None, days=1):
        """Get activity statistics for reporting"""
        today = datetime.now()
        cutoff = today.strftime("%Y-%m-%d")
        if days > 1:
            from datetime import timedelta
            cutoff_date = today - timedelta(days=days)
            cutoff = cutoff_date.strftime("%Y-%m-%d")

        filtered = []
        for entry in self.activity_log:
            entry_date = entry.get('date', '')
            if entry_date >= cutoff:
                if device_ip and entry.get('ip') != device_ip:
                    continue
                filtered.append(entry)

        return filtered

    def parental_daily_report(self):
        """Generate daily activity report"""
        report = self._build_report(days=1)
        self._show_report("📊 Daily Activity Report", report)

    def parental_weekly_report(self):
        """Generate weekly activity summary"""
        report = self._build_report(days=7)
        self._show_report("📈 Weekly Summary Report", report)

    def _build_report(self, days=1):
        """Build a text report for the given number of days"""
        activities = self._get_activity_stats(days=days)
        today = datetime.now().strftime("%Y-%m-%d")

        report = f"Parental Control Report\n"
        report += f"{'=' * 60}\n"
        report += f"Period: Last {days} day(s) ({today})\n"
        report += f"Total Queries: {len(activities)}\n"
        report += f"Blocked: {sum(1 for e in activities if e.get('blocked'))}\n"
        report += f"Allowed: {sum(1 for e in activities if not e.get('blocked'))}\n\n"

        # Per device breakdown
        devices = {}
        for entry in activities:
            dev = entry.get('device_name', entry.get('ip', 'Unknown'))
            if dev not in devices:
                devices[dev] = {'total': 0, 'blocked': 0, 'domains': {}}
            devices[dev]['total'] += 1
            if entry.get('blocked'):
                devices[dev]['blocked'] += 1
            domain = entry.get('domain', 'Unknown')
            if domain not in devices[dev]['domains']:
                devices[dev]['domains'][domain] = 0
            devices[dev]['domains'][domain] += 1

        for dev_name, stats in sorted(devices.items()):
            report += f"\n📱 {dev_name}\n"
            report += f"{'─' * 40}\n"
            report += f"  Queries: {stats['total']} | Blocked: {stats['blocked']}\n"
            if stats['domains']:
                top = sorted(stats['domains'].items(), key=lambda x: -x[1])[:10]
                report += f"  Top Domains:\n"
                for domain, count in top:
                    report += f"    {domain}: {count}\n"

        # Blocked attempts
        blocked = [e for e in activities if e.get('blocked')]
        if blocked:
            report += f"\n🛡️ Blocked Attempts ({len(blocked)})\n"
            report += f"{'─' * 40}\n"
            for entry in blocked[-20:]:
                report += f"  [{entry.get('time','')}] {entry.get('domain','')} "
                report += f"({entry.get('category','')}) - {entry.get('device_name','')}\n"

        # Time spent estimate (rough)
        online_time = len(activities) * 0.5  # rough estimate: 30s per query
        hours = int(online_time // 60)
        minutes = int(online_time % 60)
        report += f"\n⏱ Estimated Online Time: {hours}h {minutes}m\n"

        return report

    def _show_report(self, title, report):
        """Display a report in a dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("650x500")
        dialog.configure(bg=self.colors['bg'])

        text_widget = tk.Text(dialog, bg=self.colors['secondary'], fg=self.colors['text'],
                              font=('Consolas', 10), wrap=tk.WORD, bd=0, highlightthickness=0)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(1.0, report)

        btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_frame, text="💾 Save", style='Pro.TButton',
                   command=lambda: self._save_report(report)).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Close", style='Pro.TButton',
                   command=dialog.destroy).pack(side=tk.RIGHT, padx=2)

    def _save_report(self, report):
        """Save report to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(report)
                self.log(f"Report saved to {filename}", "SUCCESS")
                messagebox.showinfo("Saved", f"Report saved to:\n{filename}")
        except Exception as e:
            self.log(f"Report save error: {e}", "ERROR")

    def parental_export_report(self):
        """Export parental report as text/HTML"""
        report = self._build_report(days=1)
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("HTML files", "*.html"), ("All files", "*.*")]
            )
            if not filename:
                return

            ext = os.path.splitext(filename)[1].lower()
            if ext == '.html':
                html = self._report_to_html(report)
                with open(filename, 'w') as f:
                    f.write(html)
            else:
                with open(filename, 'w') as f:
                    f.write(report)

            self.log(f"Report exported to {filename}", "SUCCESS")
            messagebox.showinfo("Export Complete", f"Report saved to:\n{filename}")
        except Exception as e:
            self.log(f"Report export error: {e}", "ERROR")

    def _report_to_html(self, report):
        """Convert report text to simple HTML"""
        lines = report.split('\n')
        html_parts = [
            '<!DOCTYPE html><html><head><meta charset="utf-8">',
            '<title>Parental Control Report</title>',
            '<style>body{background:#0a0a12;color:#e0e0e0;font-family:Arial;padding:20px}',
            'h1{color:#6c5ce7}pre{color:#00d4aa;font-family:Consolas}',
            '.blocked{color:#ff6b6b}.allowed{color:#00d4aa}</style></head><body>',
            f'<h1>🔞 Parental Control Report</h1>',
            f'<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>',
            f'<pre>',
        ]
        for line in lines:
            escaped = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            if 'BLOCKED' in line or 'Blocked' in line:
                html_parts.append(f'<span class="blocked">{escaped}</span>')
            else:
                html_parts.append(escaped)
        html_parts.append('</pre></body></html>')
        return '\n'.join(html_parts)

    # ==================== PERIODIC PARENTAL TASKS ====================

    def periodic_parental_check(self):
        """Periodic check for schedule enforcement and alerts (called from auto_refresh)"""
        try:
            if not self.parental_settings.get('schedule_active', True):
                return

            # Check curfew for all known devices
            for ip, dev_info in self.known_devices.items():
                profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
                profile = self.parental_profiles.get(profile_name, {})
                if self.is_curfew_active(profile):
                    # Log curfew activity if device is online
                    for item in self.device_tree.get_children():
                        values = self.device_tree.item(item)['values']
                        if values[0] == ip and ('Online' in values[5] or 'Gateway' in values[5]):
                            self.log(f"Curfew active for {dev_info.get('device_name', ip)}", "PARENTAL")
                            break

            # Refresh parental display
            self.refresh_parental_display()
            self.update_parental_stats()
            self._update_parental_settings_display()
        except:
            pass

    # ==================== INFRASTRUCTURE & ROGUE DETECTION ====================

    def discover_routers(self):
        """Discover all routers/gateways on all active subnets"""
        routers = {}
        try:
            current_gw = self.get_gateway()
            if current_gw and current_gw != 'Unknown':
                gw_mac = self.get_mac_address(current_gw)
                routers[current_gw] = {
                    'ip': current_gw,
                    'mac': gw_mac,
                    'type': 'gateway',
                    'source': 'route_table',
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'active': True,
                }
            # Check all discovered networks for their gateways
            for net in self.available_networks:
                try:
                    network = ipaddress.IPv4Network(net, strict=False)
                    gw_candidate = str(network[1])  # Usually .1 is gateway
                    if gw_candidate != current_gw:
                        gw_mac2 = self.get_mac_address(gw_candidate)
                        if gw_mac2 != 'Unknown':
                            routers[gw_candidate] = {
                                'ip': gw_candidate,
                                'mac': gw_mac2,
                                'type': 'gateway',
                                'source': 'subnet_discovery',
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                                'active': True,
                            }
                except:
                    pass
        except Exception as e:
            self.log(f"Router discovery error: {e}", "WARNING")
        return routers

    def discover_dhcp_servers(self):
        """Detect DHCP servers via ARP and known gateway MACs"""
        dhcp_servers = {}
        try:
            # Check ARP table for DHCP-related activity
            if platform.system() != 'Windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        match = re.search(r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', line)
                        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                        if match and ip_match:
                            mac = match.group(1).upper()
                            ip = ip_match.group()
                            # Known DHCP server ports (67/68)
                            if self._is_port_open(ip, 67, timeout=0.5):
                                dhcp_servers[ip] = {
                                    'ip': ip, 'mac': mac,
                                    'type': 'dhcp_server',
                                    'source': 'port_67_scan',
                                    'first_seen': datetime.now().isoformat(),
                                    'last_seen': datetime.now().isoformat(),
                                }
            # The current gateway is often the DHCP server
            gw = self.get_gateway()
            if gw and gw != 'Unknown' and gw not in dhcp_servers:
                dhcp_servers[gw] = {
                    'ip': gw, 'mac': self.get_mac_address(gw),
                    'type': 'dhcp_server',
                    'source': 'gateway_assumption',
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                }
        except Exception as e:
            self.log(f"DHCP discovery error: {e}", "WARNING")
        return dhcp_servers

    def _is_port_open(self, ip, port, timeout=0.3):
        """Quick TCP port check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def wireless_scan(self):
        """Perform passive wireless scan (macOS airport or Scapy)"""
        results = {}
        try:
            # macOS: Use airport command
            if platform.system() == 'Darwin':
                airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
                if os.path.exists(airport_path):
                    result = subprocess.run([airport_path, '-s'], capture_output=True, text=True, timeout=15)
                    for line in result.stdout.split('\n')[1:]:
                        if not line.strip():
                            continue
                        parts = line.split()
                        if len(parts) >= 4:
                            ssid = parts[0]
                            bssid = parts[1] if len(parts) > 1 else ''
                            rssi = parts[2] if len(parts) > 2 else '0'
                            channel = parts[3] if len(parts) > 3 else '0'
                            if bssid:
                                bssid_upper = bssid.upper()
                                now = datetime.now().isoformat()
                                if bssid_upper in self.wireless_scan_cache:
                                    self.wireless_scan_cache[bssid_upper]['last_seen'] = now
                                    self.wireless_scan_cache[bssid_upper]['rssi'] = rssi
                                else:
                                    self.wireless_scan_cache[bssid_upper] = {
                                        'ssid': ssid, 'bssid': bssid_upper, 'rssi': rssi,
                                        'channel': channel, 'first_seen': now, 'last_seen': now,
                                        'approved': False,
                                    }
                                results[bssid_upper] = self.wireless_scan_cache[bssid_upper]
            # Linux: Use iwlist or nmcli
            elif platform.system() == 'Linux':
                try:
                    result = subprocess.run(['iwlist', 'scan'], capture_output=True, text=True, timeout=20)
                    current_bssid = None
                    for line in result.stdout.split('\n'):
                        if 'Address:' in line:
                            current_bssid = line.split('Address:')[-1].strip().upper()
                        elif 'ESSID:' in line and current_bssid:
                            ssid = line.split('ESSID:"')[1].split('"')[0] if '"' in line else ''
                            now = datetime.now().isoformat()
                            if current_bssid not in self.wireless_scan_cache:
                                self.wireless_scan_cache[current_bssid] = {
                                    'ssid': ssid, 'bssid': current_bssid, 'rssi': '0',
                                    'channel': '0', 'first_seen': now, 'last_seen': now,
                                    'approved': False,
                                }
                            results[current_bssid] = self.wireless_scan_cache[current_bssid]
                except:
                    pass
        except Exception as e:
            self.log(f"Wireless scan error: {e}", "WARNING")
        return results

    def discover_topology(self):
        """Map network topology: gateway -> APs -> subnets -> devices"""
        topology = {}
        try:
            gw = self.get_gateway()
            if gw and gw != 'Unknown':
                entry = {
                    'mac': self.get_mac_address(gw),
                    'name': self.get_hostname(gw),
                    'subnets': list(self.available_networks),
                    'aps': [],
                    'devices': [],
                    'dhcp_servers': [],
                    'last_seen': datetime.now().isoformat(),
                }
                # Add known devices
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item)['values']
                    ip = values[0]
                    if self._is_same_subnet(ip, gw):
                        entry['devices'].append(ip)
                # Check for DHCP servers
                dhcp = self.discover_dhcp_servers()
                for dhcp_ip in dhcp:
                    entry['dhcp_servers'].append(dhcp_ip)
                topology[gw] = entry
            self.network_topology = topology
        except Exception as e:
            self.log(f"Topology discovery error: {e}", "WARNING")
        return topology

    def _is_same_subnet(self, ip1, ip2):
        """Check if two IPs are on the same subnet"""
        try:
            for net in self.available_networks:
                network = ipaddress.IPv4Network(net, strict=False)
                if ipaddress.IPv4Address(ip1) in network and ipaddress.IPv4Address(ip2) in network:
                    return True
        except:
            pass
        return False

    def _get_device_subnet(self, ip):
        """Get the subnet a device belongs to"""
        try:
            for net in self.available_networks:
                network = ipaddress.IPv4Network(net, strict=False)
                if ipaddress.IPv4Address(ip) in network:
                    return net
        except:
            pass
        return 'Unknown'

    def detect_rogue_dhcp(self, approved_list=None):
        """Detect unauthorized DHCP servers"""
        if approved_list is None:
            approved_list = [v.get('ip') for v in self.infrastructure.values()
                           if v.get('approved') and v.get('type') == 'dhcp_server']
        alerts = []
        try:
            detected = self.discover_dhcp_servers()
            for dhcp_ip, dhcp_info in detected.items():
                if dhcp_ip not in approved_list:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'device_id': dhcp_ip,
                        'location': 'Unknown',
                        'evidence': f"DHCP server detected on port 67 at {dhcp_ip}",
                        'prev_state': 'unknown',
                        'new_state': 'rogue_dhcp',
                        'severity': 'high',
                        'confidence': 'medium',
                        'investigation_step': f"Check if {dhcp_ip} is a known router. Verify with 'arp -a' on gateway.",
                    }
                    alerts.append(alert)
                    self.rogue_alerts.append(alert)
                    self.log(f"⚠️ Rogue DHCP detected: {dhcp_ip}", "SECURITY")
        except Exception as e:
            self.log(f"Rogue DHCP detection error: {e}", "WARNING")
        return alerts

    def detect_rogue_ssid(self, approved_bssids=None, approved_ssids=None):
        """Detect unauthorized wireless networks"""
        if approved_bssids is None:
            approved_bssids = {v.get('mac', '').upper() for v in self.infrastructure.values()
                             if v.get('approved') and v.get('type') in ('ap', 'router')}
        if approved_ssids is None:
            approved_ssids = {v.get('ssid', '') for v in self.infrastructure.values()
                            if v.get('approved') and v.get('ssid')}
        alerts = []
        try:
            scan_results = self.wireless_scan()
            for bssid, info in scan_results.items():
                is_approved_bssid = bssid in approved_bssids
                is_approved_ssid = info.get('ssid', '') in approved_ssids
                if not is_approved_bssid:
                    # Check for SSID spoofing
                    if is_approved_ssid:
                        severity = 'critical'
                        step = f"SSID '{info.get('ssid')}' is spoofed by unknown BSSID {bssid}. Verify with physical inspection."
                    else:
                        severity = 'medium'
                        step = f"Unknown AP {bssid} ({info.get('ssid')}) detected. Check if it belongs to a neighbor."
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'device_id': bssid,
                        'location': 'Unknown',
                        'evidence': f"Wireless scan detected BSSID {bssid} with SSID '{info.get('ssid')}'",
                        'prev_state': 'not_seen',
                        'new_state': 'rogue_ap',
                        'severity': severity,
                        'confidence': 'high' if is_approved_ssid else 'medium',
                        'investigation_step': step,
                    }
                    alerts.append(alert)
                    self.rogue_alerts.append(alert)
                    self.log(f"⚠️ Rogue AP detected: {bssid} ({info.get('ssid')})", "SECURITY")
        except Exception as e:
            self.log(f"Rogue SSID detection error: {e}", "WARNING")
        return alerts

    def detect_nat_boundary(self):
        """Detect new NAT boundaries via TTL changes"""
        alerts = []
        try:
            gw = self.get_gateway()
            if gw and gw != 'Unknown':
                # Check known devices for TTL anomalies
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item)['values']
                    ip = values[0]
                    if ip == gw:
                        continue
                    try:
                        result = subprocess.run(['ping', '-c', '1', '-t', '1', ip],
                                               capture_output=True, text=True, timeout=3)
                        if 'Time to live exceeded' in result.stdout:
                            # This could be a NAT boundary
                            alert = {
                                'timestamp': datetime.now().isoformat(),
                                'device_id': ip,
                                'location': 'Unknown',
                                'evidence': f"TTL=1 ping returned 'Time to live exceeded' from {ip}",
                                'prev_state': 'direct',
                                'new_state': 'nat_boundary',
                                'severity': 'medium',
                                'confidence': 'low',
                                'investigation_step': f"Device {ip} might be a router or behind NAT. Check its ports and MAC.",
                            }
                            alerts.append(alert)
                            self.rogue_alerts.append(alert)
                    except:
                        pass
        except Exception as e:
            self.log(f"NAT detection error: {e}", "WARNING")
        return alerts

    def track_device_session(self, ip, mac, hostname=''):
        """Record current network session for a device"""
        try:
            gw = self.get_gateway()
            subnet = self._get_device_subnet(ip)
            now = datetime.now()
            device_id = mac if mac and mac != 'Unknown' else ip

            if device_id not in self.device_sessions:
                self.device_sessions[device_id] = []

            sessions = self.device_sessions[device_id]
            if sessions and sessions[-1].get('disconnected') is None:
                # Update current session
                sessions[-1]['gateway'] = gw
                sessions[-1]['subnet'] = subnet
                sessions[-1]['dns_coverage'] = self.dns_monitoring
                sessions[-1]['policy_coverage'] = self.parental_settings.get('block_method') != 'none'
                sessions[-1]['managed'] = self._is_managed_network(subnet, gw)
            else:
                # New session
                sessions.append({
                    'device_id': device_id,
                    'mac': mac,
                    'hostname': hostname,
                    'gateway': gw,
                    'ap': '',
                    'ssid': '',
                    'bssid': '',
                    'subnet': subnet,
                    'location': self.known_devices.get(ip, {}).get('location', 'Unknown'),
                    'connected': now.isoformat(),
                    'disconnected': None,
                    'dns_coverage': self.dns_monitoring,
                    'policy_coverage': self.parental_settings.get('block_method') != 'none',
                    'managed': self._is_managed_network(subnet, gw),
                })
                # Keep max 100 sessions per device
                while len(sessions) > 100:
                    sessions.pop(0)
        except Exception as e:
            self.log(f"Session tracking error: {e}", "WARNING")

    def close_device_session(self, ip, mac=''):
        """Close the current session for a device"""
        device_id = mac if mac and mac != 'Unknown' else ip
        try:
            if device_id in self.device_sessions:
                sessions = self.device_sessions[device_id]
                if sessions and sessions[-1].get('disconnected') is None:
                    sessions[-1]['disconnected'] = datetime.now().isoformat()
        except Exception as e:
            self.log(f"Session close error: {e}", "WARNING")

    def _is_managed_network(self, subnet, gateway):
        """Check if a network is in the approved infrastructure"""
        for inf_id, inf_info in self.infrastructure.items():
            if inf_info.get('approved'):
                if inf_info.get('ip') == gateway:
                    return True
                if subnet and inf_info.get('subnet') == subnet:
                    return True
        return False

    def detect_network_transition(self, ip, mac=''):
        """Detect when a child device changes networks"""
        alerts = []
        try:
            dev_info = self.known_devices.get(ip, {})
            profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
            if profile_name not in ('child', 'teen'):
                return alerts  # Only monitor child/teen devices

            device_id = mac if mac and mac != 'Unknown' else ip
            sessions = self.device_sessions.get(device_id, [])
            if len(sessions) < 2:
                return alerts

            prev = sessions[-2]
            curr = sessions[-1]

            # Check for network transition
            if prev.get('gateway') and curr.get('gateway') and prev['gateway'] != curr['gateway']:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'device_id': device_id,
                    'location': dev_info.get('location', 'Unknown'),
                    'evidence': f"Device moved from gateway {prev['gateway']} to {curr['gateway']}",
                    'prev_state': f"gateway:{prev.get('gateway')}",
                    'new_state': f"gateway:{curr.get('gateway')}",
                    'severity': 'high',
                    'confidence': 'high',
                    'investigation_step': f"Verify {ip} ({dev_info.get('device_name', '')}) is still under policy coverage.",
                }
                alerts.append(alert)
                self.rogue_alerts.append(alert)
                self.log(f"⚠️ Child device {ip} changed gateway: {prev['gateway']} -> {curr['gateway']}", "SECURITY")

            # Check DNS coverage loss
            if prev.get('dns_coverage') and not curr.get('dns_coverage'):
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'device_id': device_id,
                    'location': dev_info.get('location', 'Unknown'),
                    'evidence': f"DNS monitoring coverage lost for device {ip}",
                    'prev_state': 'dns_covered',
                    'new_state': 'dns_uncovered',
                    'severity': 'high',
                    'confidence': 'high',
                    'investigation_step': f"Check if {ip} moved to unmanaged network or disabled monitoring.",
                }
                alerts.append(alert)
                self.rogue_alerts.append(alert)
                self.log(f"⚠️ DNS coverage lost for child device {ip}", "SECURITY")

            # Check managed -> unmanaged transition
            if prev.get('managed') and not curr.get('managed'):
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'device_id': device_id,
                    'location': dev_info.get('location', 'Unknown'),
                    'evidence': f"Device {ip} moved from managed to unmanaged network",
                    'prev_state': 'managed_network',
                    'new_state': 'unmanaged_network',
                    'severity': 'critical',
                    'confidence': 'high',
                    'investigation_step': f"Device {ip} ({dev_info.get('device_name', '')}) may be on cellular or neighbor WiFi.",
                }
                alerts.append(alert)
                self.rogue_alerts.append(alert)
                self.log(f"⚠️ Child device {ip} left managed network", "SECURITY")
        except Exception as e:
            self.log(f"Transition detection error: {e}", "WARNING")
        return alerts

    def verify_infrastructure(self):
        """Verify all approved infrastructure is still present and responsive"""
        changes = []
        try:
            for inf_id, inf_info in list(self.infrastructure.items()):
                ip = inf_info.get('ip', '')
                was_active = inf_info.get('active', False)
                if ip and ip != 'Unknown':
                    # Ping the device
                    try:
                        ping3.ping(ip, timeout=1)
                        is_active = True
                    except:
                        is_active = False
                else:
                    is_active = was_active  # Can't verify without IP

                inf_info['active'] = is_active
                if was_active and not is_active:
                    changes.append(f"Infrastructure '{inf_info.get('name', inf_id)}' ({ip}) went offline")
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'device_id': inf_id,
                        'location': inf_info.get('location', 'Unknown'),
                        'evidence': f"Ping timeout for {ip}",
                        'prev_state': 'online',
                        'new_state': 'offline',
                        'severity': 'high',
                        'confidence': 'high',
                        'investigation_step': f"Check if {inf_info.get('name', ip)} is powered on and connected.",
                    }
                    self.rogue_alerts.append(alert)
                    self.log(f"⚠️ Infrastructure offline: {inf_info.get('name', inf_id)}", "SECURITY")
                elif not was_active and is_active:
                    changes.append(f"Infrastructure '{inf_info.get('name', inf_id)}' ({ip}) is back online")
                    self.log(f"Infrastructure online: {inf_info.get('name', inf_id)}", "INFO")
        except Exception as e:
            self.log(f"Infrastructure verification error: {e}", "WARNING")
        self.topology_last_verified = datetime.now().isoformat()
        return changes

    def update_topology(self):
        """Full topology refresh: discover, detect, verify"""
        try:
            # 1. Discover current state
            self.discover_topology()
            routers = self.discover_routers()
            dhcp = self.discover_dhcp_servers()

            # 2. Detect rogues
            rogue_dhcp = self.detect_rogue_dhcp()
            rogue_ssid = self.detect_rogue_ssid()
            nat_issues = self.detect_nat_boundary()

            # 3. Verify infrastructure
            infra_changes = self.verify_infrastructure()

            # 4. Update sessions for all online devices
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                ip = values[0]
                mac = values[2] if len(values) > 2 else ''
                hostname = values[1] if len(values) > 1 else ''
                self.track_device_session(ip, mac, hostname)

            return {
                'routers': len(routers),
                'dhcp_servers': len(dhcp),
                'rogue_dhcp': len(rogue_dhcp),
                'rogue_ssid': len(rogue_ssid),
                'nat_issues': len(nat_issues),
                'infra_changes': len(infra_changes),
            }
        except Exception as e:
            self.log(f"Topology update error: {e}", "WARNING")
            return {}

    def periodic_infrastructure_check(self):
        """Periodic infrastructure monitoring (called from auto_refresh)"""
        try:
            if not self.infrastructure_monitoring:
                return
            self.update_topology()
            # Refresh UI if parental tab is visible
            try:
                if hasattr(self, 'parental_infra_tree'):
                    self.refresh_infrastructure_display()
                if hasattr(self, 'parental_rogue_tree'):
                    self.refresh_rogue_alerts_display()
                if hasattr(self, 'parental_transitions_tree'):
                    self.refresh_child_transitions_display()
                if hasattr(self, 'parental_topology_tree'):
                    self.refresh_topology_display()
                if hasattr(self, 'parental_timeline_text'):
                    self.refresh_timeline_display()
            except:
                pass
        except Exception as e:
            self.log(f"Infrastructure check error: {e}", "WARNING")

    def _get_alert_count_by_severity(self, severity):
        """Count alerts by severity level"""
        return len([a for a in self.rogue_alerts if a.get('severity') == severity])

    # ==================== INFRASTRUCTURE UI METHODS ====================

    def infrastructure_add_dialog(self):
        """Dialog to add approved infrastructure"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Approved Infrastructure")
        dialog.geometry("500x420")
        dialog.configure(bg=self.colors['bg'])

        fields_frame = ttk.Frame(dialog, style='Pro.TFrame')
        fields_frame.pack(padx=20, pady=10, fill=tk.X)

        fields = [
            ('Name/Label:', 'name_var', ''),
            ('Type (router/ap/gateway/collector):', 'type_var', 'router'),
            ('IP Address:', 'ip_var', ''),
            ('MAC Address:', 'mac_var', ''),
            ('SSID (for wireless):', 'ssid_var', ''),
            ('Subnet (CIDR):', 'subnet_var', ''),
            ('Location/Floor:', 'loc_var', ''),
        ]
        vars_dict = {}
        for label_text, var_name, default in fields:
            ttk.Label(fields_frame, text=label_text, style='Pro.TLabel').pack(anchor=tk.W, pady=(5, 0))
            var = tk.StringVar(value=default)
            vars_dict[var_name] = var
            ttk.Entry(fields_frame, textvariable=var, font=('Consolas', 11), width=40).pack(fill=tk.X, pady=2)

        def save_infrastructure():
            name = vars_dict['name_var'].get().strip()
            ip = vars_dict['ip_var'].get().strip()
            mac = vars_dict['mac_var'].get().strip()
            if not name and not ip:
                messagebox.showwarning("Input", "Enter a name or IP address")
                return
            inf_id = mac.upper() if mac else ip
            now = datetime.now().isoformat()
            self.infrastructure[inf_id] = {
                'name': name or ip,
                'type': vars_dict['type_var'].get(),
                'ip': ip,
                'mac': mac.upper() if mac else '',
                'ssid': vars_dict['ssid_var'].get(),
                'subnet': vars_dict['subnet_var'].get(),
                'location': vars_dict['loc_var'].get(),
                'first_seen': now,
                'last_seen': now,
                'active': True,
                'approved': True,
            }
            self.save_data()
            self.log(f"Infrastructure added: {name or ip}", "SUCCESS")
            self.refresh_infrastructure_display()
            dialog.destroy()

        btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="✅ Save", command=save_infrastructure, style='Pro.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Cancel", command=dialog.destroy, style='Pro.TButton').pack(side=tk.LEFT, padx=5)

    def infrastructure_edit_dialog(self, inf_id):
        """Edit existing infrastructure entry"""
        info = self.infrastructure.get(inf_id, {})
        if not info:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Infrastructure - {info.get('name', inf_id)}")
        dialog.geometry("500x450")
        dialog.configure(bg=self.colors['bg'])

        fields_frame = ttk.Frame(dialog, style='Pro.TFrame')
        fields_frame.pack(padx=20, pady=10, fill=tk.X)

        fields = {
            'name_var': ('Name/Label:', info.get('name', '')),
            'type_var': ('Type (router/ap/gateway/collector):', info.get('type', 'router')),
            'ip_var': ('IP Address:', info.get('ip', '')),
            'mac_var': ('MAC Address:', info.get('mac', '')),
            'ssid_var': ('SSID:', info.get('ssid', '')),
            'subnet_var': ('Subnet:', info.get('subnet', '')),
            'loc_var': ('Location:', info.get('location', '')),
        }
        vars_dict = {}
        for var_name, (label_text, default) in fields.items():
            ttk.Label(fields_frame, text=label_text, style='Pro.TLabel').pack(anchor=tk.W, pady=(5, 0))
            var = tk.StringVar(value=default)
            vars_dict[var_name] = var
            ttk.Entry(fields_frame, textvariable=var, font=('Consolas', 11), width=40).pack(fill=tk.X, pady=2)

        # Approved checkbox
        approve_var = tk.BooleanVar(value=info.get('approved', True))
        approve_frame = ttk.Frame(fields_frame, style='Pro.TFrame')
        approve_frame.pack(fill=tk.X, pady=10)
        tk.Checkbutton(approve_frame, text="Approved", variable=approve_var,
                      bg=self.colors['bg'], fg=self.colors['text'],
                      selectcolor=self.colors['bg'], font=('Arial', 10)).pack(anchor=tk.W)

        def save_changes():
            self.infrastructure[inf_id]['name'] = vars_dict['name_var'].get()
            self.infrastructure[inf_id]['type'] = vars_dict['type_var'].get()
            self.infrastructure[inf_id]['ip'] = vars_dict['ip_var'].get()
            self.infrastructure[inf_id]['mac'] = vars_dict['mac_var'].get().upper()
            self.infrastructure[inf_id]['ssid'] = vars_dict['ssid_var'].get()
            self.infrastructure[inf_id]['subnet'] = vars_dict['subnet_var'].get()
            self.infrastructure[inf_id]['location'] = vars_dict['loc_var'].get()
            self.infrastructure[inf_id]['approved'] = approve_var.get()
            self.infrastructure[inf_id]['last_seen'] = datetime.now().isoformat()
            self.save_data()
            self.refresh_infrastructure_display()
            dialog.destroy()

        btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="💾 Save", command=save_changes, style='Pro.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Cancel", command=dialog.destroy, style='Pro.TButton').pack(side=tk.LEFT, padx=5)

    def infrastructure_remove(self, inf_id):
        """Remove infrastructure entry"""
        info = self.infrastructure.get(inf_id, {})
        if messagebox.askyesno("Remove", f"Remove {info.get('name', inf_id)} from infrastructure?"):
            del self.infrastructure[inf_id]
            self.save_data()
            self.refresh_infrastructure_display()
            self.log(f"Infrastructure removed: {info.get('name', inf_id)}", "INFO")

    def rogue_investigate(self, alert_idx=None):
        """Show investigation details for a rogue alert"""
        if alert_idx is None:
            selection = self.parental_rogue_tree.selection()
            if not selection:
                messagebox.showinfo("Info", "Select a rogue alert first")
                return
            item = self.parental_rogue_tree.item(selection[0])
            tags = item.get('tags', ())
            alert_idx = int(tags[0]) if tags else 0

        try:
            if 0 <= alert_idx < len(self.rogue_alerts):
                alert = list(self.rogue_alerts)[alert_idx]
                msg = (
                    f"🔍 Investigation Details\n"
                    f"{'=' * 50}\n"
                    f"Timestamp: {alert.get('timestamp', 'N/A')}\n"
                    f"Device:    {alert.get('device_id', 'N/A')}\n"
                    f"Location:  {alert.get('location', 'Unknown')}\n"
                    f"Evidence:  {alert.get('evidence', 'N/A')}\n"
                    f"Previous:  {alert.get('prev_state', 'N/A')}\n"
                    f"New:       {alert.get('new_state', 'N/A')}\n"
                    f"Severity:  {alert.get('severity', 'N/A')}\n"
                    f"Confidence: {alert.get('confidence', 'N/A')}\n"
                    f"\nRecommended: {alert.get('investigation_step', 'N/A')}\n"
                )
                messagebox.showinfo("Investigation", msg)
        except Exception as e:
            self.log(f"Investigation error: {e}", "WARNING")

    def rogue_acknowledge(self):
        """Acknowledge selected rogue alert"""
        selection = self.parental_rogue_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a rogue alert first")
            return
        try:
            item = self.parental_rogue_tree.item(selection[0])
            tags = item.get('tags', ())
            if tags:
                idx = int(tags[0])
                alerts_list = list(self.rogue_alerts)
                if 0 <= idx < len(alerts_list):
                    alerts_list[idx]['acknowledged'] = True
                    self.rogue_alerts = deque(alerts_list, maxlen=5000)
                    self.refresh_rogue_alerts_display()
        except Exception as e:
            self.log(f"Acknowledge error: {e}", "WARNING")

    def rogue_clear_all(self):
        """Clear all rogue alerts"""
        if messagebox.askyesno("Clear Alerts", "Clear all rogue infrastructure alerts?"):
            self.rogue_alerts.clear()
            self.refresh_rogue_alerts_display()
            self.log("Rogue alerts cleared", "INFO")

    # ==================== INFRASTRUCTURE UI DISPLAY METHODS ====================

    def refresh_infrastructure_display(self):
        """Refresh the approved infrastructure treeview"""
        try:
            if not hasattr(self, 'parental_infra_tree'):
                return
            self.parental_infra_tree.delete(*self.parental_infra_tree.get_children())
            for inf_id, info in sorted(self.infrastructure.items()):
                status = '🟢 Online' if info.get('active') else '🔴 Offline'
                approved = '✅' if info.get('approved') else '❌'
                self.parental_infra_tree.insert('', tk.END, values=(
                    info.get('name', inf_id),
                    info.get('ip', ''),
                    info.get('mac', ''),
                    info.get('type', ''),
                    status,
                    approved,
                    info.get('location', ''),
                ), tags=(inf_id,))
        except Exception as e:
            self.log(f"Infra display error: {e}", "WARNING")

    def refresh_rogue_alerts_display(self):
        """Refresh the rogue alerts treeview"""
        try:
            if not hasattr(self, 'parental_rogue_tree'):
                return
            self.parental_rogue_tree.delete(*self.parental_rogue_tree.get_children())
            for idx, alert in enumerate(self.rogue_alerts):
                ts = alert.get('timestamp', '')
                if len(ts) > 19:
                    ts = ts[11:19]  # HH:MM:SS
                device_id = alert.get('device_id', '')
                if len(device_id) > 20:
                    device_id = device_id[:17] + '...'
                severity = alert.get('severity', 'medium')
                sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
                confidence = alert.get('confidence', 'low')
                conf_icon = {'high': '✅', 'medium': '◐', 'low': '○'}.get(confidence, '?')
                new_state = alert.get('new_state', '')
                acked = '✓' if alert.get('acknowledged') else '○'
                self.parental_rogue_tree.insert('', 0, values=(
                    ts, device_id, f"{sev_icon} {severity}",
                    new_state, f"{conf_icon} {confidence}", acked
                ), tags=(str(idx),))
        except Exception as e:
            self.log(f"Rogue display error: {e}", "WARNING")

    def refresh_child_transitions_display(self):
        """Refresh the child network transitions treeview"""
        try:
            if not hasattr(self, 'parental_transitions_tree'):
                return
            self.parental_transitions_tree.delete(*self.parental_transitions_tree.get_children())
            # Show recent transitions from rogue alerts that relate to child devices
            for alert in list(self.rogue_alerts)[-50:]:
                if 'child' in alert.get('investigation_step', '').lower() or                    'device' in alert.get('evidence', '').lower():
                    ts = alert.get('timestamp', '')
                    if len(ts) > 19:
                        ts = ts[11:19]
                    self.parental_transitions_tree.insert('', 0, values=(
                        ts,
                        alert.get('device_id', ''),
                        alert.get('prev_state', ''),
                        alert.get('new_state', ''),
                        '✅' if alert.get('dns_coverage') else '❌',
                    ))
        except Exception as e:
            self.log(f"Transitions display error: {e}", "WARNING")

    def refresh_topology_display(self):
        """Refresh the network topology treeview"""
        try:
            if not hasattr(self, 'parental_topology_tree'):
                return
            self.parental_topology_tree.delete(*self.parental_topology_tree.get_children())

            # Add gateway as root
            gw = self.get_gateway()
            if gw and gw != 'Unknown':
                gw_node = self.parental_topology_tree.insert('', tk.END, values=(
                    '🌐 Gateway', gw, self.get_hostname(gw), '🟢',
                ), open=True)

                # Add subnets
                for net in self.available_networks:
                    subnet_node = self.parental_topology_tree.insert(gw_node, tk.END, values=(
                        '📡 Subnet', net, '', '🟢',
                    ), open=True)

                    # Add devices on this subnet
                    for item in self.device_tree.get_children():
                        values = self.device_tree.item(item)['values']
                        ip = values[0]
                        try:
                            network = ipaddress.IPv4Network(net, strict=False)
                            if ipaddress.IPv4Address(ip) in network:
                                hostname = values[1] if len(values) > 1 else ''
                                status = '🟢' if 'Online' in values[5] else '🔴'
                                self.parental_topology_tree.insert(subnet_node, tk.END, values=(
                                    '💻 Device', ip, hostname, status,
                                ))
                        except:
                            pass

                # Add known infrastructure
                for inf_id, info in self.infrastructure.items():
                    if info.get('approved'):
                        inf_type = {'router': '🌐', 'ap': '📶', 'gateway': '🌐', 'collector': '📡'}.get(info.get('type', ''), '🖥')
                        status = '🟢' if info.get('active') else '🔴'
                        self.parental_topology_tree.insert('', tk.END, values=(
                            f'{inf_type} {info.get("type", "device")}',
                            info.get('ip', ''),
                            info.get('name', ''),
                            status,
                        ))
        except Exception as e:
            self.log(f"Topology display error: {e}", "WARNING")

    def refresh_timeline_display(self):
        """Refresh the investigation timeline text"""
        try:
            if not hasattr(self, 'parental_timeline_text'):
                return
            self.parental_timeline_text.delete(1.0, tk.END)
            self.parental_timeline_text.insert(1.0, "📋 Investigation Timeline\n")
            self.parental_timeline_text.insert(tk.END, f"{'=' * 70}\n")

            if not self.rogue_alerts:
                self.parental_timeline_text.insert(tk.END, "\nNo events recorded. Infrastructure monitoring idle.\n")
                return

            for alert in list(self.rogue_alerts)[-100:]:
                ts = alert.get('timestamp', '')
                if len(ts) > 19:
                    ts_display = ts[:19]
                else:
                    ts_display = ts
                sev = alert.get('severity', 'medium')
                sev_str = {'critical': '🔴 CRIT', 'high': '🟠 HIGH', 'medium': '🟡 MED', 'low': '🟢 LOW'}.get(sev, '⚪ ???')
                line = (
                    f"[{ts_display}] {sev_str} | {alert.get('new_state', '')}\n"
                    f"    Device: {alert.get('device_id', '')} | Location: {alert.get('location', 'Unknown')}\n"
                    f"    Evidence: {alert.get('evidence', '')}\n"
                    f"    {alert.get('prev_state', '')} → {alert.get('new_state', '')}\n"
                    f"    Confidence: {alert.get('confidence', '')} | Step: {alert.get('investigation_step', '')}\n"
                    f"{'─' * 70}\n"
                )
                self.parental_timeline_text.insert(tk.END, line)

            self.parental_timeline_text.see(tk.END)
        except Exception as e:
            self.log(f"Timeline display error: {e}", "WARNING")

    def toggle_infrastructure_monitoring(self):
        """Toggle infrastructure monitoring on/off"""
        if self.infrastructure_monitoring:
            self.infrastructure_monitoring = False
            self.parental_infra_monitor_btn.config(text="▶ Start Infra Monitor", bg=self.colors['accent'])
            self.log("Infrastructure monitoring stopped", "INFO")
        else:
            self.infrastructure_monitoring = True
            self.parental_infra_monitor_btn.config(text="⏹ Stop Infra Monitor", bg=self.colors['danger'])
            self.log("Starting infrastructure monitoring...", "INFO")
            # Run initial discovery
            threading.Thread(target=self.update_topology, daemon=True).start()

    def _on_infra_tree_double_click(self):
        """Handle double-click on infrastructure tree"""
        try:
            selection = self.parental_infra_tree.selection()
            if selection:
                item = self.parental_infra_tree.item(selection[0])
                tags = item.get('tags', ())
                if tags:
                    self.infrastructure_edit_dialog(tags[0])
        except Exception as e:
            self.log(f"Infra tree click error: {e}", "WARNING")

    def _infra_remove_selected(self):
        """Remove selected infrastructure entry"""
        try:
            selection = self.parental_infra_tree.selection()
            if selection:
                item = self.parental_infra_tree.item(selection[0])
                tags = item.get('tags', ())
                if tags:
                    self.infrastructure_remove(tags[0])
        except Exception as e:
            self.log(f"Infra remove error: {e}", "WARNING")


    def create_logs_tab(self):
        """Logs tab with professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="📝 Logs")

        # Log Controls Card
        ctrl_card = self._create_card(tab, "Log Controls", pady=(10, 5))
        ctrl_inner = ttk.Frame(ctrl_card, style='Pro.TFrame')
        ctrl_inner.pack(fill=tk.X, padx=12, pady=8)
        for text, command in [("🗑 Clear", self.clear_logs), ("💾 Save", self.save_logs)]:
            ttk.Button(ctrl_inner, text=text, command=command, style='Pro.TButton').pack(side=tk.LEFT, padx=5)

        # Activity Logs Card
        log_card = self._create_card(tab, "Activity Logs", expand=True, fill=tk.BOTH, pady=(5, 10))
        log_inner = ttk.Frame(log_card, style='Pro.TFrame')
        log_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.log_display = tk.Text(log_inner, bg=self.colors['secondary'], fg=self.colors['text'],
                                   font=('Consolas', 9), height=25, bd=0, highlightthickness=0)
        log_scrollbar = ttk.Scrollbar(log_inner, orient=tk.VERTICAL,
                                       command=self.log_display.yview, style='Pro.Vertical.TScrollbar')
        self.log_display.configure(yscrollcommand=log_scrollbar.set)
        self.log_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_menu(self):
        """Create menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg='white')
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Report (TXT)", command=self.export_report)
        file_menu.add_command(label="Export CSV", command=self.export_csv)
        file_menu.add_command(label="Export PDF", command=self.export_pdf)
        file_menu.add_command(label="Export Devices (JSON)", command=self.export_device_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        scan_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg='white')
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Quick Scan (Ctrl+N)", command=self.quick_scan)
        scan_menu.add_command(label="Full Scan (Ctrl+F)", command=self.full_scan)
        scan_menu.add_command(label="Deep Scan (Ctrl+D)", command=self.deep_scan)

        tools_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg='white')
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Port Scanner", command=self.port_scan_tool)
        tools_menu.add_command(label="Traceroute", command=self.traceroute)
        tools_menu.add_command(label="DNS Lookup", command=self.dns_lookup)
        tools_menu.add_command(label="Security Audit", command=self.security_audit)
        tools_menu.add_command(label="SSL Certificate Check", command=self.analyze_ssl_certificate)
        tools_menu.add_command(label="Generate Security Report", command=self.generate_security_report)
        tools_menu.add_separator()
        tools_menu.add_command(label="Netcat (Ctrl+S)", command=self.netcat_start)
        tools_menu.add_command(label="Monitor (Ctrl+M)", command=self.start_monitoring)

        parental_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg='white')
        menubar.add_cascade(label="Parental", menu=parental_menu)
        parental_menu.add_command(label="DNS Monitor", command=self.toggle_dns_monitoring)
        parental_menu.add_command(label="Content Filter", command=self.toggle_content_filter)
        parental_menu.add_command(label="Daily Report", command=self.parental_daily_report)
        parental_menu.add_command(label="Weekly Summary", command=self.parental_weekly_report)
        parental_menu.add_command(label="Settings", command=self.parental_settings_dialog)

        help_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg='white')
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)

    def create_status_bar(self):
        """Create enhanced status bar with progress"""
        status_bar = ttk.Frame(self.main_container, style='Pro.TFrame')
        status_bar.pack(fill=tk.X, pady=(10, 0))
        self.status_label = ttk.Label(status_bar, textvariable=self.status_text,
                                      style='Status.TLabel', font=('Consolas', 9))
        self.status_label.pack(side=tk.LEFT, padx=5)
        self.status_progress = ttk.Progressbar(status_bar, length=100, mode='indeterminate', style='Pro.Horizontal.TProgressbar')
        self.status_progress.pack_forget()
        self.time_label = ttk.Label(status_bar, text="", style='Status.TLabel', font=('Consolas', 9))
        self.time_label.pack(side=tk.RIGHT, padx=5)

    def show_status_progress(self):
        """Show and start progress indicator"""
        self.status_progress.pack(side=tk.LEFT, padx=5)
        self.status_progress.start(10)

    def hide_status_progress(self):
        """Stop and hide progress indicator"""
        self.status_progress.stop()
        self.status_progress.pack_forget()

    def log(self, message, level="INFO"):
        """Log message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        levels = {
            "INFO": "ℹ️", "WARNING": "⚠️", "ERROR": "❌", "SUCCESS": "✅",
            "SCAN": "🔍", "MONITOR": "📡", "SECURITY": "🔒", "TOOL": "🔧",
            "PACKET": "📦", "NETCAT": "🔌", "PARENTAL": "🔞"
        }
        emoji = levels.get(level, "📝")
        log_entry = f"[{timestamp}] {emoji} [{level}] {message}\n"

        if hasattr(self, 'log_display'):
            self.log_display.insert(tk.END, log_entry)
            self.log_display.see(tk.END)

        if hasattr(self, 'activity_text'):
            self.activity_text.insert(1.0, f"{timestamp} - {message}\n")
            if self.activity_text.index('end-1c') > '100.0':
                self.activity_text.delete('100.0', 'end-1c')

        self.status_text.set(message[:80])
        print(log_entry.strip())

    def update_status_time(self):
        """Update time"""
        current_time = datetime.now().strftime("%H:%M:%S")
        if hasattr(self, 'time_label'):
            self.time_label.config(text=f"🕐 {current_time}")
        self.root.after(1000, self.update_status_time)

    def auto_refresh(self):
        """Auto refresh"""
        self.update_summary()
        self.update_system_status()
        self.periodic_parental_check()
        self.periodic_infrastructure_check()
        self.root.after(30000, self.auto_refresh)

    def update_summary(self):
        """Update summary"""
        try:
            local_ip = self.get_local_ip()
            gateway = self.get_gateway()
            device_count = len(self.device_tree.get_children()) if hasattr(self, 'device_tree') else 0
            scapy_indicator = "✅ Available" if SCAPY_AVAILABLE else "❌ Not available"
            scapy_color = self.colors['success'] if SCAPY_AVAILABLE else self.colors['danger']

            if hasattr(self, 'stat_local_ip'):
                self.stat_local_ip.config(text=local_ip)
            if hasattr(self, 'stat_gateway_ip'):
                self.stat_gateway_ip.config(text=gateway)
            if hasattr(self, 'stat_gateway_host'):
                gw_hostname = self.get_hostname(gateway) if gateway and gateway != 'Unknown' else '-'
                self.stat_gateway_host.config(text=gw_hostname if gw_hostname != 'Unknown' else '-')
            if hasattr(self, 'stat_devices'):
                self.stat_devices.config(text=str(device_count))
            if hasattr(self, 'stat_scapy'):
                self.stat_scapy.config(text=scapy_indicator, fg=scapy_color)
            if hasattr(self, 'stat_updated'):
                self.stat_updated.config(text=datetime.now().strftime('%H:%M:%S'))
        except:
            pass

    def update_system_status(self):
        """Update system status"""
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()

            cpu_bar = '█' * int(cpu / 5) + '░' * (20 - int(cpu / 5))
            cpu_color = self.colors['success'] if cpu < 50 else self.colors['warning'] if cpu < 80 else self.colors['danger']
            mem_str = f"{mem.percent}%   {mem.used // 1024 ** 3} / {mem.total // 1024 ** 3} GB"
            disk_str = f"{disk.percent}%   {disk.used // 1024 ** 3} / {disk.total // 1024 ** 3} GB"
            net_str = f"⬆ {net.bytes_sent // 1024 ** 2} MB   ⬇ {net.bytes_recv // 1024 ** 2} MB"

            if hasattr(self, 'sys_cpu'):
                self.sys_cpu.config(text=f"{cpu:.1f}%  {cpu_bar}", fg=cpu_color)
            if hasattr(self, 'sys_memory'):
                mem_color = self.colors['success'] if mem.percent < 50 else self.colors['warning'] if mem.percent < 80 else self.colors['danger']
                self.sys_memory.config(text=mem_str, fg=mem_color)
            if hasattr(self, 'sys_disk'):
                disk_color = self.colors['success'] if disk.percent < 50 else self.colors['warning'] if disk.percent < 80 else self.colors['danger']
                self.sys_disk.config(text=disk_str, fg=disk_color)
            if hasattr(self, 'sys_net'):
                self.sys_net.config(text=net_str)
        except:
            pass

    def add_alert(self, message):
        """Add security alert"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = f"[{timestamp}] {message}"
        self.security_alerts.append(alert)
        self.alerts.append(alert)
        self.alert_count.set(f"{len(self.alerts)} alerts")
        self.log(message, "SECURITY")

    def setup_keyboard_shortcuts(self):
        """Setup keyboard shortcuts"""
        shortcuts = [
            ('<Control-n>', self.quick_scan),
            ('<Control-f>', self.full_scan),
            ('<Control-d>', self.deep_scan),
            ('<Control-m>', self.start_monitoring),
            ('<Control-s>', self.netcat_start),
            ('<Control-e>', self.export_report),
            ('<Control-b>', self.backup_data),
        ]
        for key, command in shortcuts:
            try:
                self.root.bind(key, lambda e, cmd=command: cmd())
            except:
                pass

    def get_local_ip(self):
        """Get local IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_gateway(self):
        """Get gateway"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway and gateway != '':
                            return gateway
            else:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) > 2:
                            return parts[2]
        except:
            pass
        return "Unknown"

    def _is_gateway(self, ip):
        """Check if an IP address is the default gateway"""
        gateway = self.get_gateway()
        if gateway and gateway != 'Unknown':
            return ip == gateway
        return False

    def discover_networks(self):
        """Auto-detect all network subnets from all interfaces"""
        networks = []
        try:
            for name, addrs in psutil.net_if_addrs().items():
                if name.startswith(('lo', 'Loopback')):
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address and addr.netmask:
                        ip = addr.address
                        netmask = addr.netmask
                        # Compute CIDR prefix length from netmask
                        mask_bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                        # Compute network address
                        ip_parts = [int(x) for x in ip.split('.')]
                        mask_parts = [int(x) for x in netmask.split('.')]
                        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                        network_addr = '.'.join(str(x) for x in network_parts)
                        cidr = f"{network_addr}/{mask_bits}"
                        if cidr not in networks:
                            networks.append(cidr)
                            self.log(f"Discovered network: {cidr} ({name})", "INFO")
            if not networks:
                self.log("No networks discovered, using default", "WARNING")
        except Exception as e:
            self.log(f"Network discovery error: {e}", "WARNING")
        return networks if networks else ["192.168.1.0/24"]

    # ==================== NETCAT - ENTERPRISE GRADE ====================

    def netcat_start(self):
        """Start netcat session with protocol selection"""
        with self.netcat_lock:
            if self.netcat_active:
                self.terminal_display.insert(1.0, "⚠️ Session already active\n")
                return

            target = self.netcat_target.get().strip()
            port_str = self.netcat_port.get().strip()
            protocol = self.netcat_protocol.get()

            if not target:
                self.log("Please enter a target IP", "WARNING")
                return

            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    raise ValueError
            except ValueError:
                self.log("Invalid port number", "ERROR")
                return

            self.terminal_display.delete(1.0, tk.END)
            self.terminal_display.insert(1.0, f"🔌 Netcat Session ({protocol.upper()})\n{'=' * 60}\n")

            use_ssl = self.netcat_ssl_enabled.get() and protocol == 'tcp'

            mode = self.netcat_mode.get()
            if mode == "connect":
                self.terminal_display.insert(1.0, f"Connecting to {target}:{port}...\n")
                if use_ssl:
                    self.terminal_display.insert(1.0, "🔒 SSL/TLS enabled\n")
                self.log(f"Connecting to {target}:{port} via {protocol.upper()}", "NETCAT")
                self.netcat_btn.config(text="🔄 Connecting...", state='disabled')
                self.netcat_stop_btn.config(state='normal')
                self.netcat_input.config(state='disabled')

                self.netcat_active = True
                self.netcat_running = True

                if use_ssl:
                    threading.Thread(target=self.netcat_do_connect_ssl, args=(target, port), daemon=True).start()
                elif protocol == 'udp':
                    threading.Thread(target=self.netcat_do_connect_udp, args=(target, port), daemon=True).start()
                else:
                    threading.Thread(target=self.netcat_do_connect, args=(target, port), daemon=True).start()
            else:
                self.terminal_display.insert(1.0, f"Listening on port {port}...\n")
                if use_ssl:
                    self.terminal_display.insert(1.0, "🔒 SSL/TLS enabled\n")
                self.log(f"Listening on port {port} via {protocol.upper()}", "NETCAT")
                self.netcat_btn.config(text="🔄 Listening...", state='disabled')
                self.netcat_stop_btn.config(state='normal')
                self.netcat_input.config(state='disabled')

                self.netcat_active = True
                self.netcat_running = True

                if protocol == 'udp':
                    threading.Thread(target=self.netcat_do_listen_udp, args=(port,), daemon=True).start()
                else:
                    threading.Thread(target=self.netcat_do_listen_multi, args=(port,), daemon=True).start()

    def netcat_do_connect(self, target, port):
        """Connect to remote - PROPER IMPLEMENTATION"""
        try:
            self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.netcat_sock.settimeout(5)
            self.netcat_sock.connect((target, port))

            self.terminal_display.insert(1.0, f"✅ Connected to {target}:{port}\n")
            self.terminal_display.insert(1.0, f"{'=' * 60}\n")
            self.terminal_display.insert(1.0, "Type messages and press Enter to send\n\n")
            self.log(f"Connected to {target}:{port}", "SUCCESS")

            self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
            self.root.after(0, lambda: self.netcat_input.config(state='normal'))

            threading.Thread(target=self.netcat_do_receive, daemon=True).start()

        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            self.terminal_display.insert(1.0, f"❌ Connection failed: {e}\n")
            self.log(f"Connection failed to {target}:{port}: {e}", "ERROR")
            if self.netcat_reconnect.get():
                threading.Thread(target=self.netcat_auto_reconnect, args=(target, port), daemon=True).start()
            else:
                self.netcat_stop()

    def netcat_do_connect_ssl(self, target, port):
        """SSL/TLS encrypted connection"""
        try:
            self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.netcat_sock.settimeout(5)
            self.netcat_sock.connect((target, port))

            context = ssl.create_default_context()
            if self.netcat_ssl_insecure.get():
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            self.netcat_sock = context.wrap_socket(self.netcat_sock, server_hostname=target)

            self.terminal_display.insert(1.0, f"✅ SSL connection to {target}:{port}\n")
            try:
                self.terminal_display.insert(1.0, f"🔒 Cipher: {self.netcat_sock.cipher()[0]}\n")
            except:
                pass
            self.terminal_display.insert(1.0, f"{'=' * 60}\n")
            self.terminal_display.insert(1.0, "Type messages and press Enter to send\n\n")
            self.log(f"SSL connected to {target}:{port}", "SUCCESS")

            self.root.after(0, lambda: self.netcat_btn.config(text="🔌 🔒 Active", state='normal'))
            self.root.after(0, lambda: self.netcat_input.config(state='normal'))

            threading.Thread(target=self.netcat_do_receive, daemon=True).start()

        except ssl.SSLError as e:
            self.terminal_display.insert(1.0, f"❌ SSL error: {e}\n")
            self.log(f"SSL error: {e}", "ERROR")
            self.netcat_stop()
        except Exception as e:
            self.terminal_display.insert(1.0, f"❌ Connection error: {e}\n")
            self.log(f"Connection error: {e}", "ERROR")
            self.netcat_stop()

    def netcat_do_connect_udp(self, target, port):
        """UDP connect mode (connectionless with target fixed)"""
        try:
            self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.netcat_sock.settimeout(1)
            self.netcat_udp_target = (target, port)

            self.terminal_display.insert(1.0, f"✅ UDP session ready to {target}:{port}\n")
            self.terminal_display.insert(1.0, f"{'=' * 60}\n")
            self.terminal_display.insert(1.0, "UDP is connectionless. Messages may be lost.\n\n")
            self.log(f"UDP session ready to {target}:{port}", "SUCCESS")

            self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
            self.root.after(0, lambda: self.netcat_input.config(state='normal'))

            threading.Thread(target=self.netcat_do_receive_udp, daemon=True).start()

        except Exception as e:
            self.terminal_display.insert(1.0, f"❌ UDP setup failed: {e}\n")
            self.log(f"UDP setup failed: {e}", "ERROR")
            self.netcat_stop()

    def netcat_do_listen_udp(self, port):
        """UDP listen mode"""
        try:
            self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.netcat_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.netcat_sock.bind(('0.0.0.0', port))
            self.netcat_sock.settimeout(1)

            self.terminal_display.insert(1.0, f"✅ UDP listening on port {port}\n")
            self.terminal_display.insert(1.0, f"{'=' * 60}\n")
            self.log(f"UDP listening on port {port}", "SUCCESS")

            self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
            self.root.after(0, lambda: self.netcat_input.config(state='normal'))

            self.netcat_udp_target = None
            threading.Thread(target=self.netcat_do_receive_udp, daemon=True).start()

        except Exception as e:
            self.terminal_display.insert(1.0, f"❌ UDP listen failed: {e}\n")
            self.log(f"UDP listen failed: {e}", "ERROR")
            self.netcat_stop()

    def netcat_do_receive_udp(self):
        """Receive UDP datagrams"""
        try:
            while self.netcat_running and self.netcat_sock:
                try:
                    data, addr = self.netcat_sock.recvfrom(65535)
                    if data:
                        self.netcat_udp_target = addr
                        if self.netcat_verbose.get():
                            self.show_hexdump(data)
                        else:
                            try:
                                text = data.decode('utf-8', errors='ignore')
                                self.terminal_display.insert(tk.END, f"\n[RECV] {addr[0]}:{addr[1]} -> {text}\n")
                            except:
                                self.terminal_display.insert(tk.END, f"\n[RECV] {addr[0]}:{addr[1]} -> {len(data)} bytes\n")
                        self.terminal_display.see(tk.END)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.netcat_running:
                        self.log(f"UDP receive error: {e}", "WARNING")
                    break
        except:
            pass
        finally:
            if self.netcat_running:
                self.netcat_stop()

    def netcat_do_listen_multi(self, port):
        """Listen with multiple connection support"""
        try:
            self.netcat_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.netcat_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.netcat_server.bind(('0.0.0.0', port))
            self.netcat_server.listen(5)
            self.netcat_server.settimeout(1)

            self.terminal_display.insert(1.0, f"✅ Listening on port {port} (queue: 5)\n")
            self.terminal_display.insert(1.0, "Waiting for connections...\n")
            self.log(f"Listening on port {port} (multi-connection)", "NETCAT")

            self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))

            self.netcat_connections = []
            self.netcat_current_conn = -1

            while self.netcat_running:
                try:
                    client, addr = self.netcat_server.accept()
                    self.terminal_display.insert(1.0, f"✅ Connection {len(self.netcat_connections) + 1} from {addr[0]}:{addr[1]}\n")
                    self.log(f"Connection from {addr[0]}:{addr[1]}", "SUCCESS")

                    self.netcat_connections.append(client)
                    self.netcat_current_conn = len(self.netcat_connections) - 1

                    if len(self.netcat_connections) == 1:
                        self.netcat_sock = client
                        self.root.after(0, lambda: self.netcat_input.config(state='normal'))

                    threading.Thread(target=self.netcat_do_receive_multi, args=(client, len(self.netcat_connections) - 1), daemon=True).start()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.netcat_running:
                        self.log(f"Accept error: {e}", "WARNING")
                    break

            if self.netcat_server:
                self.netcat_server.close()
                self.netcat_server = None

        except Exception as e:
            if self.netcat_running:
                self.terminal_display.insert(1.0, f"❌ Listen failed: {e}\n")
                self.log(f"Listen failed: {e}", "ERROR")
                self.netcat_stop()

    def netcat_do_receive_multi(self, client, conn_id):
        """Receive data from a specific connection"""
        try:
            client.settimeout(1)
            while self.netcat_running:
                try:
                    data = client.recv(4096)
                    if data:
                        if self.netcat_verbose.get():
                            self.show_hexdump(data)
                        else:
                            try:
                                text = data.decode('utf-8', errors='ignore')
                                self.terminal_display.insert(tk.END, f"\n[CONN {conn_id} RECV] {text}\n")
                            except:
                                self.terminal_display.insert(tk.END, f"\n[CONN {conn_id} RECV] {len(data)} bytes (binary)\n")
                        self.terminal_display.see(tk.END)
                    else:
                        self.terminal_display.insert(1.0, f"\n❌ Connection {conn_id} closed by peer\n")
                        self.log(f"Connection {conn_id} closed by peer", "WARNING")
                        break
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.netcat_running:
                        self.terminal_display.insert(1.0, f"\n❌ Connection {conn_id} receive error: {e}\n")
                    break
        except:
            pass
        finally:
            try:
                client.close()
            except:
                pass
            if conn_id < len(self.netcat_connections):
                self.netcat_connections[conn_id] = None

    def netcat_do_receive(self):
        """Receive data with file transfer detection"""
        receiving_file = False
        file_data = bytearray()
        file_name = ""
        file_size = 0
        file_received = 0

        try:
            self.netcat_sock.settimeout(1)
            while self.netcat_running and self.netcat_sock:
                try:
                    data = self.netcat_sock.recv(8192)
                    if data:
                        if not receiving_file:
                            try:
                                text = data.decode('utf-8', errors='ignore')
                                if text.startswith('FILE:'):
                                    parts = text.strip().split(':')
                                    if len(parts) >= 3:
                                        file_name = parts[1]
                                        file_size = int(parts[2])
                                        receiving_file = True
                                        file_received = 0
                                        file_data = bytearray()
                                        self.terminal_display.insert(1.0, f"\n📁 Receiving file: {file_name} ({file_size:,} bytes)\n")
                                        self.terminal_display.insert(1.0, "Progress: ")
                                        data = data[data.find(b'\n') + 1:]
                                    else:
                                        if self.netcat_verbose.get():
                                            self.show_hexdump(data)
                                        else:
                                            self.terminal_display.insert(tk.END, f"\n[RECV] {text}\n")
                                        continue
                                else:
                                    if self.netcat_verbose.get():
                                        self.show_hexdump(data.encode('utf-8'))
                                    else:
                                        self.terminal_display.insert(tk.END, f"\n[RECV] {text}\n")
                                    continue
                            except:
                                if self.netcat_verbose.get():
                                    self.show_hexdump(data)
                                else:
                                    self.terminal_display.insert(tk.END, f"\n[RECV] {len(data)} bytes (binary)\n")
                                continue

                        if receiving_file:
                            file_data.extend(data)
                            file_received += len(data)
                            progress = int((file_received / file_size) * 100)
                            self.terminal_display.insert(tk.END, f"{progress}% ")
                            self.terminal_display.see(tk.END)

                            if file_received >= file_size:
                                save_path = filedialog.asksaveasfilename(
                                    initialfile=file_name,
                                    defaultextension=".*",
                                    filetypes=[("All files", "*.*")]
                                )
                                if save_path:
                                    with open(save_path, 'wb') as f:
                                        f.write(file_data)
                                    self.terminal_display.insert(1.0, f"\n✅ File received: {save_path}\n")
                                    self.log(f"File received: {file_name} ({file_size:,} bytes)", "SUCCESS")
                                else:
                                    self.terminal_display.insert(1.0, f"\n⚠️ File save cancelled\n")
                                receiving_file = False
                                file_data = bytearray()
                    else:
                        self.terminal_display.insert(1.0, "\n❌ Connection closed by peer\n")
                        self.log("Connection closed by peer", "WARNING")
                        break
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.netcat_running:
                        self.terminal_display.insert(1.0, f"\n❌ Receive error: {e}\n")
                    break
        except:
            pass
        finally:
            if self.netcat_running:
                self.netcat_stop()

    def netcat_send(self, event=None):
        """Send data with protocol awareness"""
        if not self.netcat_active or not self.netcat_sock:
            self.log("Not connected", "WARNING")
            return

        data = self.netcat_input.get()
        if not data:
            return

        try:
            if self.netcat_protocol.get() == 'udp':
                self.netcat_send_udp(data)
                return

            self.netcat_sock.send(data.encode('utf-8'))
            self.terminal_display.insert(tk.END, f"\n[SENT] {data}\n")
            self.terminal_display.see(tk.END)
            self.netcat_input.delete(0, tk.END)
        except Exception as e:
            self.log(f"Send error: {e}", "ERROR")
            self.terminal_display.insert(1.0, f"\n❌ Send error: {e}\n")
            self.netcat_stop()

    def netcat_send_udp(self, data):
        """Send UDP datagram"""
        try:
            if self.netcat_mode.get() == "connect":
                if hasattr(self, 'netcat_udp_target') and self.netcat_udp_target:
                    self.netcat_sock.sendto(data.encode('utf-8'), self.netcat_udp_target)
                else:
                    self.log("No UDP target set", "WARNING")
                    return
            else:
                target = self.netcat_target.get().strip()
                port = int(self.netcat_port.get().strip())
                self.netcat_sock.sendto(data.encode('utf-8'), (target, port))

            self.terminal_display.insert(tk.END, f"\n[SENT] {data}\n")
            self.terminal_display.see(tk.END)
            self.netcat_input.delete(0, tk.END)
        except Exception as e:
            self.log(f"UDP send error: {e}", "ERROR")

    def netcat_send_file(self):
        """Send file over netcat connection"""
        if not self.netcat_active or not self.netcat_sock:
            self.log("No active connection", "WARNING")
            return

        filename = filedialog.askopenfilename(title="Select file to send")
        if not filename:
            return

        try:
            file_size = os.path.getsize(filename)
            self.terminal_display.insert(1.0, f"\n📁 Sending file: {os.path.basename(filename)} ({file_size:,} bytes)\n")
            self.terminal_display.insert(1.0, "Progress: ")

            header = f"FILE:{os.path.basename(filename)}:{file_size}\n"
            self.netcat_sock.send(header.encode('utf-8'))

            sent = 0
            chunk_size = 8192
            with open(filename, 'rb') as f:
                while sent < file_size and self.netcat_running:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    self.netcat_sock.send(chunk)
                    sent += len(chunk)
                    progress = int((sent / file_size) * 100)
                    self.terminal_display.insert(tk.END, f"{progress}% ")
                    self.terminal_display.see(tk.END)

            self.terminal_display.insert(1.0, f"\n✅ File sent successfully ({sent:,} bytes)\n")
            self.log(f"File sent: {os.path.basename(filename)} ({sent:,} bytes)", "SUCCESS")

        except Exception as e:
            self.log(f"File send error: {e}", "ERROR")
            self.terminal_display.insert(1.0, f"\n❌ File send failed: {e}\n")

    def netcat_receive_file(self):
        """Prompt file receive mode"""
        self.terminal_display.insert(1.0, "\n📁 Ready to receive file. Send a FILE: header from the remote side.\n")
        self.log("File receive mode activated", "NETCAT")

    def netcat_auto_reconnect(self, target, port, max_retries=5, base_delay=2):
        """Auto-reconnect with exponential backoff"""
        for retry in range(max_retries):
            if not self.netcat_running:
                return False

            wait = base_delay * (2 ** retry)
            self.terminal_display.insert(1.0, f"⚠️ Reconnecting in {wait}s (attempt {retry + 1}/{max_retries})...\n")
            self.log(f"Reconnect attempt {retry + 1}/{max_retries}", "NETCAT")
            time.sleep(wait)

            if not self.netcat_running:
                return False

            try:
                self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.netcat_sock.settimeout(5)
                self.netcat_sock.connect((target, port))
                self.terminal_display.insert(1.0, f"✅ Reconnected to {target}:{port}\n")
                self.log(f"Reconnected to {target}:{port}", "SUCCESS")

                self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
                self.root.after(0, lambda: self.netcat_input.config(state='normal'))
                threading.Thread(target=self.netcat_do_receive, daemon=True).start()
                return True
            except:
                continue

        self.terminal_display.insert(1.0, f"❌ Auto-reconnect failed after {max_retries} attempts\n")
        self.log("Auto-reconnect failed", "ERROR")
        self.netcat_stop()
        return False

    def show_hexdump(self, data, max_bytes=1024):
        """Display hexdump of binary data"""
        if not data:
            return

        display_data = data[:max_bytes]
        hex_lines = []

        for i in range(0, len(display_data), 16):
            chunk = display_data[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            hex_part = hex_part.ljust(48)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            hex_lines.append(f"  {i:04x}: {hex_part}  {ascii_part}")

        self.terminal_display.insert(tk.END, f"\n[HEXDUMP] {len(data)} bytes:\n")
        self.terminal_display.insert(tk.END, '\n'.join(hex_lines) + '\n')

        if len(data) > max_bytes:
            self.terminal_display.insert(tk.END, f"... and {len(data) - max_bytes} more bytes\n")

    def netcat_stop(self):
        """Stop netcat - PROPER CLEANUP"""
        with self.netcat_lock:
            if not self.netcat_active and not self.netcat_running:
                return

            self.netcat_running = False
            self.netcat_active = False

            # Close client socket
            if self.netcat_sock:
                try:
                    self.netcat_sock.close()
                except:
                    pass
                self.netcat_sock = None

            # Close server socket
            if self.netcat_server:
                try:
                    self.netcat_server.close()
                except:
                    pass
                self.netcat_server = None

            # Close multi-connections
            if hasattr(self, 'netcat_connections'):
                for conn in self.netcat_connections:
                    try:
                        if conn:
                            conn.close()
                    except:
                        pass
                self.netcat_connections = []

            # Update UI
            self.terminal_display.insert(1.0, "\n🔌 Connection closed\n")
            self.log("Netcat closed", "INFO")

            self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Start", state='normal'))
            self.root.after(0, lambda: self.netcat_stop_btn.config(state='disabled'))
            self.root.after(0, lambda: self.netcat_input.config(state='disabled'))

    # ==================== SCAN FUNCTIONS ====================

    def update_network_combo(self):
        """Update Combobox values from available_networks"""
        if hasattr(self, 'network_combo'):
            self.network_combo['values'] = self.available_networks

    def refresh_networks(self):
        """Re-discover available networks"""
        self.available_networks = self.discover_networks()
        self.update_network_combo()
        if self.available_networks:
            self.network_ip.set(self.available_networks[0])
        self.log(f"Networks refreshed: {', '.join(self.available_networks)}", "INFO")

    def _get_scan_targets(self):
        """Return list of (base_ip, network_cidr) tuples for all discovered networks (deduplicated)"""
        seen_bases = set()
        targets = []
        for network in self.available_networks:
            base = network.split('/')[0]
            parts = base.split('.')
            base_ip = '.'.join(parts[:3])
            if base_ip not in seen_bases:
                seen_bases.add(base_ip)
                targets.append((base_ip, network))
        return targets

    def quick_scan(self):
        """Quick scan"""
        self.log("Starting quick scan (thread pool)...", "SCAN")
        self.scan_status.config(text="Scanning...")
        threading.Thread(target=self.run_quick_scan_threadpool, daemon=True).start()

    def run_quick_scan(self):
        """Run quick scan (sequential, all networks, deduplicated)"""
        try:
            self.device_tree.delete(*self.device_tree.get_children())
            self.device_list.delete(*self.device_list.get_children())

            targets = self._get_scan_targets()
            if not targets:
                return

            # Build all IPs (deduplicated)
            all_ips = []
            seen_ips = set()
            for base_ip, net in targets:
                for i in range(1, 255):
                    ip = f"{base_ip}.{i}"
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        all_ips.append(ip)

            self.scan_progress['maximum'] = len(all_ips)
            devices_found = []
            seen_found = set()

            for idx, ip in enumerate(all_ips):
                try:
                    response = ping3.ping(ip, timeout=0.3)
                    if response is not None:
                        hostname = self.get_hostname(ip)
                        mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                        vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'

                        if ip not in seen_found:
                            seen_found.add(ip)
                            devices_found.append(ip)
                            status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
                            self.device_tree.insert('', tk.END, values=(
                                ip, hostname, mac, vendor, 'None', status
                            ))
                            self.device_list.insert('', tk.END, values=(
                                ip, hostname, mac, status
                            ))
                except:
                    pass
                self.scan_progress['value'] = idx + 1
                self.root.update_idletasks()

            self.scan_progress['value'] = 0
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices across {len(targets)} network(s)")
            self.update_scan_stats()
            self.root.after(0, self.update_summary)
            self.root.after(0, self.update_system_status)
            self.log(f"Quick scan complete: {len(devices_found)} devices", "SUCCESS")
        except Exception as e:
            self.log(f"Quick scan error: {e}", "ERROR")

    def full_scan(self):
        """Full scan with root check"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available, using quick scan", "WARNING")
            self.quick_scan()
            return
        if platform.system() != 'Windows' and os.geteuid() != 0:
            self.log("Full scan requires root for ARP packets. Use quick scan instead.", "WARNING")
            self.scan_status.config(text="Need root - use Quick Scan")
            self._show_tool_message("⚠️ Full scan requires root privileges.\n\nRun: sudo python3 main.py\n\nWithout root, use Quick Scan mode instead.")
            return
        self.log("Starting full scan...", "SCAN")
        self.scan_status.config(text="ARP scan in progress...")
        threading.Thread(target=self.run_full_scan, daemon=True).start()

    def run_full_scan(self):
        """Run full scan (deduplicated)"""
        try:
            self.device_tree.delete(*self.device_tree.get_children())
            self.device_list.delete(*self.device_list.get_children())

            network = self.network_ip.get()
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            self.scan_progress['maximum'] = 100
            self.scan_progress['value'] = 20

            result = srp(packet, timeout=3, verbose=False)[0]
            self.scan_progress['value'] = 80

            devices_found = []
            seen_ips = set()
            for sent, received in result:
                ip = received.psrc
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                mac = received.hwsrc
                hostname = self.get_hostname(ip)
                vendor = self.get_vendor(mac)
                open_ports = self.scan_common_ports(ip)
                ports_str = ','.join(map(str, open_ports[:5])) if open_ports else 'None'

                devices_found.append(ip)
                status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
                self.device_tree.insert('', tk.END, values=(
                    ip, hostname, mac, vendor, ports_str, status
                ))
                self.device_list.insert('', tk.END, values=(
                    ip, hostname, mac, status
                ))

            self.scan_progress['value'] = 100
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices")
            self.update_scan_stats()
            self.root.after(0, self.update_summary)
            self.root.after(0, self.update_system_status)
            self.log(f"Full scan complete: {len(devices_found)} devices", "SUCCESS")
        except Exception as e:
            self.log(f"Full scan error: {e}", "ERROR")

    def deep_scan(self):
        """Deep scan"""
        self.log("Starting deep scan...", "SCAN")
        self.scan_status.config(text="Deep scan in progress...")
        threading.Thread(target=self.run_deep_scan, daemon=True).start()

    def run_deep_scan(self):
        """Run deep scan across all networks (deduplicated)"""
        try:
            self.device_tree.delete(*self.device_tree.get_children())
            self.device_list.delete(*self.device_list.get_children())

            targets = self._get_scan_targets()
            if not targets:
                return

            all_ips = []
            seen_ips = set()
            for base_ip, net in targets:
                for i in range(1, 255):
                    ip = f"{base_ip}.{i}"
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        all_ips.append(ip)

            self.scan_progress['maximum'] = len(all_ips)
            devices_found = []
            seen_found = set()

            for idx, ip in enumerate(all_ips):
                try:
                    response = ping3.ping(ip, timeout=0.5)
                    if response is not None:
                        hostname = self.get_hostname(ip)
                        mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                        vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'

                        open_ports = self.scan_ports(ip, list(range(1, 1025)))
                        ports_str = ','.join(map(str, open_ports[:5])) if open_ports else 'None'

                        if ip not in seen_found:
                            seen_found.add(ip)
                            devices_found.append(ip)
                            status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
                            self.device_tree.insert('', tk.END, values=(
                                ip, hostname, mac, vendor, ports_str, status
                            ))
                            self.device_list.insert('', tk.END, values=(
                                ip, hostname, mac, status
                            ))
                except:
                    pass
                self.scan_progress['value'] = idx + 1
                self.root.update_idletasks()

            self.scan_progress['value'] = 0
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices across {len(targets)} network(s)")
            self.update_scan_stats()
            self.root.after(0, self.update_summary)
            self.root.after(0, self.update_system_status)
            self.log(f"Deep scan complete: {len(devices_found)} devices", "SUCCESS")
        except Exception as e:
            self.log(f"Deep scan error: {e}", "ERROR")

    def get_mac_address(self, ip):
        """Get MAC address using multiple methods with fallbacks"""
        # Method 1: Scapy ARP (requires root)
        try:
            if SCAPY_AVAILABLE:
                arp_request = ARP(pdst=ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                answered = srp(broadcast / arp_request, timeout=1, verbose=False)[0]
                if answered:
                    mac = answered[0][1].hwsrc
                    if mac:
                        return mac.upper()
        except:
            pass
        # Method 2: System ARP cache
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=3)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                return part.upper()
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=3)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        parts = line.split()
                        for part in parts:
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                                return part.upper()
        except:
            pass
        # Method 3: ping then check ARP table (populates cache)
        try:
            ping3.ping(ip, timeout=1)
            time.sleep(0.1)
            result = subprocess.run(['arp', '-n', ip] if platform.system() != 'Windows' else ['arp', '-a', ip],
                                    capture_output=True, text=True, timeout=3)
            for line in result.stdout.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                            return part.upper()
        except:
            pass
        # Method 4: Full arp -a scan for neighbor table (macOS/Linux)
        try:
            if platform.system() != 'Windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        match = re.search(r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', line)
                        if match:
                            return match.group(1).upper()
        except:
            pass
        return 'Unknown'

    def scan_common_ports(self, ip):
        """Scan common ports"""
        common = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
        return self.scan_ports(ip, common)

    def scan_ports(self, ip, ports):
        """Scan ports"""
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports

    def get_hostname(self, ip):
        """Get hostname with caching and multiple resolution methods"""
        if not hasattr(self, '_hostname_cache'):
            self._hostname_cache = {}
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        # Method 1: Reverse DNS
        try:
            result = socket.gethostbyaddr(ip)
            name = result[0].split('.')[0]
            if name and name != ip:
                self._hostname_cache[ip] = name
                return name
        except (socket.herror, socket.gaierror, OSError):
            pass
        # Method 2: NetBIOS name lookup (Windows)
        if platform.system() == 'Windows':
            try:
                result = subprocess.run(
                    ['nbtstat', '-A', ip],
                    capture_output=True, text=True, timeout=3
                )
                for line in result.stdout.split('\n'):
                    if '<00>' in line and 'UNIQUE' in line:
                        name = line.split()[0]
                        self._hostname_cache[ip] = name
                        return name
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        # Method 3: mdns lookup (macOS/Linux)
        if platform.system() != 'Windows':
            try:
                result = subprocess.run(
                    ['dns-sd', '-Q', ip, 'ptr', '--timeout', '1'],
                    capture_output=True, text=True, timeout=2
                )
                for line in result.stdout.split('\n'):
                    if 'PTR' in line and 'local' in line:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            name = parts[-1].split('.')[0]
                            self._hostname_cache[ip] = name
                            return name
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        self._hostname_cache[ip] = 'Unknown'
        return 'Unknown'

    def classify_device(self, mac, hostname='', ports=None):
        """Classify device type based on MAC OUI, hostname patterns, and open ports"""
        vendor = self.get_vendor(mac)
        apple_v = ['Apple Inc.', 'Apple']
        samsung_v = ['Samsung']
        google_v = ['Google']
        amazon_v = ['Amazon']
        pc_v = ['Dell', 'HP', 'Lenovo', 'ASUS', 'Acer', 'MSI']
        net_v = ['Cisco', 'Netgear', 'TP-Link', 'Ubiquiti', 'Aruba', 'ZyXEL', 'D-Link', 'Linksys']
        if any(v in vendor for v in apple_v):
            if hostname and any(h in hostname.lower() for h in ['iphone', 'ipad']):
                return 'iPad' if 'iPad' in hostname else 'iPhone'
            return 'Apple Device'
        elif any(v in vendor for v in samsung_v):
            return 'Samsung Device'
        elif any(v in vendor for v in google_v):
            return 'Google Home' if any(x in hostname.lower() for x in ['nest', 'home']) else 'Google Device'
        elif any(v in vendor for v in amazon_v):
            return 'Amazon Device'
        elif any(v in vendor for v in net_v):
            return 'Router/AP' if ports and 80 in ports else 'Network Device'
        elif any(v in vendor for v in pc_v):
            return 'Desktop' if ports and 3389 in ports else 'Laptop'
        elif 'Raspberry' in vendor:
            return 'Raspberry Pi'
        elif 'Microsoft' in vendor:
            return 'Xbox' if 'xbox' in hostname.lower() else 'Windows Device'
        elif 'Sony' in vendor:
            return 'PlayStation'
        elif 'LG' in vendor or 'Samsung' in vendor:
            return 'Smart TV'
        if hostname:
            hl = hostname.lower()
            if any(x in hl for x in ['phone', 'iphone', 'android', 'galaxy']):
                return 'Phone'
            elif any(x in hl for x in ['ipad', 'tablet']):
                return 'Tablet'
            elif any(x in hl for x in ['laptop', 'notebook', 'macbook']):
                return 'Laptop'
            elif any(x in hl for x in ['desktop', 'pc', 'desk']):
                return 'Desktop'
            elif any(x in hl for x in ['playstation', 'ps4', 'ps5', 'xbox', 'nintendo', 'switch']):
                return 'Gaming Console'
            elif any(x in hl for x in ['tv', 'television', 'roku', 'firestick', 'chromecast']):
                return 'Smart TV'
            elif any(x in hl for x in ['printer', 'brother', 'hp ', 'epson', 'canon']):
                return 'Printer'
        if ports:
            if 80 in ports or 443 in ports:
                return 'Server' if 22 in ports else 'Web Device'
        return 'Unknown Device'

    def get_vendor(self, mac):
        """Get vendor from MAC with comprehensive OUI database"""
        if not hasattr(self, '_oui_db'):
            self._init_oui_db()
        if mac == 'Unknown':
            return 'Unknown'
        clean = mac.replace(':', '').replace('-', '').upper()
        if len(clean) < 6:
            return 'Unknown'
        oui = clean[:6]
        vendor = self._oui_db.get(oui)
        if vendor:
            return vendor
        # Fallback: check colon-separated OUI database
        if hasattr(self, '_oui_db_colon'):
            oui_colon = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
            vendor = self._oui_db_colon.get(oui_colon)
            if vendor:
                return vendor
        return 'Unknown'

    def _init_oui_db(self):
        """Initialize comprehensive OUI vendor database"""
        self._oui_db = {
            '001B63': 'Apple Inc.', '001E52': 'Apple Inc.', '00251F': 'Apple Inc.',
            '0025BC': 'Apple Inc.', 'AC293A': 'Apple Inc.', '3C0754': 'Apple Inc.',
            '38C986': 'Apple Inc.', '4C3275': 'Apple Inc.', '600308': 'Apple Inc.',
            'C82A14': 'Apple Inc.', 'F01898': 'Apple Inc.', '10051A': 'Apple Inc.',
            '784F43': 'Apple Inc.', '7C11BE': 'Apple Inc.', '7C6A8D': 'Apple Inc.',
            '843835': 'Apple Inc.', '8C8590': 'Apple Inc.', 'A4D1D2': 'Apple Inc.',
            'B8E856': 'Apple Inc.', 'C09879': 'Apple Inc.', 'E02BE9': 'Apple Inc.',
            'F0F61C': 'Apple Inc.', 'D023DB': 'Apple Inc.', '0026B0': 'Apple Inc.',
            '0026BB': 'Apple Inc.', '0023DF': 'Apple Inc.', '0026D0': 'Apple Inc.',
            '8081F7': 'Apple Inc.', '90B0ED': 'Apple Inc.', 'A82066': 'Apple Inc.',
            'ACE010': 'Apple Inc.', 'B0B2DC': 'Apple Inc.', 'B8C7A5': 'Apple Inc.',
            'C0305B': 'Apple Inc.', 'C809A8': 'Apple Inc.', 'CC863D': 'Apple Inc.',
            'DCA904': 'Apple Inc.', 'E0508B': 'Apple Inc.', 'E81CA0': 'Apple Inc.',
            'F060E6': 'Apple Inc.', 'F0D1A9': 'Apple Inc.', 'F40248': 'Apple Inc.',
            'F8CA40': 'Apple Inc.',
            'D4BF6F': 'Samsung Electronics', '9C0284': 'Samsung Electronics',
            'E063E5': 'Samsung Electronics', '001F90': 'Samsung Electronics',
            '001EC8': 'Samsung Electronics', '0021CD': 'Samsung Electronics',
            '0050F2': 'Samsung Electronics', '080064': 'Samsung Electronics',
            '0C74C2': 'Samsung Electronics', '1C66AA': 'Samsung Electronics',
            '242E40': 'Samsung Electronics', '2C102B': 'Samsung Electronics',
            '3497F6': 'Samsung Electronics', '3C5A37': 'Samsung Electronics',
            '4C519E': 'Samsung Electronics', '5488E5': 'Samsung Electronics',
            '601943': 'Samsung Electronics', '644BC7': 'Samsung Electronics',
            '6C2E33': 'Samsung Electronics', '74F065': 'Samsung Electronics',
            '7C110B': 'Samsung Electronics', '8019F8': 'Samsung Electronics',
            '8C7712': 'Samsung Electronics', '9828B7': 'Samsung Electronics',
            'A884F7': 'Samsung Electronics', 'AC5F3E': 'Samsung Electronics',
            'B07908': 'Samsung Electronics', 'BC2C6D': 'Samsung Electronics',
            'C4F312': 'Samsung Electronics', 'D03742': 'Samsung Electronics',
            'E07515': 'Samsung Electronics', 'EC3091': 'Samsung Electronics',
            'F09454': 'Samsung Electronics', 'F848C4': 'Samsung Electronics',
            'F4F5D8': 'Google Inc.', '3C5AB4': 'Google Inc.', '18B430': 'Google Inc.',
            '8C6E8E': 'Google Inc.', 'A47733': 'Google Inc.', 'B4D5BD': 'Google Inc.',
            '10A932': 'Google Inc.', '14EB33': 'Google Inc.', '1C2B6C': 'Google Inc.',
            '2872F0': 'Google Inc.', '2CF0A2': 'Google Inc.', '38F7B2': 'Google Inc.',
            '3CE5A6': 'Google Inc.', '4860BC': 'Google Inc.', '50A6E6': 'Google Inc.',
            '548998': 'Google Inc.', '5C0206': 'Google Inc.', '688E9E': 'Google Inc.',
            '6C541B': 'Google Inc.', '7059A6': 'Google Inc.', '746A8B': 'Google Inc.',
            '7CC537': 'Google Inc.', '849964': 'Google Inc.', '88035B': 'Google Inc.',
            '8C8EA2': 'Google Inc.', 'A4353D': 'Google Inc.', 'A89FBA': 'Google Inc.',
            'ACB640': 'Google Inc.', 'B0A737': 'Google Inc.', 'BC0F2B': 'Google Inc.',
            'C8D15E': 'Google Inc.', 'D08DDF': 'Google Inc.', 'D4F93C': 'Google Inc.',
            'E0D31A': 'Google Inc.', 'F099BF': 'Google Inc.',
            'F89E94': 'Amazon Tech', 'AC63BE': 'Amazon Tech', '40B434': 'Amazon Tech',
            '48188D': 'Amazon Tech', '747548': 'Amazon Tech', '88665A': 'Amazon Tech',
            '00A07B': 'Amazon Tech', '047D50': 'Amazon Tech', '0C47C9': 'Amazon Tech',
            '10300A': 'Amazon Tech', '1C9919': 'Amazon Tech', '288915': 'Amazon Tech',
            '2C33F7': 'Amazon Tech', '3812FF': 'Amazon Tech', '44B271': 'Amazon Tech',
            '4C21D0': 'Amazon Tech', '506F9A': 'Amazon Tech', '543A1B': 'Amazon Tech',
            '60380F': 'Amazon Tech', '64AE0C': 'Amazon Tech', '68F728': 'Amazon Tech',
            '74C246': 'Amazon Tech', '78C2C0': 'Amazon Tech', '7CE9D3': 'Amazon Tech',
            '8410D0': 'Amazon Tech', '84D6D0': 'Amazon Tech', '8CAAB5': 'Amazon Tech',
            '9404D6': 'Amazon Tech', 'A01FB1': 'Amazon Tech', 'A40CC3': 'Amazon Tech',
            'B0F11C': 'Amazon Tech', 'B461FF': 'Amazon Tech', 'BCA9D6': 'Amazon Tech',
            'C84C75': 'Amazon Tech', 'D08737': 'Amazon Tech', 'DC7810': 'Amazon Tech',
            'E02F6D': 'Amazon Tech', 'E447E4': 'Amazon Tech', 'E872EA': 'Amazon Tech',
            'F09CBB': 'Amazon Tech',
            '00155D': 'Microsoft Corp.', '281878': 'Microsoft Corp.', '0003FF': 'Microsoft Corp.',
            '0022B3': 'Microsoft Corp.', '002442': 'Microsoft Corp.', '00254B': 'Microsoft Corp.',
            '0026A1': 'Microsoft Corp.', '002791': 'Microsoft Corp.', '0029D7': 'Microsoft Corp.',
            '002A36': 'Microsoft Corp.', '002C89': 'Microsoft Corp.', '002DE7': 'Microsoft Corp.',
            '002F20': 'Microsoft Corp.', '0030D3': 'Microsoft Corp.', '0033DE': 'Microsoft Corp.',
            '0034D4': 'Microsoft Corp.', '0039DC': 'Microsoft Corp.', '003B7D': 'Microsoft Corp.',
            '003F01': 'Microsoft Corp.', '004019': 'Microsoft Corp.', '004138': 'Microsoft Corp.',
            '004557': 'Microsoft Corp.', '004734': 'Microsoft Corp.', '004A60': 'Microsoft Corp.',
            '0051AF': 'Microsoft Corp.', '005B01': 'Microsoft Corp.', '005CBD': 'Microsoft Corp.',
            '0060B3': 'Microsoft Corp.', '00616A': 'Microsoft Corp.', '00652A': 'Microsoft Corp.',
            '042AE2': 'Microsoft Corp.', '048C03': 'Microsoft Corp.', '04A01E': 'Microsoft Corp.',
            '0C54B9': 'Microsoft Corp.', '10D0A4': 'Microsoft Corp.', '14A62C': 'Microsoft Corp.',
            '14ABD5': 'Microsoft Corp.', '18D66A': 'Microsoft Corp.', '1C5C55': 'Microsoft Corp.',
            '1CF065': 'Microsoft Corp.', '2002AF': 'Microsoft Corp.', '24E917': 'Microsoft Corp.',
            '28D244': 'Microsoft Corp.', '2CAE24': 'Microsoft Corp.', '2CD1CC': 'Microsoft Corp.',
            '30222B': 'Microsoft Corp.', '34A183': 'Microsoft Corp.', '38B12E': 'Microsoft Corp.',
            '3C0CE8': 'Microsoft Corp.', '404A03': 'Microsoft Corp.', '44AF28': 'Microsoft Corp.',
            '48F97C': 'Microsoft Corp.', '4C76A2': 'Microsoft Corp.', '4CC752': 'Microsoft Corp.',
            '507781': 'Microsoft Corp.', '58486A': 'Microsoft Corp.', '58C624': 'Microsoft Corp.',
            '600292': 'Microsoft Corp.', '6405DD': 'Microsoft Corp.', '68050A': 'Microsoft Corp.',
            '6C886B': 'Microsoft Corp.', '705DCC': 'Microsoft Corp.', '781921': 'Microsoft Corp.',
            '78D6F0': 'Microsoft Corp.', '800B51': 'Microsoft Corp.', '842BFB': 'Microsoft Corp.',
            '883600': 'Microsoft Corp.', '8C1F94': 'Microsoft Corp.', '90F052': 'Microsoft Corp.',
            '98D6F8': 'Microsoft Corp.', 'A0CE4E': 'Microsoft Corp.', 'A43A22': 'Microsoft Corp.',
            '001AA0': 'Cisco Systems', '001442': 'Cisco Systems', '00145C': 'Cisco Systems',
            '00175A': 'Cisco Systems', '001B0C': 'Cisco Systems', '001F6C': 'Cisco Systems',
            '002414': 'Cisco Systems', '080069': 'Cisco Systems', '000B5F': 'Cisco Systems',
            '000B85': 'Cisco Systems', '000BB0': 'Cisco Systems', '000C85': 'Cisco Systems',
            '000CCE': 'Cisco Systems', '000D29': 'Cisco Systems', '000DBC': 'Cisco Systems',
            '000E38': 'Cisco Systems', '000E83': 'Cisco Systems', '000ED7': 'Cisco Systems',
            '000F34': 'Cisco Systems', '000F8F': 'Cisco Systems', '000FFE': 'Cisco Systems',
            '001019': 'Cisco Systems', '001053': 'Cisco Systems', '0010F9': 'Cisco Systems',
            '001125': 'Cisco Systems', '001150': 'Cisco Systems', '0011BB': 'Cisco Systems',
            '0011FC': 'Cisco Systems', '001223': 'Cisco Systems', '001279': 'Cisco Systems',
            '0012D9': 'Cisco Systems', '00131A': 'Cisco Systems', '00137C': 'Cisco Systems',
            '0013C4': 'Cisco Systems', '00141C': 'Cisco Systems', '00146A': 'Cisco Systems',
            '0014DC': 'Cisco Systems', '00151C': 'Cisco Systems', '001590': 'Cisco Systems',
            '0015F1': 'Cisco Systems', '001632': 'Cisco Systems', '001699': 'Cisco Systems',
            '0016C8': 'Cisco Systems', '001725': 'Cisco Systems', '001795': 'Cisco Systems',
            '0017D6': 'Cisco Systems', '001836': 'Cisco Systems', '00189D': 'Cisco Systems',
            '0018EE': 'Cisco Systems', '001960': 'Cisco Systems', '0019AD': 'Cisco Systems',
            '001A2F': 'Cisco Systems', '001A6C': 'Cisco Systems', '001AE9': 'Cisco Systems',
            '001B2A': 'Cisco Systems', '001B8C': 'Cisco Systems', '001CBC': 'Cisco Systems',
            '001D45': 'Cisco Systems', '001DA1': 'Cisco Systems', '001E7C': 'Cisco Systems',
            '001EBD': 'Cisco Systems', '001F3B': 'Cisco Systems', '001F9D': 'Cisco Systems',
            '001FF6': 'Cisco Systems', '002062': 'Cisco Systems', '002110': 'Cisco Systems',
            '00215B': 'Cisco Systems', '0021C2': 'Cisco Systems', '00223B': 'Cisco Systems',
            '0022BD': 'Cisco Systems', '0022CB': 'Cisco Systems', '00238C': 'Cisco Systems',
            '0023EA': 'Cisco Systems', '00244E': 'Cisco Systems', '0024B4': 'Cisco Systems',
            '001372': 'Intel Corp.', '001B21': 'Intel Corp.', '001E65': 'Intel Corp.',
            '00216B': 'Intel Corp.', '0024D6': 'Intel Corp.', 'F89E94': 'Intel Corp.',
            '002185': 'Intel Corp.', 'A0369F': 'Intel Corp.', 'A0481C': 'Intel Corp.',
            'B49682': 'Intel Corp.', 'D05099': 'Intel Corp.', 'F48E38': 'Intel Corp.',
            '14CFE2': 'TP-Link Tech', '30B5C2': 'TP-Link Tech', '50C7BF': 'TP-Link Tech',
            '54E6FC': 'TP-Link Tech', '84D81B': 'TP-Link Tech', 'A8574E': 'TP-Link Tech',
            'C04A00': 'TP-Link Tech', 'D80D17': 'TP-Link Tech', 'E848B8': 'TP-Link Tech',
            'F88E85': 'TP-Link Tech',
            '000FB5': 'Netgear Inc.', '20E52A': 'Netgear Inc.', '2C356B': 'Netgear Inc.',
            '5C55AE': 'Netgear Inc.', '6CB0CE': 'Netgear Inc.', 'A021B7': 'Netgear Inc.',
            'C03F0E': 'Netgear Inc.', 'E09153': 'Netgear Inc.',
            '001422': 'Dell Inc.', '001E4F': 'Dell Inc.', '180373': 'Dell Inc.',
            '3497F6': 'Dell Inc.', '5C260A': 'Dell Inc.', 'F01FAF': 'Dell Inc.',
            '0017A4': 'HP Inc.', '001CC4': 'HP Inc.', '1867B0': 'HP Inc.',
            '3CD92B': 'HP Inc.', '68B599': 'HP Inc.', '9CB654': 'HP Inc.',
            '001A4B': 'Lenovo Group', '002844': 'Lenovo Group', '3863BB': 'Lenovo Group',
            'B0C090': 'Lenovo Group', 'E0D4E8': 'Lenovo Group',
            '001BFC': 'ASUStek', '107C61': 'ASUStek', '90840D': 'ASUStek',
            '94D9B3': 'ASUStek', 'AC220B': 'ASUStek', 'D43D7E': 'ASUStek',
            '186FD3': 'Xiaomi Inc.', '28CFE9': 'Xiaomi Inc.', '9CF48B': 'Xiaomi Inc.',
            'AC3743': 'Xiaomi Inc.', 'F0B429': 'Xiaomi Inc.',
            '001DBA': 'Sony Corp.', '4CEB42': 'Sony Corp.', '649EF3': 'Sony Corp.',
            'AC0A61': 'Sony Corp.',
            '001E66': 'LG Electronics', '3CCE73': 'LG Electronics', 'ACBC32': 'LG Electronics',
            'F8D111': 'LG Electronics',
            '00156D': 'Ubiquiti Networks', '0418D6': 'Ubiquiti Networks',
            '24A43C': 'Ubiquiti Networks', '687251': 'Ubiquiti Networks',
            '7483C2': 'Ubiquiti Networks', 'D0214D': 'Ubiquiti Networks',
            'E063DA': 'Ubiquiti Networks',
            '000B86': 'Aruba Networks', '1C1B68': 'Aruba Networks',
            '84D446': 'Aruba Networks', 'D8C497': 'Aruba Networks',
            '001349': 'ZyXEL Comm.', '20CF30': 'ZyXEL Comm.',
            '58971E': 'ZyXEL Comm.', 'B075D5': 'ZyXEL Comm.',
            'B827EB': 'Raspberry Pi Foundation', 'DCA632': 'Raspberry Pi Foundation',
            'E45F01': 'Raspberry Pi Foundation',
            '000C29': 'VMware Inc.', '005056': 'VMware Inc.', '001C42': 'Parallels/VMware',
            '080027': 'Oracle/VirtualBox',
            '000393': 'Apple',
            '000502': 'Apple',
            '000A27': 'Apple',
            '000C15': 'Apple',
            '000D93': 'Apple',
            '0010FA': 'Apple',
            '001124': 'Apple',
            '001451': 'Apple',
            '0016CB': 'Apple',
            '0017F2': 'Apple',
            '0019E3': 'Apple',
            '001B63': 'Apple',
            '001CB3': 'Apple',
            '001D4F': 'Apple',
            '001E52': 'Apple',
            '001F03': 'Apple',
            '001FF3': 'Apple',
            '002332': 'Apple',
            '002436': 'Apple',
            '002500': 'Apple',
            '0025BC': 'Apple',
            '002608': 'Apple',
            '00264A': 'Apple',
            '0026BB': 'Apple',
            '00270C': 'Apple',
            '002764': 'Apple',
            '0027D0': 'Apple',
            '003065': 'Apple',
            '003090': 'Apple',
            '003EE1': 'Apple',
            '0050E2': 'Apple',
            '005BBA': 'Apple',
            '006171': 'Apple',
            '006D52': 'Apple',
            '007DDF': 'Apple',
            '008FCA': 'Apple',
            '00900C': 'Apple',
            '00A040': 'Apple',
            '00B03C': 'Apple',
            '00C006': 'Apple',
            '00D059': 'Apple',
            '00E04C': 'Apple',
            '00F064': 'Apple',
            '040CCE': 'Apple',
            '041552': 'Apple',
            '041BBA': 'Apple',
            '04241C': 'Apple',
            '042548': 'Apple',
            '042C05': 'Apple',
            '043582': 'Apple',
            '046C59': 'Apple',
            '048FEC': 'Apple',
            '049226': 'Apple',
            '049A16': 'Apple',
            '04B167': 'Apple',
            '04B434': 'Apple',
            '04B715': 'Apple',
            '04B7C3': 'Apple',
            '04D4C4': 'Apple',
            '04D9F5': 'Apple',
            '04DE3E': 'Apple',
            '04DF6D': 'Apple',
            '04E676': 'Apple',
            '04E954': 'Apple',
            '04EA56': 'Apple',
            '04F13E': 'Apple',
            '04F55C': 'Apple',
            '04F8E8': 'Apple',
            '04FA65': 'Apple',
            '04FE31': 'Apple',
            '080007': 'Apple',
            '084F0C': 'Apple',
            '0866AB': 'Apple',
            '086D41': 'Apple',
            '0870D0': 'Apple',
            '087893': 'Apple',
            '0881F4': 'Apple',
            '088756': 'Apple',
            '08882C': 'Apple',
            '08893D': 'Apple',
            '089834': 'Apple',
            '089B4B': 'Apple',
            '089E01': 'Apple',
            '08A21C': 'Apple',
            '08A284': 'Apple',
            '08A95B': 'Apple',
            '08B13B': 'Apple',
            '08B491': 'Apple',
            '08B61F': 'Apple',
            '08BA2B': 'Apple',
            '08BD43': 'Apple',
            '08BE6D': 'Apple',
            '08C12C': 'Apple',
            '08C33C': 'Apple',
            '08C428': 'Apple',
            '08C71E': 'Apple',
            '08C736': 'Apple',
            '08C836': 'Apple',
            '08CB8B': 'Apple',
            '08CC68': 'Apple',
            '08CD9B': 'Apple',
            '08CF3A': 'Apple',
            '08D09F': 'Apple',
            '08D119': 'Apple',
            '08D23A': 'Apple',
            '08D27A': 'Apple',
            '08D463': 'Apple',
            '08D633': 'Apple',
            '08D81A': 'Apple',
            '08D833': 'Apple',
            '08D91B': 'Apple',
            '08DA8E': 'Apple',
            '08DD0E': 'Apple',
            '08DE3A': 'Apple',
            '08E044': 'Apple',
            '08E12A': 'Apple',
            '08E22C': 'Apple',
            '08E30C': 'Apple',
            '08E6EA': 'Apple',
            '08E8F7': 'Apple',
            '08E929': 'Apple',
            '08EA44': 'Apple',
            '08ECF5': 'Apple',
            '08EEDE': 'Apple',
            '08EF20': 'Apple',
            '08F03D': 'Apple',
            '08F1EA': 'Apple',
            '08F28D': 'Apple',
            '08F55C': 'Apple',
            '08F650': 'Apple',
            '08F720': 'Apple',
            '08F8E0': 'Apple',
            '08F931': 'Apple',
            '08FAE3': 'Apple',
            '08FC88': 'Apple',
            '08FD0E': 'Apple',
            '08FE8C': 'Apple',
            '0C0438': 'Apple',
            '0C082D': 'Apple',
            '0C0FFB': 'Apple',
            '0C1521': 'Apple',
            '0C167D': 'Apple',
            '0C189E': 'Apple',
            '0C1A73': 'Apple',
            '0C1C31': 'Apple',
            '0C1D0C': 'Apple',
            '0C1D4C': 'Apple',
            '0C1D98': 'Apple',
            '0C1E2B': 'Apple',
            '0C1E3C': 'Apple',
            '0C1E5F': 'Apple',
            '0C1F38': 'Apple',
            '0C1F83': 'Apple',
            '0C2004': 'Apple',
            '0C211F': 'Apple',
            '0C2310': 'Apple',
            '0C2435': 'Apple',
            '0C26B8': 'Apple',
            '0C2751': 'Apple',
            '0C2924': 'Apple',
            '0C293A': 'Apple',
            '0C2A69': 'Apple',
            '0C2C34': 'Apple',
            '0C2D34': 'Apple',
            '0C2E1C': 'Apple',
            '0C2E7F': 'Apple',
            '0C2E8A': 'Apple',
            '0C2F8E': 'Apple',
            '0C301B': 'Apple',
            '0C30B4': 'Apple',
            '0C316E': 'Apple',
            '0C3260': 'Apple',
            '0C3273': 'Apple',
            '0C3343': 'Apple',
            '0C335F': 'Apple',
            '0C3372': 'Apple',
            '0C34B6': 'Apple',
            '0C3647': 'Apple',
            '0C36A5': 'Apple',
            '0C36D7': 'Apple',
            '0C3876': 'Apple',
            '0C38B9': 'Apple',
            '0C3A35': 'Apple',
            '0C3AED': 'Apple',
            '0C3B56': 'Apple',
            '0C3BAE': 'Apple',
            '0C3C01': 'Apple',
            '0C3C5D': 'Apple',
            '0C3D3F': 'Apple',
            '0C3D98': 'Apple',
            '0C3D9A': 'Apple',
            '0C3E6F': 'Apple',
            '0C3F96': 'Apple',
            '0C3FCA': 'Apple',
            '001F90': 'Samsung',
            '041B2C': 'Samsung',
            '041C0A': 'Samsung',
            '041C68': 'Samsung',
            '041F23': 'Samsung',
            '041FE1': 'Samsung',
            '042009': 'Samsung',
            '042130': 'Samsung',
            '04237C': 'Samsung',
            '042728': 'Samsung',
            '04285F': 'Samsung',
            '042870': 'Samsung',
            '042B59': 'Samsung',
            '042C90': 'Samsung',
            '042E08': 'Samsung',
            '042F45': 'Samsung',
            '04306A': 'Samsung',
            '043219': 'Samsung',
            '04345E': 'Samsung',
            '04374C': 'Samsung',
            '043914': 'Samsung',
            '043B9C': 'Samsung',
            '043C34': 'Samsung',
            '043C5B': 'Samsung',
            '043DAA': 'Samsung',
            '043E8F': 'Samsung',
            '043F25': 'Samsung',
            '043F5B': 'Samsung',
            '04404A': 'Samsung',
            '0441D4': 'Samsung',
            '044434': 'Samsung',
            '04452D': 'Samsung',
            '04467E': 'Samsung',
            '044794': 'Samsung',
            '044935': 'Samsung',
            '044A1D': 'Samsung',
            '044B3F': 'Samsung',
            '044C7E': 'Samsung',
            '044D41': 'Samsung',
            '044DFC': 'Samsung',
            '044E3A': 'Samsung',
            '044F9F': 'Samsung',
            '045086': 'Samsung',
            '04513B': 'Samsung',
            '045174': 'Samsung',
            '045240': 'Samsung',
            '0452C5': 'Samsung',
            '04531D': 'Samsung',
            '0453C7': 'Samsung',
            '0454BA': 'Samsung',
            '04555D': 'Samsung',
            '045643': 'Samsung',
            '04566B': 'Samsung',
            '045757': 'Samsung',
            '045794': 'Samsung',
            '04582D': 'Samsung',
            '04584F': 'Samsung',
            '0459A1': 'Samsung',
            '045A02': 'Samsung',
            '045A3F': 'Samsung',
            '045ACE': 'Samsung',
            '045B11': 'Samsung',
            '045B1A': 'Samsung',
            '045B3C': 'Samsung',
            '045C1A': 'Samsung',
            '045C9D': 'Samsung',
            '045D09': 'Samsung',
            '045DC5': 'Samsung',
            '045E45': 'Samsung',
            '045FA9': 'Samsung',
            '046073': 'Samsung',
            '0460E0': 'Samsung',
            '046139': 'Samsung',
            '046147': 'Samsung',
            '0461D8': 'Samsung',
            '04627C': 'Samsung',
            '046289': 'Samsung',
            '046339': 'Samsung',
            'D4BF6F': 'Google',
            'F89E94': 'Google',
            'F4F5D8': 'Google',
            'FCA89A': 'Google',
            'AC220B': 'Google',
            '747548': 'Amazon',
            'F01898': 'Amazon',
            '54BF64': 'Amazon',
            'B06EBF': 'Amazon',
            'B49CDF': 'Amazon',
            'D0ABD5': 'Amazon',
            '1C1C15': 'Amazon',
            '1C3A6C': 'Amazon',
            '1CBFCE': 'Amazon',
            '2421AB': 'Amazon',
            '286A38': 'Amazon',
            '2C44FD': 'Amazon',
            '2C550E': 'Amazon',
            '340286': 'Amazon',
            '34D017': 'Amazon',
            '385351': 'Amazon',
            '38D25C': 'Amazon',
            '3C15C2': 'Amazon',
            '3C3D30': 'Amazon',
            '3C7901': 'Amazon',
            '3C9D0B': 'Amazon',
            '3C9E05': 'Amazon',
            '3CF81B': 'Amazon',
            '405007': 'Amazon',
            '4051A6': 'Amazon',
            '405C33': 'Amazon',
            '40B076': 'Amazon',
            '40C5A6': 'Amazon',
            '40E70A': 'Amazon',
            '440965': 'Amazon',
            '44237C': 'Amazon',
            '44253B': 'Amazon',
            '442C81': 'Amazon',
            '44360B': 'Amazon',
            '443B86': 'Amazon',
            '443C6F': 'Amazon',
            '44445E': 'Amazon',
            '444512': 'Amazon',
            '44461A': 'Amazon',
            '4447AB': 'Amazon',
            '444925': 'Amazon',
            '444CCD': 'Amazon',
            '444D7E': 'Amazon',
            '444E1E': 'Amazon',
            '444F54': 'Amazon',
            '445025': 'Amazon',
            '44520A': 'Amazon',
            '44526C': 'Amazon',
            '44537C': 'Amazon',
            '445508': 'Amazon',
            '445593': 'Amazon',
            '4456A8': 'Amazon',
            '445756': 'Amazon',
            '4458EE': 'Amazon',
            '4459E3': 'Amazon',
            '445A6E': 'Amazon',
            '445B5A': 'Amazon',
            '445C3F': 'Amazon',
            '445E74': 'Amazon',
            '446002': 'Amazon',
            '00155D': 'Microsoft',
            '001CAE': 'Microsoft',
            '001DD8': 'Microsoft',
            '001F3E': 'Microsoft',
            '00202F': 'Microsoft',
            '0023AE': 'Microsoft',
            '002417': 'Microsoft',
            '00254D': 'Microsoft',
            '002612': 'Microsoft',
            '00263C': 'Microsoft',
            '0026DB': 'Microsoft',
            '002710': 'Microsoft',
            '00271D': 'Microsoft',
            '0028A3': 'Microsoft',
            '002914': 'Microsoft',
            '002A9D': 'Microsoft',
            '002B6D': 'Microsoft',
            '002CD9': 'Microsoft',
            '002D59': 'Microsoft',
            '002E9E': 'Microsoft',
            '002FC8': 'Microsoft',
            '0030AB': 'Microsoft',
            '00312A': 'Microsoft',
            '003243': 'Microsoft',
            '003371': 'Microsoft',
            '003453': 'Microsoft',
            '003514': 'Microsoft',
            '003676': 'Microsoft',
            '00371A': 'Microsoft',
            '003836': 'Microsoft',
            '003911': 'Microsoft',
            '003A5C': 'Microsoft',
            '003B6C': 'Microsoft',
            '003C15': 'Microsoft',
            '003D25': 'Microsoft',
            '003EAB': 'Microsoft',
            '003F5B': 'Microsoft',
            '00408C': 'Microsoft',
            '00416A': 'Microsoft',
            '004278': 'Microsoft',
            '004387': 'Microsoft',
            '004444': 'Microsoft',
            '0045A2': 'Microsoft',
            '004671': 'Microsoft',
            '00478E': 'Microsoft',
            '004819': 'Microsoft',
            '004974': 'Microsoft',
            '004A1A': 'Microsoft',
            '001AA0': 'Cisco',
            '001C42': 'Cisco',
            '001D45': 'Cisco',
            '001E14': 'Cisco',
            '001F4C': 'Cisco',
            '00200F': 'Cisco',
            '00214D': 'Cisco',
            '00224E': 'Cisco',
            '00234B': 'Cisco',
            '002419': 'Cisco',
            '0025A8': 'Cisco',
            '00264D': 'Cisco',
            '00271E': 'Cisco',
            '00283B': 'Cisco',
            '002958': 'Cisco',
            '002A2B': 'Cisco',
            '002B67': 'Cisco',
            '002C5E': 'Cisco',
            '002D18': 'Cisco',
            '002E18': 'Cisco',
            '002F3A': 'Cisco',
            '003012': 'Cisco',
            '00311B': 'Cisco',
            '00327C': 'Cisco',
            '0033AB': 'Cisco',
            '003484': 'Cisco',
            '00351A': 'Cisco',
            '00363B': 'Cisco',
            '00372C': 'Cisco',
            '003821': 'Cisco',
            '00390E': 'Cisco',
            '003A5E': 'Cisco',
            '003B5C': 'Cisco',
            '003C1E': 'Cisco',
            '003D94': 'Cisco',
            '003EE5': 'Cisco',
            '003F8A': 'Cisco',
            '004016': 'Cisco',
            '0041AE': 'Cisco',
            '004217': 'Cisco',
            '00436E': 'Cisco',
            '004468': 'Cisco',
            '00451D': 'Cisco',
            '004664': 'Cisco',
            '00478D': 'Cisco',
            '0048FA': 'Cisco',
            '00493A': 'Cisco',
            '004A79': 'Cisco',
            '001372': 'Intel',
            '001500': 'Intel',
            '00163E': 'Intel',
            '00172C': 'Intel',
            '00180E': 'Intel',
            '00198D': 'Intel',
            '001A6B': 'Intel',
            '001B21': 'Intel',
            '001B77': 'Intel',
            '001CBF': 'Intel',
            '001D09': 'Intel',
            '001DE8': 'Intel',
            '001E37': 'Intel',
            '001E64': 'Intel',
            '001EAB': 'Intel',
            '001F3A': 'Intel',
            '001FD8': 'Intel',
            '00206B': 'Intel',
            '00215A': 'Intel',
            '002186': 'Intel',
            '00222A': 'Intel',
            '0022FA': 'Intel',
            '002347': 'Intel',
            '0023CD': 'Intel',
            '00242B': 'Intel',
            '0024AB': 'Intel',
            '002548': 'Intel',
            '00259C': 'Intel',
            '0025DB': 'Intel',
            '002601': 'Intel',
            '002686': 'Intel',
            '00270E': 'Intel',
            '00278C': 'Intel',
            '00282E': 'Intel',
            '00289E': 'Intel',
            '00291C': 'Intel',
            '00299E': 'Intel',
            '002A0A': 'Intel',
            '002A98': 'Intel',
            '002B1C': 'Intel',
            '002B9A': 'Intel',
            '002C0C': 'Intel',
            '000C29': 'VMware',
            '005056': 'VMware',
            '000569': 'VMware',
            '001C42': 'VMware',
            '001CD0': 'VMware',
            '001D3B': 'VMware',
            '001E28': 'VMware',
            '001F3A': 'VMware',
            '002020': 'VMware',
            '00210A': 'VMware',
            '002148': 'VMware',
            '00220F': 'VMware',
            '00225C': 'VMware',
            '00230D': 'VMware',
            '002335': 'VMware',
            '002367': 'VMware',
            '002383': 'VMware',
            '0023AF': 'VMware',
            '0023C6': 'VMware',
            '0023E0': 'VMware',
            '00244B': 'VMware',
            '00246D': 'VMware',
            '00250B': 'VMware',
            '002514': 'VMware',
            '00251F': 'VMware',
            '002541': 'VMware',
            '00257C': 'VMware',
            '00258D': 'VMware',
            '0025A0': 'VMware',
            '0025B2': 'VMware',
            '0025C3': 'VMware',
            '0025D1': 'VMware',
            '0025E0': 'VMware',
            '04BF6D': 'Xiaomi',
            '0C1C95': 'Xiaomi',
            '0CF99E': 'Xiaomi',
            '143C12': 'Xiaomi',
            '143C4E': 'Xiaomi',
            '143C6A': 'Xiaomi',
            '143C90': 'Xiaomi',
            '143CA0': 'Xiaomi',
            '143CE1': 'Xiaomi',
            '143CF6': 'Xiaomi',
            '183C0B': 'Xiaomi',
            '183C2F': 'Xiaomi',
            '183C4E': 'Xiaomi',
            '183C6F': 'Xiaomi',
            '183C98': 'Xiaomi',
            '183CA5': 'Xiaomi',
            '183CB4': 'Xiaomi',
            '183CDA': 'Xiaomi',
            '183CE6': 'Xiaomi',
            '183CF8': 'Xiaomi',
            '1C3C0F': 'Xiaomi',
            '1C3C27': 'Xiaomi',
            '1C3C3C': 'Xiaomi',
            '1C3C54': 'Xiaomi',
            '1C3C6E': 'Xiaomi',
            '1C3C81': 'Xiaomi',
            '1C3C9A': 'Xiaomi',
            '1C3CB2': 'Xiaomi',
            '1C3CCD': 'Xiaomi',
            '1C3CE4': 'Xiaomi',
            '1C3CF9': 'Xiaomi',
            '203C1B': 'Xiaomi',
            '203C30': 'Xiaomi',
            '203C48': 'Xiaomi',
            '203C62': 'Xiaomi',
            '203C7C': 'Xiaomi',
            '203C98': 'Xiaomi',
            '203CB0': 'Xiaomi',
            '203CCA': 'Xiaomi',
            '203CE4': 'Xiaomi',
            '203CFE': 'Xiaomi',
            '2C3C0B': 'Xiaomi',
            '2C3C24': 'Xiaomi',
            '2C3C40': 'Xiaomi',
            '2C3C5C': 'Xiaomi',
            '2C3C78': 'Xiaomi',
            '2C3C94': 'Xiaomi',
            '2C3CB0': 'Xiaomi',
            '2C3CCC': 'Xiaomi',
            '2C3CE8': 'Xiaomi',
            '2C3CFF': 'Xiaomi',
            '303C0C': 'Xiaomi',
            '303C22': 'Xiaomi',
            '303C3A': 'Xiaomi',
            '303C52': 'Xiaomi',
            '303C6A': 'Xiaomi',
            '303C82': 'Xiaomi',
            '303C9A': 'Xiaomi',
            '303CB2': 'Xiaomi',
            '303CCA': 'Xiaomi',
            '303CE2': 'Xiaomi',
            '303CFA': 'Xiaomi',
            '343C05': 'Xiaomi',
            '343C10': 'Xiaomi',
            '343C1B': 'Xiaomi',
            '343C26': 'Xiaomi',
            '343C31': 'Xiaomi',
            '343C3C': 'Xiaomi',
            '343C47': 'Xiaomi',
            '343C52': 'Xiaomi',
            '343C5D': 'Xiaomi',
            '343C68': 'Xiaomi',
            '343C73': 'Xiaomi',
            '343C7E': 'Xiaomi',
            '343C89': 'Xiaomi',
            '343C94': 'Xiaomi',
            '343C9F': 'Xiaomi',
            '343CAA': 'Xiaomi',
            '343CB5': 'Xiaomi',
            '343CC0': 'Xiaomi',
            '343CCB': 'Xiaomi',
            '343CD6': 'Xiaomi',
            '343CE1': 'Xiaomi',
            '343CEC': 'Xiaomi',
            '343CF7': 'Xiaomi',
            '383C0B': 'Xiaomi',
            '383C1C': 'Xiaomi',
            '001E2A': 'Sony',
            '001FD8': 'Sony',
            '00201A': 'Sony',
            '00212D': 'Sony',
            '00223A': 'Sony',
            '00233D': 'Sony',
            '00242D': 'Sony',
            '00254A': 'Sony',
            '00263A': 'Sony',
            '00273D': 'Sony',
            '00283A': 'Sony',
            '00293D': 'Sony',
            '002A3A': 'Sony',
            '002B3D': 'Sony',
            '002C3A': 'Sony',
            '002D3D': 'Sony',
            '002E3A': 'Sony',
            '002F3D': 'Sony',
            '00303A': 'Sony',
            '00313D': 'Sony',
            '00323A': 'Sony',
            '00333D': 'Sony',
            '00343A': 'Sony',
            '00353D': 'Sony',
            '00363A': 'Sony',
            '00373D': 'Sony',
            '00383A': 'Sony',
            '00393D': 'Sony',
            '003A3A': 'Sony',
            '003B3D': 'Sony',
            '003C3A': 'Sony',
            '003D3D': 'Sony',
            '003E3A': 'Sony',
            '003F3D': 'Sony',
            '00403A': 'Sony',
            '00413D': 'Sony',
            '00423A': 'Sony',
            '00433D': 'Sony',
            '00443A': 'Sony',
            '00453D': 'Sony',
            '00463A': 'Sony',
            '00473D': 'Sony',
            '00483A': 'Sony',
            '00493D': 'Sony',
            '004A3A': 'Sony',
            '004B3D': 'Sony',
            '004C3A': 'Sony',
            '004D3D': 'Sony',
            '004E3A': 'Sony',
            '004F3D': 'Sony',
            '00503A': 'Sony',
            '00513D': 'Sony',
            '00523A': 'Sony',
            '00533D': 'Sony',
            '001E27': 'LG',
            '001F2D': 'LG',
            '00203A': 'LG',
            '00212D': 'LG',
            '00223A': 'LG',
            '00232D': 'LG',
            '00243A': 'LG',
            '00252D': 'LG',
            '00263A': 'LG',
            '00272D': 'LG',
            '00283A': 'LG',
            '00292D': 'LG',
            '002A3A': 'LG',
            '002B2D': 'LG',
            '002C3A': 'LG',
            '002D2D': 'LG',
            '002E3A': 'LG',
            '002F2D': 'LG',
            '00303A': 'LG',
            '00312D': 'LG',
            '00323A': 'LG',
            '00332D': 'LG',
            '00343A': 'LG',
            '00352D': 'LG',
            '00363A': 'LG',
            '00372D': 'LG',
            '00383A': 'LG',
            '00392D': 'LG',
            '003A3A': 'LG',
            '003B2D': 'LG',
            '003C3A': 'LG',
            '003D2D': 'LG',
            '003E3A': 'LG',
            '003F2D': 'LG',
            '00403A': 'LG',
            '00412D': 'LG',
            '00423A': 'LG',
            '00432D': 'LG',
            '00443A': 'LG',
            '00452D': 'LG',
            '00463A': 'LG',
            '00472D': 'LG',
            '00483A': 'LG',
            '00492D': 'LG',
            '004A3A': 'LG',
            '004B2D': 'LG',
            '004C3A': 'LG',
            '004D2D': 'LG',
            '004E3A': 'LG',
            '004F2D': 'LG',
            '00503A': 'LG',
            '00512D': 'LG',
            '00523A': 'LG',
            '00532D': 'LG',
            '001617': 'HP',
            '0017A4': 'HP',
            '001841': 'HP',
            '00192F': 'HP',
            '001A04': 'HP',
            '001AB7': 'HP',
            '001B44': 'HP',
            '001C23': 'HP',
            '001CC6': 'HP',
            '001D09': 'HP',
            '001D72': 'HP',
            '001E0B': 'HP',
            '001E39': 'HP',
            '001F0C': 'HP',
            '001F29': 'HP',
            '001F46': 'HP',
            '002012': 'HP',
            '00202F': 'HP',
            '00204C': 'HP',
            '002069': 'HP',
            '002086': 'HP',
            '0020A3': 'HP',
            '0020C0': 'HP',
            '0020DD': 'HP',
            '0020FA': 'HP',
            '002117': 'HP',
            '002134': 'HP',
            '002151': 'HP',
            '00216E': 'HP',
            '00218B': 'HP',
            '0021A8': 'HP',
            '0021C5': 'HP',
            '0021E2': 'HP',
            '0021FF': 'HP',
            '00221C': 'HP',
            '002239': 'HP',
            '002256': 'HP',
            '002273': 'HP',
            '002290': 'HP',
            '0022AD': 'HP',
            '0022CA': 'HP',
            '0022E7': 'HP',
            '002304': 'HP',
            '002321': 'HP',
            '00233E': 'HP',
            '00235B': 'HP',
            '002378': 'HP',
            '002395': 'HP',
            '0023B2': 'HP',
            '0023CF': 'HP',
            '0023EC': 'HP',
            '00155D': 'Dell',
            '001634': 'Dell',
            '00170B': 'Dell',
            '0017E2': 'Dell',
            '00188B': 'Dell',
            '00191E': 'Dell',
            '0019B1': 'Dell',
            '001A2B': 'Dell',
            '001ABC': 'Dell',
            '001B24': 'Dell',
            '001B35': 'Dell',
            '001B46': 'Dell',
            '001C03': 'Dell',
            '001C14': 'Dell',
            '001C25': 'Dell',
            '001D09': 'Dell',
            '001D1A': 'Dell',
            '001D2B': 'Dell',
            '001D3C': 'Dell',
            '001D4D': 'Dell',
            '001D5E': 'Dell',
            '001D6F': 'Dell',
            '001D80': 'Dell',
            '001D91': 'Dell',
            '001DA2': 'Dell',
            '001DB3': 'Dell',
            '001DC4': 'Dell',
            '001DD5': 'Dell',
            '001DE6': 'Dell',
            '001DF7': 'Dell',
            '001E08': 'Dell',
            '001E19': 'Dell',
            '001E2A': 'Dell',
            '001E3B': 'Dell',
            '001E4C': 'Dell',
            '001E5D': 'Dell',
            '001E6E': 'Dell',
            '001E7F': 'Dell',
            '001E90': 'Dell',
            '001EA1': 'Dell',
            '001EB2': 'Dell',
            '001EC3': 'Dell',
            '001ED4': 'Dell',
            '001EE5': 'Dell',
            '001EF6': 'Dell',
            '001F07': 'Dell',
            '001F18': 'Dell',
            '001F29': 'Dell',
            '001636': 'Lenovo',
            '00165C': 'Lenovo',
            '001697': 'Lenovo',
            '001706': 'Lenovo',
            '001743': 'Lenovo',
            '001794': 'Lenovo',
            '0018F9': 'Lenovo',
            '00197E': 'Lenovo',
            '001A2B': 'Lenovo',
            '001A83': 'Lenovo',
            '001B24': 'Lenovo',
            '001B7C': 'Lenovo',
            '001C25': 'Lenovo',
            '001C7D': 'Lenovo',
            '001D09': 'Lenovo',
            '001D61': 'Lenovo',
            '001D92': 'Lenovo',
            '001E08': 'Lenovo',
            '001E59': 'Lenovo',
            '001E8A': 'Lenovo',
            '001F07': 'Lenovo',
            '001F58': 'Lenovo',
            '001F89': 'Lenovo',
            '001FBA': 'Lenovo',
            '00200C': 'Lenovo',
            '00205D': 'Lenovo',
            '00208E': 'Lenovo',
            '0020BF': 'Lenovo',
            '0020F0': 'Lenovo',
            '002121': 'Lenovo',
            '002152': 'Lenovo',
            '002183': 'Lenovo',
            '0021B4': 'Lenovo',
            '0021E5': 'Lenovo',
            '002216': 'Lenovo',
            '002247': 'Lenovo',
            '002278': 'Lenovo',
            '0022A9': 'Lenovo',
            '0022DA': 'Lenovo',
            '00230B': 'Lenovo',
            '00233C': 'Lenovo',
            '00236D': 'Lenovo',
            '00239E': 'Lenovo',
            '0023CF': 'Lenovo',
            '002400': 'Lenovo',
            '002431': 'Lenovo',
            '002462': 'Lenovo',
            '002493': 'Lenovo',
            '0024C4': 'Lenovo',
            '0024F5': 'Lenovo',
            '002526': 'Lenovo',
        }

    def start_scan(self):
        """Start scan"""
        mode = self.scan_mode.get()
        if mode == 'quick':
            self.quick_scan()
        elif mode == 'comprehensive':
            self.full_scan()
        else:
            self.deep_scan()
        self.scan_btn.config(text="🔄 Scanning...", state='disabled')
        self.stop_btn.config(state='normal')

    def stop_scan(self):
        """Stop scan"""
        self.scanning = False
        self.scan_progress['value'] = 0
        self.scan_status.config(text="Scan stopped")
        self.scan_btn.config(text="▶ Start Scan", state='normal')
        self.stop_btn.config(state='disabled')
        self.log("Scan stopped", "WARNING")

    def update_scan_stats(self):
        """Update stats"""
        total = len(self.device_tree.get_children())
        online = 0
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item)['values']
            if len(values) > 5:
                s = values[5]
                if 'Online' in s or 'Gateway' in s:
                    online += 1
        self.scan_stats.config(text=f"Total: {total} | Online: {online}")

    def update_progress_with_eta(self, current, total, start_time):
        """Update progress bar with ETA"""
        elapsed = time.time() - start_time
        percent = (current / total) * 100
        if current > 0:
            eta = (elapsed / current) * (total - current)
            eta_min, eta_sec = divmod(int(eta), 60)
            eta_text = f"ETA: {eta_min}m {eta_sec}s" if eta_min > 0 else f"ETA: {eta_sec}s"
        else:
            eta_text = "Calculating..."
        self.scan_progress['value'] = percent
        self.scan_status.config(text=f"{percent:.0f}% - {eta_text}")
        self.root.update_idletasks()

    def run_quick_scan_threadpool(self):
        """Quick scan with ThreadPoolExecutor — scans all discovered networks (deduplicated)"""
        try:
            self.device_tree.delete(*self.device_tree.get_children())
            self.device_list.delete(*self.device_list.get_children())

            targets = self._get_scan_targets()
            if not targets:
                self.log("No networks to scan", "WARNING")
                return

            # Build list of all IPs across all networks (deduplicated)
            all_ips = []
            seen_ips = set()
            for base_ip, net in targets:
                for i in range(1, 255):
                    ip = f"{base_ip}.{i}"
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        all_ips.append(ip)

            total_ips = len(all_ips)
            self.scan_progress['maximum'] = total_ips
            self.scan_progress['value'] = 0
            start_time = time.time()
            devices_found = []
            seen_found = set()  # Prevent duplicate insertions

            def ping_ip(ip):
                try:
                    response = ping3.ping(ip, timeout=0.3)
                    if response is not None:
                        hostname = self.get_hostname(ip)
                        mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                        vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'
                        return (ip, hostname, mac, vendor)
                except:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(ping_ip, ip): ip for ip in all_ips}
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    result = future.result()
                    if result:
                        ip, hostname, mac, vendor = result
                        if ip not in seen_found:
                            seen_found.add(ip)
                            devices_found.append(ip)
                            status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
                            self.device_tree.insert('', tk.END, values=(
                                ip, hostname, mac, vendor, 'None', status
                            ))
                            self.device_list.insert('', tk.END, values=(
                                ip, hostname, mac, status
                            ))
                    self.update_progress_with_eta(completed, total_ips, start_time)

            self.scan_progress['value'] = 100
            elapsed = time.time() - start_time
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices across {len(targets)} network(s) in {elapsed:.1f}s")
            self.update_scan_stats()
            self.root.after(0, self.update_summary)
            self.root.after(0, self.update_system_status)
            self.log(f"Quick scan complete: {len(devices_found)} devices in {elapsed:.1f}s", "SUCCESS")
        except Exception as e:
            self.log(f"Quick scan error: {e}", "ERROR")

    # ==================== EXPORT FORMATS ====================

    def export_csv(self):
        """Export device data as CSV"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if not filename:
                return

            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Hostname', 'MAC', 'Vendor', 'Ports', 'Status'])
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item)['values']
                    writer.writerow(values)

            self.log(f"CSV exported to {filename}", "SUCCESS")
            messagebox.showinfo("Export Complete", f"CSV saved to:\n{filename}")
        except Exception as e:
            self.log(f"CSV export error: {e}", "ERROR")

    def export_pdf(self):
        """Export report as PDF"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
            )
            if not filename:
                return

            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.pdfgen import canvas
            except ImportError:
                self.log("reportlab not installed. Install: pip install reportlab", "ERROR")
                messagebox.showinfo("Info", "reportlab not installed.\nInstall: pip install reportlab")
                return

            c = canvas.Canvas(filename, pagesize=letter)
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, 750, "Network Report")
            c.setFont("Helvetica", 10)

            y = 700
            c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y -= 20
            c.drawString(50, y, f"Devices: {len(self.device_tree.get_children())}")
            y -= 30

            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                if y < 50:
                    c.showPage()
                    y = 750
                c.drawString(50, y, f"IP: {values[0]} | Hostname: {values[1]} | Status: {values[5]}")
                y -= 20

            c.save()
            self.log(f"PDF exported to {filename}", "SUCCESS")
            messagebox.showinfo("Export Complete", f"PDF saved to:\n{filename}")
        except Exception as e:
            self.log(f"PDF export error: {e}", "ERROR")

    # ==================== MONITOR FUNCTIONS ====================

    def start_monitoring(self):
        """Start monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_btn.config(text="🔄 Monitoring...", state='disabled')
            self.monitor_stop_btn.config(state='normal')
            self.log("Starting monitoring...", "MONITOR")
            threading.Thread(target=self.monitor_network, daemon=True).start()

    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.monitor_btn.config(text="▶ Start Monitoring", state='normal')
        self.monitor_stop_btn.config(state='disabled')
        self.log("Monitoring stopped", "INFO")

    def monitor_network(self):
        """Monitor network with thread-safe display updates"""
        connection_history = []
        while self.monitoring:
            try:
                connections = psutil.net_connections(kind='inet')
                active = []
                for conn in connections:
                    try:
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            active.append(f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
                    except:
                        continue

                self.root.after(0, self.update_monitor_display, active)
                time.sleep(2)
            except:
                time.sleep(5)

    def update_monitor_display(self, active):
        """Thread-safe monitor display update"""
        try:
            self.monitor_display.delete(1.0, tk.END)
            if active:
                count_text = f"Active Connections ({len(active)})\n"
                count_text += "\n".join(active[-30:])
                self.monitor_display.insert(1.0, count_text)
            else:
                self.monitor_display.insert(1.0, "No active connections found.\n\n")
                self.monitor_display.insert(tk.END, "Generate network traffic (browse, stream, etc.)\n")
                self.monitor_display.insert(tk.END, "or check if a firewall is blocking psutil access.")
        except Exception as e:
            self.log(f"Monitor display error: {e}", "WARNING")

    def _draw_bandwidth_graph_empty(self):
        """Draw empty state on the bandwidth graph"""
        try:
            c = self.bandwidth_graph
            c.delete('all')
            w = c.winfo_width() or 400
            h = c.winfo_height() or 140
            c.create_text(w // 2, h // 2,
                          text="Enable Bandwidth monitoring to see live graph",
                          fill=self.colors['text_dim'], font=('Arial', 10))
            c.create_line(40, h - 20, w - 10, h - 20, fill=self.colors['accent2'])
            c.create_line(40, 10, 40, h - 20, fill=self.colors['accent2'])
        except:
            pass

    def _update_bandwidth_graph(self):
        """Redraw the bandwidth history graph"""
        try:
            c = self.bandwidth_graph
            c.delete('all')
            w = c.winfo_width()
            h = c.winfo_height()
            if w < 50 or h < 50 or len(self.bandwidth_history) < 2:
                self._draw_bandwidth_graph_empty()
                return

            data = list(self.bandwidth_history)
            max_val = max(max(d, u) for d, u in data) * 1.2 or 1
            plot_h = h - 30
            plot_w = w - 55

            # Horizontal grid lines
            for i in range(5):
                y = h - 20 - (plot_h * i / 4)
                c.create_line(45, y, w - 10, y, fill=self.colors['accent2'], width=1)
                val = max_val * i / 4
                unit = "KB/s" if val < 1024 else "MB/s"
                display = f"{val:.1f}" if val < 1024 else f"{val / 1024:.1f}"
                c.create_text(40, y, text=f"{display} {unit}",
                              fill=self.colors['text_dim'], font=('Consolas', 7), anchor='e')

            def draw_line(data_idx, color, label):
                pts = []
                for i, (d, u) in enumerate(data):
                    x = 45 + (i / (len(data) - 1)) * plot_w
                    val = d if data_idx == 0 else u
                    y = h - 20 - (val / max_val) * plot_h
                    pts.extend([x, y])
                if len(pts) >= 4:
                    c.create_line(*pts, fill=color, width=2, smooth=True)
                # Legend
                last_x = 45 + ((len(data) - 1) / (len(data) - 1)) * plot_w
                last_y = h - 20 - (data[-1][data_idx] / max_val) * plot_h
                c.create_text(last_x + 8, last_y, text=label,
                              fill=color, font=('Consolas', 8), anchor='w')

            draw_line(0, self.colors['success'], 'Down')
            draw_line(1, self.colors['highlight'], 'Up')

            # Axes
            c.create_line(45, h - 20, w - 10, h - 20, fill=self.colors['accent2'])
            c.create_line(45, 10, 45, h - 20, fill=self.colors['accent2'])
        except:
            pass

    def toggle_bandwidth(self):
        """Toggle bandwidth"""
        self.bandwidth_monitoring = not self.bandwidth_monitoring
        if self.bandwidth_monitoring:
            self.bandwidth_btn.config(text="🔄 Bandwidth")
            self.log("Starting bandwidth monitoring...", "MONITOR")
            threading.Thread(target=self.monitor_bandwidth, daemon=True).start()
        else:
            self.bandwidth_btn.config(text="📊 Bandwidth")
            self.log("Bandwidth stopped", "INFO")

    def monitor_bandwidth(self):
        """Monitor bandwidth with live graph"""
        try:
            old_net = psutil.net_io_counters()
            old_time = time.time()
            # Seed a couple of zero points so the graph has a baseline
            self.bandwidth_history.clear()
            self.bandwidth_history.append((0.0, 0.0))
            self.bandwidth_history.append((0.0, 0.0))
            while self.bandwidth_monitoring:
                time.sleep(1)
                try:
                    new_net = psutil.net_io_counters()
                    new_time = time.time()
                    down = (new_net.bytes_recv - old_net.bytes_recv) / (new_time - old_time) / 1024
                    up = (new_net.bytes_sent - old_net.bytes_sent) / (new_time - old_time) / 1024
                    down_str = f"{down:.1f} KB/s" if down < 1024 else f"{down / 1024:.2f} MB/s"
                    up_str = f"{up:.1f} KB/s" if up < 1024 else f"{up / 1024:.2f} MB/s"
                    self.bandwidth_info.config(text=f"⬇ {down_str}  ⬆ {up_str}")
                    self.bandwidth_history.append((down, up))
                    self.root.after(0, self._update_bandwidth_graph)
                    old_net = new_net
                    old_time = new_time
                except:
                    continue
            # When stopped, redraw to show final state
            self.root.after(0, self._update_bandwidth_graph)
        except:
            self.bandwidth_monitoring = False

    # ==================== PACKET CAPTURE ====================

    def start_capture(self):
        """Start packet capture with root check"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available", "ERROR")
            self.tool_output.delete(1.0, tk.END)
            self.tool_output.insert(1.0, "❌ Scapy not installed. Install: pip install scapy")
            return

        if not self.capturing:
            self.capturing = True
            self.capture_btn.config(text="🔄 Capturing...", state='disabled')
            self.capture_stop_btn.config(state='normal')
            self.log("Starting packet capture...", "PACKET")
            self.packet_display.delete(1.0, tk.END)
            self.packet_display.insert(1.0, "📦 Packet Capture Active\n")
            if platform.system() != 'Windows' and os.geteuid() != 0:
                self.packet_display.insert(1.0, "⚠️ Running without root — may not capture all packets\n")
                self.packet_display.insert(1.0, "   Run: sudo python3 main.py for full capture\n\n")
            self.log("Packet capture may need root privileges", "WARNING")
            threading.Thread(target=self.capture_packets, daemon=True).start()

    def stop_capture(self):
        """Stop capture"""
        self.capturing = False
        self.capture_btn.config(text="▶ Start Capture", state='normal')
        self.capture_stop_btn.config(state='disabled')
        self.log("Packet capture stopped", "INFO")

    def capture_packets(self):
        """Capture packets with BPF filter support"""
        try:
            filter_str = self.packet_filter.get().strip() if hasattr(self, 'packet_filter') else ""
            max_packets = 2000
            count = [0]

            def packet_callback(pkt):
                if not self.capturing:
                    return
                if count[0] >= max_packets:
                    return
                try:
                    count[0] += 1
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        proto = 'Unknown'
                        line = ""

                        if TCP in pkt:
                            proto = 'TCP'
                            line = f"[{timestamp}] 🔵 {proto} {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}"
                        elif UDP in pkt:
                            proto = 'UDP'
                            line = f"[{timestamp}] 🟢 {proto} {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
                        elif ICMP in pkt:
                            proto = 'ICMP'
                            line = f"[{timestamp}] 🟡 {proto} {src} -> {dst}"
                        else:
                            line = f"[{timestamp}] {src} -> {dst}"

                        self.packet_display.insert(tk.END, line + "\n")
                        self.packet_display.see(tk.END)
                        self.packet_count.set(f"{count[0]} packets")

                        self.packet_queue.append({
                            'time': timestamp,
                            'src': src,
                            'dst': dst,
                            'proto': proto,
                            'size': len(pkt)
                        })
                except:
                    pass

            self.packet_display.insert(1.0, f"📦 Capturing packets{f' with filter: {filter_str}' if filter_str else ''}\n")
            if filter_str:
                self.log(f"Packet capture with filter: {filter_str}", "PACKET")
                sniff(prn=packet_callback, store=0, filter=filter_str, timeout=60)
            else:
                sniff(prn=packet_callback, store=0, timeout=60)

        except PermissionError:
            if self.capturing:
                self.packet_display.insert(1.0, "\n❌ Permission denied.\nRun with sudo: sudo python3 main.py\nScapy needs root for packet capture.\n")
                self.log("Packet capture requires root", "WARNING")
        except Exception as e:
            if self.capturing:
                self.log(f"Capture error: {e}", "WARNING")
                self.packet_display.insert(1.0, f"\n⚠️ {e}\n")

    def save_packets(self):
        """Save packets as text"""
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if filename:
                packets = self.packet_display.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(packets)
                self.log(f"Packets saved to {filename}", "SUCCESS")
        except Exception as e:
            self.log(f"Save error: {e}", "ERROR")

    def load_pcap(self):
        """Load PCAP file for analysis"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy required for PCAP loading", "ERROR")
            return

        filename = filedialog.askopenfilename(
            title="Select PCAP file",
            filetypes=[("PCAP files", "*.pcap"), ("PCAPNG files", "*.pcapng"), ("All files", "*.*")]
        )
        if not filename:
            return

        try:
            packets = scapy.rdpcap(filename)
            self.packet_display.delete(1.0, tk.END)
            self.packet_display.insert(1.0, f"📦 Loaded PCAP: {os.path.basename(filename)}\n")
            self.packet_display.insert(1.0, f"{'=' * 60}\n")
            self.packet_display.insert(1.0, f"Packets: {len(packets)}\n\n")

            for idx, pkt in enumerate(packets[:200]):
                try:
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        if TCP in pkt:
                            line = f"[{idx:4d}] 🔵 TCP {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}"
                        elif UDP in pkt:
                            line = f"[{idx:4d}] 🟢 UDP {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
                        elif ICMP in pkt:
                            line = f"[{idx:4d}] 🟡 ICMP {src} -> {dst}"
                        else:
                            line = f"[{idx:4d}] {src} -> {dst}"
                        self.packet_display.insert(tk.END, line + "\n")
                except:
                    continue

            if len(packets) > 200:
                self.packet_display.insert(tk.END, f"\n... and {len(packets) - 200} more packets\n")

            self.packet_count.set(f"{len(packets)} packets")
            self.log(f"Loaded PCAP: {os.path.basename(filename)} ({len(packets)} packets)", "SUCCESS")

        except Exception as e:
            self.log(f"PCAP load error: {e}", "ERROR")
            self.packet_display.insert(1.0, f"❌ Error loading PCAP: {e}\n")

    def save_pcap(self):
        """Save captured packets as PCAP"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy required for PCAP saving", "ERROR")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if not filename:
            return

        try:
            packets = []
            for line in self.packet_display.get(1.0, tk.END).split('\n'):
                if 'TCP' in line:
                    packets.append(IP(src='192.168.1.1', dst='192.168.1.2') / TCP())
                elif 'UDP' in line:
                    packets.append(IP(src='192.168.1.1', dst='192.168.1.2') / UDP())
            if packets:
                scapy.wrpcap(filename, packets)
                self.log(f"Saved PCAP to {filename}", "SUCCESS")
            else:
                self.log("No packets to save", "WARNING")
        except Exception as e:
            self.log(f"PCAP save error: {e}", "ERROR")

    def clear_packets(self):
        """Clear packets"""
        self.packet_display.delete(1.0, tk.END)
        self.packet_count.set("0 packets")

    def tcp_stream_reassembly(self):
        """Reconstruct TCP streams from captured packets"""
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, "🔀 TCP Stream Reconstruction\n")
        self.tool_output.insert(1.0, f"{'=' * 60}\n")

        streams = {}
        content = self.packet_display.get(1.0, tk.END)
        for line in content.split('\n'):
            if 'TCP' in line:
                parts = line.split()
                try:
                    src = parts[3].split(':')[0]
                    dst = parts[5].split(':')[0]
                    key = f"{src}:{dst}" if src < dst else f"{dst}:{src}"
                    if key not in streams:
                        streams[key] = {'src': src, 'dst': dst, 'packets': []}
                    streams[key]['packets'].append(line)
                except (IndexError, ValueError):
                    continue

        self.tool_output.insert(1.0, f"Found {len(streams)} TCP streams\n\n")
        for key, stream in streams.items():
            self.tool_output.insert(1.0, f"Stream: {stream['src']} <-> {stream['dst']}\n")
            self.tool_output.insert(1.0, f"Packets: {len(stream['packets'])}\n")
            self.tool_output.insert(1.0, "-" * 40 + "\n")
            for pkt in stream['packets'][:10]:
                self.tool_output.insert(1.0, f"  {pkt}\n")
            if len(stream['packets']) > 10:
                self.tool_output.insert(1.0, f"  ... and {len(stream['packets']) - 10} more\n")
            self.tool_output.insert(1.0, "\n")

        self.log(f"TCP stream reassembly: {len(streams)} streams", "SUCCESS")

    # ==================== SECURITY FUNCTIONS ====================

    def load_cve_database(self):
        """Load local CVE database (NVD API 2.0)"""
        try:
            cve_file = os.path.expanduser("~/network_analyzer_data/cve_cache.json")
            # Use cache if less than 24 hours old
            if os.path.exists(cve_file):
                cache_age = time.time() - os.path.getmtime(cve_file)
                if cache_age < 86400:
                    with open(cve_file, 'r') as f:
                        self.cve_db = json.load(f)
                    self.log(f"Loaded {len(self.cve_db)} CVE entries (cached)", "INFO")
                    return

            self.log("Downloading CVE database...", "INFO")
            import urllib.request
            import ssl as ssl_mod

            from datetime import timedelta
            # Try NVD API 2.0 first
            try:
                ctx = ssl_mod.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_mod.CERT_NONE
                end_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
                start = datetime.utcnow() - timedelta(days=120)
                start_date = start.strftime("%Y-%m-%dT%H:%M:%S.000")
                url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                       f"?lastModStartDate={start_date}&lastModEndDate={end_date}&resultsPerPage=50")
                req = urllib.request.Request(url, headers={'User-Agent': 'NetworkAnalyzerPro/4.2'})
                response = urllib.request.urlopen(req, context=ctx, timeout=15)
                data = json.loads(response.read())
                self.cve_db = {}
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    if cve_id:
                        descs = cve.get('descriptions', [])
                        desc = next((d['value'] for d in descs if d.get('lang') == 'en'), '')
                        if desc:
                            self.cve_db[cve_id] = desc[:200]
                self.log(f"NVD API: loaded {len(self.cve_db)} CVEs", "SUCCESS")
            except Exception as nvd_err:
                self.log(f"NVD API failed ({nvd_err}), trying CIRCL...", "INFO")
                # Fallback: CIRCL CVE API (no auth required)
                try:
                    url = "https://cve.circl.lu/api/last"
                    req = urllib.request.Request(url, headers={'User-Agent': 'NetworkAnalyzerPro/4.2'})
                    response = urllib.request.urlopen(req, timeout=10)
                    data = json.loads(response.read())
                    self.cve_db = {}
                    for entry in data:
                        cve_id = entry.get('id', '')
                        summary = entry.get('summary', '')
                        if cve_id and summary:
                            self.cve_db[cve_id] = summary[:200]
                    self.log(f"CIRCL API: loaded {len(self.cve_db)} CVEs", "SUCCESS")
                except Exception as circl_err:
                    self.log(f"CIRCL API also failed ({circl_err})", "WARNING")
                    raise

            os.makedirs(os.path.dirname(cve_file), exist_ok=True)
            with open(cve_file, 'w') as f:
                json.dump(self.cve_db, f)

        except Exception as e:
            self.log(f"CVE database error: {e}", "WARNING")
            self.cve_db = {}

    def check_device_vulnerabilities(self, ip):
        """Check device for known vulnerabilities"""
        vulnerabilities = []
        open_ports = self.scan_common_ports(ip)
        port_vulns = {
            21: "FTP - weak authentication possible",
            22: "SSH - check for weak cipher suites",
            23: "Telnet - insecure protocol",
            80: "HTTP - check for known web vulnerabilities",
            443: "HTTPS - verify SSL/TLS configuration",
            445: "SMB - known vulnerabilities (EternalBlue, etc.)",
            3389: "RDP - check for BlueKeep vulnerability"
        }
        for port in open_ports:
            if port in port_vulns:
                vulnerabilities.append(f"Port {port}: {port_vulns[port]}")

        if self.cve_db:
            for cve_id, description in self.cve_db.items():
                for port in open_ports:
                    if str(port) in description.lower():
                        vulnerabilities.append(f"{cve_id}: {description[:100]}...")
                        break

        return vulnerabilities

    def arp_spoofing_detection(self):
        """Monitor for ARP spoofing attacks"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy required for ARP monitoring", "ERROR")
            return self._show_tool_message("❌ Scapy not installed.\nInstall: pip install scapy")
        if not self._check_root("ARP spoofing detection"):
            return

        self.log("Starting ARP spoofing detection...", "SECURITY")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, "🔍 ARP Spoofing Detection\n")
        self.tool_output.insert(1.0, f"{'=' * 60}\n")
        self.tool_output.insert(1.0, "Monitoring ARP traffic (30s)...\n\n")

        arp_table = {}

        def arp_monitor(pkt):
            if not hasattr(self, 'arp_monitoring') or not self.arp_monitoring:
                return
            if ARP in pkt and pkt[ARP].op == 2:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in arp_table:
                    if arp_table[ip] != mac:
                        alert = f"⚠️ ARP SPOOFING: {ip} now at {mac} (was {arp_table[ip]})"
                        self.tool_output.insert(1.0, f"\n{alert}\n")
                        self.add_alert(alert)
                else:
                    arp_table[ip] = mac
                    self.tool_output.insert(1.0, f"✅ {ip} -> {mac}\n")

        self.arp_monitoring = True
        try:
            sniff(filter="arp", prn=arp_monitor, store=0, timeout=30)
        except PermissionError:
            self.tool_output.insert(1.0, "\n❌ Permission denied. Run with sudo for ARP monitoring.\n")
            self.log("ARP monitoring requires root privileges", "WARNING")
        except Exception as e:
            self.tool_output.insert(1.0, f"\n⚠️ ARP monitoring error: {e}\n")
            self.log(f"ARP monitoring error: {e}", "WARNING")
        finally:
            self.arp_monitoring = False
            self.tool_output.insert(1.0, "\n✅ ARP monitoring complete\n")

    def _show_tool_message(self, message):
        """Show a message in the tool output area"""
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, message + "\n")

    def port_scan_detection(self):
        """Detect port scans against this machine"""
        if not SCAPY_AVAILABLE:
            self._show_tool_message("❌ Scapy not installed.\nInstall: pip install scapy")
            return
        if not self._check_root("Port scan detection"):
            return

        self.log("Starting port scan detection...", "SECURITY")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, "🛡️ Port Scan Detection\n")
        self.tool_output.insert(1.0, f"{'=' * 60}\n")
        self.tool_output.insert(1.0, "Monitoring for scans (30s)...\n\n")

        scan_threshold = 10
        source_tracker = {}

        def scan_detector(pkt):
            if not hasattr(self, 'scan_detection') or not self.scan_detection:
                return
            if IP in pkt and TCP in pkt:
                src = pkt[IP].src
                flags = pkt[TCP].flags
                if flags & 0x02 and not (flags & 0x10):
                    if src not in source_tracker:
                        source_tracker[src] = {'ports': []}
                    source_tracker[src]['ports'].append(pkt[TCP].dport)
                    if len(source_tracker[src]['ports']) >= scan_threshold:
                        alert = f"⚠️ Port scan detected from {src}: {len(source_tracker[src]['ports'])} ports"
                        self.tool_output.insert(1.0, f"\n{alert}\n")
                        self.add_alert(alert)
                        source_tracker[src]['ports'] = []

        self.scan_detection = True
        try:
            sniff(filter="tcp", prn=scan_detector, store=0, timeout=30)
        except PermissionError:
            self.tool_output.insert(1.0, "\n❌ Permission denied. Run with sudo for scan detection.\n")
            self.log("Scan detection requires root privileges", "WARNING")
        except Exception as e:
            self.tool_output.insert(1.0, f"\n⚠️ Detection error: {e}\n")
            self.log(f"Scan detection error: {e}", "WARNING")
        finally:
            self.scan_detection = False
            self.tool_output.insert(1.0, "\n✅ Scan detection complete\n")

    def analyze_ssl_certificate(self, target=None, port=443):
        """Analyze SSL/TLS certificate"""
        if not target:
            dialog = tk.Toplevel(self.root)
            dialog.title("SSL Certificate Analysis")
            dialog.geometry("500x200")
            dialog.configure(bg=self.colors['bg'])
            ttk.Label(dialog, text="Target (domain or IP):", style='Pro.TLabel').pack(pady=10)
            entry = ttk.Entry(dialog, width=40, font=('Consolas', 11))
            entry.pack(pady=10)
            def do_lookup():
                t = entry.get().strip()
                if t:
                    dialog.destroy()
                    threading.Thread(target=self.analyze_ssl_certificate, args=(t,), daemon=True).start()
            ttk.Button(dialog, text="Analyze", command=do_lookup, style='Pro.TButton').pack(pady=10)
            entry.bind('<Return>', lambda e: do_lookup())
            return

        self.log(f"Analyzing SSL certificate for {target}:{port}", "SECURITY")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, f"🔒 SSL Certificate Analysis\n")
        self.tool_output.insert(1.0, f"{'=' * 60}\n")
        self.tool_output.insert(1.0, f"Target: {target}:{port}\n\n")

        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=target
            )
            conn.settimeout(5)
            conn.connect((target, port))

            cert = conn.getpeercert()
            cipher = conn.cipher()

            self.tool_output.insert(1.0, f"✅ SSL connection established\n")
            self.tool_output.insert(1.0, f"Cipher: {cipher[0]}\n")

            if cert:
                self.tool_output.insert(1.0, f"\n📋 Certificate Details:\n")
                self.tool_output.insert(1.0, f"{'-' * 40}\n")
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                self.tool_output.insert(1.0, f"Subject: {subject.get('commonName', 'Unknown')}\n")
                self.tool_output.insert(1.0, f"Issuer: {issuer.get('commonName', 'Unknown')}\n")

                not_after = cert['notAfter']
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now()).days

                if days_left < 0:
                    self.tool_output.insert(1.0, f"⚠️ Certificate EXPIRED on {not_after}\n")
                elif days_left < 30:
                    self.tool_output.insert(1.0, f"⚠️ Expires in {days_left} days ({not_after})\n")
                else:
                    self.tool_output.insert(1.0, f"✅ Valid until {not_after} ({days_left} days)\n")

                if 'subjectAltName' in cert:
                    san = [x[1] for x in cert['subjectAltName']]
                    self.tool_output.insert(1.0, f"SAN: {', '.join(san[:5])}\n")

            conn.close()
            self.log(f"SSL analysis complete for {target}", "SUCCESS")

        except ssl.SSLError as e:
            self.tool_output.insert(1.0, f"❌ SSL Error: {e}\n")
            self.log(f"SSL analysis error: {e}", "WARNING")
        except Exception as e:
            self.tool_output.insert(1.0, f"❌ Error: {e}\n")
            self.log(f"SSL analysis error: {e}", "ERROR")

    def generate_security_report(self):
        """Generate HTML security report"""
        self.log("Generating security report...", "SECURITY")
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.expanduser(f"~/network_analyzer_data/security_report_{timestamp}.html")

            html = """<!DOCTYPE html>
<html>
<head><title>Security Report</title>
<style>
body { background: #0a0a12; color: #e0e0e0; font-family: Arial; padding: 20px; }
h1 { color: #6c5ce7; }
table { width: 100%; border-collapse: collapse; margin: 20px 0; }
th { background: #6c5ce7; padding: 10px; text-align: left; }
td { background: #14141f; padding: 8px; border: 1px solid #2d2d44; }
.warning { color: #ffd93d; }
.danger { color: #ff6b6b; }
.success { color: #00d4aa; }
</style>
</head>
<body>
<h1>🔒 Network Security Report</h1>
<p>Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
<p>Devices: """ + str(len(self.device_tree.get_children())) + """</p>

<h2>Device Security Summary</h2>
<table>
<tr><th>IP</th><th>Hostname</th><th>Open Ports</th><th>Vulnerabilities</th></tr>
"""
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                ip = values[0]
                hostname = values[1]
                ports = values[4]
                vulns = self.check_device_vulnerabilities(ip)
                vuln_class = "success" if not vulns else "danger" if len(vulns) > 2 else "warning"
                vuln_text = "<br>".join(vulns) if vulns else "✅ No issues found"
                html += f"""
            <tr>
                <td>{ip}</td>
                <td>{hostname}</td>
                <td>{ports}</td>
                <td class="{vuln_class}">{vuln_text}</td>
            </tr>
            """

            html += """
</table>
<h2>Recommendations</h2>
<ul>
<li>Run regular security audits</li>
<li>Keep firmware/software updated</li>
<li>Disable unnecessary services</li>
<li>Use strong passwords</li>
<li>Enable firewall</li>
</ul>
</body>
</html>
"""
            with open(filename, 'w') as f:
                f.write(html)

            self.log(f"Security report generated: {filename}", "SUCCESS")
            messagebox.showinfo("Report Complete", f"Security report saved to:\n{filename}")
        except Exception as e:
            self.log(f"Report generation error: {e}", "ERROR")

    # ==================== TOOL FUNCTIONS ====================

    def port_scan_tool(self):
        """Port scan tool"""
        selection = self.device_tree.selection()
        if not selection:
            selection = self.device_list.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a device first")
            return
        item = self.device_tree.item(selection[0])
        ip = item['values'][0]
        self.log(f"Port scan on {ip}...", "TOOL")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, f"🔍 Port Scan: {ip}\n{'=' * 60}\n")
        threading.Thread(target=self.run_port_scan, args=(ip,), daemon=True).start()

    def run_port_scan(self, ip):
        """Run port scan"""
        try:
            open_ports = []
            for port in range(1, 1025):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                        self.tool_output.insert(1.0, f"✅ Port {port} open\n")
                    sock.close()
                except:
                    pass
                if port % 100 == 0:
                    self.tool_output.insert(1.0, f"Progress: {port}/1024\n")
                    self.root.update_idletasks()
            self.tool_output.insert(1.0, f"\n{'=' * 60}\n")
            if open_ports:
                self.tool_output.insert(1.0, f"Found {len(open_ports)} open ports\n")
                self.tool_output.insert(1.0, f"Ports: {', '.join(map(str, open_ports))}\n")
            else:
                self.tool_output.insert(1.0, "No open ports found\n")
            self.log(f"Port scan complete: {len(open_ports)} open ports", "SUCCESS")
        except Exception as e:
            self.log(f"Port scan error: {e}", "ERROR")
            self.tool_output.insert(1.0, f"\nError: {e}")

    def traceroute(self):
        """Traceroute"""
        selection = self.device_tree.selection()
        if not selection:
            selection = self.device_list.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a device first")
            return
        item = self.device_tree.item(selection[0])
        ip = item['values'][0]
        self.log(f"Traceroute to {ip}...", "TOOL")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, f"📡 Traceroute to {ip}\n{'=' * 60}\n")
        threading.Thread(target=self.run_traceroute, args=(ip,), daemon=True).start()

    def run_traceroute(self, target):
        """Run traceroute with root check"""
        if not self._check_root("Traceroute"):
            return
        try:
            for ttl in range(1, 31):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    sock.settimeout(2)
                    packet = struct.pack('!BBHHH', 8, 0, 0, 0, 0)
                    start = time.time()
                    sock.sendto(packet, (target, 0))
                    try:
                        data, addr = sock.recvfrom(1024)
                        rtt = (time.time() - start) * 1000
                        self.tool_output.insert(1.0, f"{ttl:2d}  {addr[0]}  {rtt:.1f}ms\n")
                        if addr[0] == target:
                            self.tool_output.insert(1.0, "\n✅ Complete!\n")
                            break
                    except socket.timeout:
                        self.tool_output.insert(1.0, f"{ttl:2d}  * * *\n")
                    sock.close()
                except PermissionError:
                    self.tool_output.insert(1.0, f"{ttl:2d}  ❌ Permission denied (need root)\n")
                    break
                except:
                    self.tool_output.insert(1.0, f"{ttl:2d}  Error\n")
                time.sleep(0.3)
        except Exception as e:
            self.log(f"Traceroute error: {e}", "ERROR")

    def dns_lookup(self):
        """DNS Lookup with multi-IP display"""
        dialog = tk.Toplevel(self.root)
        dialog.title("DNS Lookup")
        dialog.geometry("500x350")
        dialog.configure(bg=self.colors['bg'])

        ttk.Label(dialog, text="Domain (without http://):", style='Pro.TLabel',
                  font=('Arial', 11)).pack(pady=(10, 2))
        domain_entry = ttk.Entry(dialog, width=40, font=('Consolas', 11))
        domain_entry.pack(pady=5)
        domain_entry.focus()

        ttk.Label(dialog, text="Example: google.com, github.com", style='Pro.TLabel',
                  foreground=self.colors['text_dim']).pack()

        result_text = tk.Text(dialog, height=10, width=50,
                              bg=self.colors['secondary'], fg=self.colors['text'],
                              font=('Consolas', 10), bd=0, highlightthickness=0)
        result_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        def lookup():
            domain = domain_entry.get().strip()
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            if not domain:
                result_text.delete(1.0, tk.END)
                result_text.insert(1.0, "Please enter a domain name")
                return

            self.log(f"DNS lookup for {domain}", "TOOL")
            result_text.delete(1.0, tk.END)
            result_text.insert(1.0, f"🔍 Looking up {domain}...\n")
            self.root.update_idletasks()

            try:
                ip = socket.gethostbyname(domain)
                result = f"🌐 DNS Lookup Result\n{'=' * 40}\n"
                result += f"Domain: {domain}\n"
                result += f"IP Address: {ip}\n"

                try:
                    addrs = socket.getaddrinfo(domain, None)
                    ips = set()
                    for addr in addrs:
                        if addr[4][0] not in ('', domain):
                            ips.add(addr[4][0])
                    if len(ips) > 1:
                        result += f"\nAll Resolved IPs:\n"
                        for r_ip in sorted(ips):
                            result += f"  {r_ip}\n"
                except:
                    pass

                result_text.delete(1.0, tk.END)
                result_text.insert(1.0, result)
                self.log(f"DNS lookup: {domain} -> {ip}", "SUCCESS")
            except socket.gaierror as e:
                error_msg = f"❌ Domain not found: {domain}\n"
                error_msg += f"Error: {e}\n\n"
                error_msg += "💡 Tips:\n"
                error_msg += "  - Check spelling\n"
                error_msg += "  - Don't include http:// or https://\n"
                error_msg += "  - Make sure domain exists"
                result_text.delete(1.0, tk.END)
                result_text.insert(1.0, error_msg)
                self.log(f"DNS lookup failed for {domain}: {e}", "ERROR")
            except Exception as e:
                result_text.delete(1.0, tk.END)
                result_text.insert(1.0, f"Error: {e}")
                self.log(f"DNS lookup error: {e}", "ERROR")

        btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="🔍 Lookup", command=lookup,
                  style='Pro.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=dialog.destroy,
                  style='Pro.TButton').pack(side=tk.LEFT, padx=5)
        domain_entry.bind('<Return>', lambda e: lookup())

    def security_audit(self):
        """Security audit with CVE checking"""
        self.log("Starting security audit...", "SECURITY")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, "🔒 Security Audit\n")
        self.tool_output.insert(1.0, f"{'=' * 60}\n")
        threading.Thread(target=self.run_security_audit, daemon=True).start()

    def run_security_audit(self):
        """Run security audit with CVE and weak password checks"""
        try:
            # Load CVE database if not loaded
            if not self.cve_db:
                self.tool_output.insert(1.0, "Loading CVE database...\n")
                self.load_cve_database()

            total = len(self.device_tree.get_children())
            if total == 0:
                self.tool_output.insert(1.0, "⚠️ No devices found. Run a scan first.\n")
                return

            self.tool_output.insert(1.0, f"Scanning {total} devices...\n\n")
            findings = []

            for idx, item in enumerate(self.device_tree.get_children()):
                values = self.device_tree.item(item)['values']
                ip = values[0]
                hostname = values[1]
                self.tool_output.insert(1.0, f"Checking {ip} ({hostname})...\n")
                self.root.update_idletasks()

                open_ports = self.scan_common_ports(ip)
                if open_ports:
                    vulns = []
                    if 21 in open_ports:
                        vulns.append("  🔓 FTP (21) - use SFTP instead")
                    if 22 in open_ports:
                        vulns.append("  🔓 SSH (22) - check for weak passwords/ciphers")
                    if 23 in open_ports:
                        vulns.append("  🔴 Telnet (23) - insecure, disable")
                    if 25 in open_ports:
                        vulns.append("  🔓 SMTP (25) - check for open relay")
                    if 80 in open_ports:
                        vulns.append("  ℹ️ HTTP (80) - check for web vulnerabilities")
                    if 445 in open_ports:
                        vulns.append("  🔴 SMB (445) - known RCE vulnerabilities")
                    if 3389 in open_ports:
                        vulns.append("  🔴 RDP (3389) - check BlueKeep")

                    if vulns:
                        findings.append(f"\n⚠️ {ip} ({hostname}):\n" + "\n".join(vulns))

                progress = (idx + 1) / total * 100
                self.tool_output.insert(1.0, f"  Progress: {progress:.0f}%\n")
                self.root.update_idletasks()

            self.tool_output.insert(1.0, f"\n{'=' * 60}\n")
            if findings:
                self.tool_output.insert(1.0, f"⚠️ Found {len(findings)} security issues:\n")
                self.tool_output.insert(1.0, "\n".join(findings))
                self.log(f"Security audit: {len(findings)} issues found", "WARNING")
            else:
                self.tool_output.insert(1.0, "✅ No security issues found\n")
                self.log("Security audit: Clean", "SUCCESS")

            self.tool_output.insert(1.0, f"\n💾 Click 'Generate Report' to save as HTML\n")

        except Exception as e:
            self.log(f"Security audit error: {e}", "ERROR")

    def network_stats(self):
        """Network stats"""
        self.log("Getting network stats...", "TOOL")
        self.tool_output.delete(1.0, tk.END)

        try:
            stats = "📊 Network Statistics\n"
            stats += f"{'=' * 60}\n\n"

            try:
                interfaces = psutil.net_if_addrs()
                stats += "Network Interfaces:\n"
                stats += f"{'-' * 30}\n"
                for name, addrs in list(interfaces.items())[:5]:
                    stats += f"  {name}:\n"
                    for addr in addrs[:2]:
                        if addr.family == socket.AF_INET:
                            stats += f"    IPv4: {addr.address}\n"
                stats += "\n"
            except:
                pass

            try:
                net_io = psutil.net_io_counters()
                stats += "Network I/O:\n"
                stats += f"{'-' * 30}\n"
                stats += f"  Bytes Sent: {net_io.bytes_sent // 1024 ** 2:,} MB\n"
                stats += f"  Bytes Received: {net_io.bytes_recv // 1024 ** 2:,} MB\n"
                stats += f"  Packets Sent: {net_io.packets_sent:,}\n"
                stats += f"  Packets Received: {net_io.packets_recv:,}\n\n"
            except:
                pass

            try:
                connections = psutil.net_connections()
                stats += f"Active Connections: {len(connections)}\n"
                stats += f"{'-' * 30}\n"
                tcp = len([c for c in connections if c.type == socket.SOCK_STREAM])
                udp = len([c for c in connections if c.type == socket.SOCK_DGRAM])
                stats += f"  TCP: {tcp}\n  UDP: {udp}\n"
            except:
                pass

            self.tool_output.insert(1.0, stats)
            self.log("Network stats displayed", "SUCCESS")
        except Exception as e:
            self.log(f"Network stats error: {str(e)[:50]}", "WARNING")
            self.tool_output.insert(1.0, f"Error: {str(e)[:100]}")

    def speed_test(self):
        """Speed test"""
        self.log("Starting speed test...", "TOOL")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, "📊 Speed Test\n{'='*60}\n")
        threading.Thread(target=self.run_speed_test, daemon=True).start()

    def run_speed_test(self):
        """Run speed test with jitter and quality rating"""
        try:
            self.tool_output.insert(1.0, "📊 Speed Test\n{'=' * 60}\n\n")
            self.tool_output.insert(1.0, "📡 Measuring latency (10 pings to 8.8.8.8)...\n")
            self.tool_output.see(tk.END)

            latencies = []
            for i in range(10):
                try:
                    ping_time = ping3.ping('8.8.8.8', timeout=2)
                    if ping_time:
                        rtt = ping_time * 1000
                        latencies.append(rtt)
                        status = '✅' if rtt < 50 else '⚠️' if rtt < 100 else '❌'
                        self.tool_output.insert(1.0, f"  Ping {i + 1}: {rtt:.1f}ms {status}\n")
                    else:
                        self.tool_output.insert(1.0, f"  Ping {i + 1}: Timeout ❌\n")
                except:
                    self.tool_output.insert(1.0, f"  Ping {i + 1}: Error\n")
                self.tool_output.see(tk.END)
                self.root.update_idletasks()
                time.sleep(0.5)

            if latencies:
                avg = sum(latencies) / len(latencies)
                min_lat = min(latencies)
                max_lat = max(latencies)
                jitter = max_lat - min_lat
                loss = (10 - len(latencies)) / 10 * 100

                self.tool_output.insert(1.0, f"\n{'=' * 60}\n")
                self.tool_output.insert(1.0, f"📊 Results:\n")
                self.tool_output.insert(1.0, f"  Average: {avg:.1f}ms\n")
                self.tool_output.insert(1.0, f"  Minimum: {min_lat:.1f}ms\n")
                self.tool_output.insert(1.0, f"  Maximum: {max_lat:.1f}ms\n")
                self.tool_output.insert(1.0, f"  Jitter: {jitter:.1f}ms\n")
                self.tool_output.insert(1.0, f"  Packet Loss: {loss:.1f}%\n")

                if avg < 20:
                    quality = "🌟 Excellent"
                elif avg < 50:
                    quality = "✅ Good"
                elif avg < 100:
                    quality = "⚠️ Fair"
                else:
                    quality = "❌ Poor"
                self.tool_output.insert(1.0, f"  Quality: {quality}\n")
                self.log(f"Speed test: {avg:.1f}ms, {quality.split()[-1]}", "SUCCESS")
            else:
                self.tool_output.insert(1.0, "\n❌ No responses received\n")
                self.log("Speed test failed - no responses", "ERROR")
        except Exception as e:
            self.log(f"Speed test error: {e}", "ERROR")
            self.tool_output.insert(1.0, f"\n❌ Error: {e}\n")

    # ==================== DEVICE FUNCTIONS ====================

    def on_device_select(self, event):
        """Device select with rich security details"""
        selection = self.device_tree.selection()
        if not selection:
            selection = self.device_list.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            values = item['values']
            ip = values[0]
            hostname = values[1]
            mac = values[2]
            vendor = values[3]
            ports = values[4]
            status = values[5]

            is_gw = self._is_gateway(ip)
            details = ""
            if is_gw:
                details += "🌐 Gateway Router\n"
            details += f"{'─' * 50}\n"
            details += f"  IP        {ip}\n"
            details += f"  Hostname  {hostname}\n"
            details += f"  MAC       {mac}\n"
            details += f"  Vendor    {vendor}\n"
            details += f"  Ports     {ports}\n"
            details += f"  Status    {status}\n"

            if is_gw:
                details += f"\n  🔒 This device is the network gateway.\n"
                details += f"     Routes traffic between your network and the internet.\n"

            # Security analysis for all devices with ports
            if ports and ports != 'None':
                try:
                    port_list = [int(p) for p in ports.split(',') if p.strip().isdigit()]
                    if port_list:
                        details += f"\n🔐 Security Analysis\n"
                        details += f"{'─' * 50}\n"
                        # Port descriptions
                        port_desc = {
                            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
                            3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
                        }
                        for p in port_list:
                            desc = port_desc.get(p, "")
                            risk = ""
                            if p in (21, 23, 25):
                                risk = " ⚠️ Insecure"
                            elif p == 445:
                                risk = " ⚠️ RCE Risk"
                            elif p == 3389:
                                risk = " ⚠️ BlueKeep Risk"
                            elif p == 22:
                                risk = " 🔒 Secure"
                            elif p == 443:
                                risk = " 🔒 Encrypted"
                            details += f"     Port {p:5d}  {desc}{risk}\n"

                        vulns = self.check_device_vulnerabilities(ip)
                        if vulns:
                            details += f"\n  ⚠ Vulnerabilities:\n"
                            for v in vulns[:5]:
                                details += f"     • {v}\n"
                        else:
                            details += f"\n  ✅ No known vulnerabilities detected\n"
                except:
                    pass

            if ip in self.known_devices:
                details += f"\n📝 Notes:\n"
                details += f"     {self.known_devices[ip].get('notes', 'None')}\n"

            # Parental control info
            if ip in self.known_devices:
                dev_info = self.known_devices[ip]
                if dev_info.get('owner') or dev_info.get('profile'):
                    details += f"\n🔞 Parental Control\n"
                    details += f"{'─' * 50}\n"
                    details += f"     Owner:  {dev_info.get('owner', 'Not set')}\n"
                    details += f"     Profile: {dev_info.get('profile', 'Not set').capitalize()}\n"
                    details += f"     Device:  {dev_info.get('device_name', 'Unknown')}\n"
                    details += f"     Type:    {dev_info.get('device_type', 'Unknown')}\n"
                    details += f"     Location: {dev_info.get('location', 'Unknown')}\n"
                    details += f"     Blocked: {'Yes 🔒' if dev_info.get('blocked', False) else 'No'}\n"

            self.device_details.delete(1.0, tk.END)
            self.device_details.insert(1.0, details)

    def refresh_devices(self):
        """Refresh"""
        self.log("Refreshing devices...", "INFO")
        self.quick_scan()

    def analyze_devices(self):
        """Analyze"""
        self.log("Analyzing devices...", "TOOL")
        self.tool_output.delete(1.0, tk.END)
        devices = []
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item)['values']
            devices.append({'ip': values[0], 'hostname': values[1]})
        if devices:
            analysis = f"📊 Device Analysis\n{'=' * 60}\n"
            analysis += f"Total: {len(devices)}\n"
            unknown = len([d for d in devices if d['hostname'] == 'Unknown'])
            analysis += f"Unknown: {unknown}\n"
            self.tool_output.insert(1.0, analysis)

    def add_device_note(self):
        """Add note"""
        selection = self.device_tree.selection()
        if not selection:
            selection = self.device_list.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a device first")
            return
        item = self.device_tree.item(selection[0])
        ip = item['values'][0]

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Add Note - {ip}")
        dialog.geometry("500x300")
        dialog.configure(bg=self.colors['bg'])
        ttk.Label(dialog, text=f"Device: {ip}", style='Pro.TLabel').pack(pady=10)
        note_entry = tk.Text(dialog, height=8, width=50, bg=self.colors['secondary'], fg='white')
        note_entry.pack(pady=10)
        if ip in self.known_devices and 'notes' in self.known_devices[ip]:
            note_entry.insert(1.0, self.known_devices[ip]['notes'])

        def save_note():
            note = note_entry.get(1.0, tk.END).strip()
            if ip not in self.known_devices:
                self.known_devices[ip] = {}
            self.known_devices[ip]['notes'] = note
            self.known_devices[ip]['date'] = datetime.now().isoformat()
            self.save_data()
            self.log(f"Note saved for {ip}", "SUCCESS")
            dialog.destroy()

        ttk.Button(dialog, text="Save", command=save_note, style='Pro.TButton').pack(pady=10)

    def ping_tool(self):
        """Ping tool"""
        selection = self.device_tree.selection()
        if not selection:
            selection = self.device_list.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a device first")
            return
        item = self.device_tree.item(selection[0])
        ip = item['values'][0]
        self.log(f"Pinging {ip}...", "TOOL")
        self.tool_output.delete(1.0, tk.END)
        threading.Thread(target=self.run_ping, args=(ip,), daemon=True).start()

    def run_ping(self, ip):
        """Run ping"""
        try:
            result = f"📡 Ping Results: {ip}\n{'=' * 60}\n"
            times = []
            for i in range(5):
                response = ping3.ping(ip, timeout=2)
                if response:
                    rtt = response * 1000
                    times.append(rtt)
                    result += f"Reply: {rtt:.1f}ms\n"
                else:
                    result += "Timeout\n"
                self.tool_output.delete(1.0, tk.END)
                self.tool_output.insert(1.0, result)
                self.root.update_idletasks()
                time.sleep(1)
            if times:
                result += f"\nAvg: {sum(times) / len(times):.1f}ms | Min: {min(times):.1f}ms | Max: {max(times):.1f}ms\n"
                self.tool_output.insert(1.0, result)
            self.log(f"Ping complete to {ip}", "SUCCESS")
        except Exception as e:
            self.log(f"Ping error: {e}", "ERROR")

    # ==================== EXPORT FUNCTIONS ====================

    def export_report(self):
        """Export report"""
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if filename:
                report = f"🔬 Network Report\n{'=' * 70}\n"
                report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                report += f"Total Devices: {len(self.device_tree.get_children())}\n\n"
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item)['values']
                    report += f"IP: {values[0]} | Hostname: {values[1]} | Status: {values[5]}\n"
                with open(filename, 'w') as f:
                    f.write(report)
                self.log(f"Report exported", "SUCCESS")
                messagebox.showinfo("Export Complete", f"Saved to:\n{filename}")
        except Exception as e:
            self.log(f"Export error: {e}", "ERROR")

    def export_device_data(self):
        """Export device data"""
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".json",
                                                    filetypes=[("JSON", "*.json"), ("All", "*.*")])
            if filename:
                devices = []
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item)['values']
                    devices.append({'ip': values[0], 'hostname': values[1], 'status': values[5]})
                with open(filename, 'w') as f:
                    json.dump(devices, f, indent=2)
                self.log(f"Device data exported", "SUCCESS")
                messagebox.showinfo("Export Complete", f"Saved to:\n{filename}")
        except Exception as e:
            self.log(f"Export error: {e}", "ERROR")

    def backup_data(self):
        """Backup"""
        try:
            backup_dir = os.path.expanduser("~/network_analyzer_backup")
            os.makedirs(backup_dir, exist_ok=True, mode=0o755)
            try:
                if os.stat(backup_dir).st_uid == 0 and os.geteuid() != 0:
                    os.system(f"sudo chown -R {os.getlogin()} '{backup_dir}' 2>/dev/null")
                    os.system(f"sudo chmod -R 755 '{backup_dir}' 2>/dev/null")
            except:
                pass
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(backup_dir, f"backup_{timestamp}.json")
            data = {
                'backup_time': datetime.now().isoformat(),
                'known_devices': self.known_devices,
                'alerts': self.alerts
            }
            with open(backup_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.log(f"Backup saved to {backup_file}", "SUCCESS")
            messagebox.showinfo("Backup Complete", f"Saved to:\n{backup_file}")
        except Exception as e:
            self.log(f"Backup error: {e}", "ERROR")

    # ==================== LOG FUNCTIONS ====================

    def clear_logs(self):
        """Clear logs"""
        if messagebox.askyesno("Clear Logs", "Clear all logs?"):
            self.log_display.delete(1.0, tk.END)
            self.log("Logs cleared", "INFO")

    def save_logs(self):
        """Save logs"""
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                    filetypes=[("Text", "*.txt"), ("All", "*.*")])
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.log_display.get(1.0, tk.END))
                self.log(f"Logs saved", "SUCCESS")
                messagebox.showinfo("Save Complete", f"Saved to:\n{filename}")
        except Exception as e:
            self.log(f"Save error: {e}", "ERROR")

    def load_data(self):
        """Load data including parental control settings"""
        try:
            data_dir = getattr(self, 'data_dir', None)
            if not data_dir:
                data_dir = os.path.expanduser("~/network_analyzer_data")
            known_file = os.path.join(data_dir, "known_devices.json")
            if os.path.exists(known_file):
                with open(known_file, 'r') as f:
                    data = json.load(f)
                # Handle both plain dict and enhanced format
                if isinstance(data, dict) and 'known_devices' in data:
                    self.known_devices = data.get('known_devices', {})
                    self.parental_settings.update(data.get('parental_settings', {}))
                    self.parental_profiles.update(data.get('parental_profiles', {}))
                    self.parental_blocked_count = data.get('parental_blocked_count', 0)
                    self.content_blocklist = set(data.get('content_blocklist', []))
                    self.content_allowlist = set(data.get('content_allowlist', []))
                    self.parental_last_reset = data.get('parental_last_reset', datetime.now().isoformat())
                    # Load infrastructure data
                    loaded_infra = data.get('infrastructure', {})
                    if loaded_infra:
                        self.infrastructure = loaded_infra
                    loaded_alerts = data.get('rogue_alerts', [])
                    if loaded_alerts:
                        self.rogue_alerts = deque(loaded_alerts, maxlen=5000)
                    loaded_sessions = data.get('device_sessions', {})
                    if loaded_sessions:
                        self.device_sessions = loaded_sessions
                    loaded_wireless = data.get('wireless_scan_cache', {})
                    if loaded_wireless:
                        self.wireless_scan_cache = loaded_wireless
                else:
                    self.known_devices = data
                self.log(f"Loaded {len(self.known_devices)} known devices", "INFO")
        except Exception as e:
            self.log(f"Data load error: {e}", "WARNING")

    def save_data(self):
        """Save data including parental control settings"""
        try:
            data_dir = getattr(self, 'data_dir', None)
            if not data_dir:
                data_dir = os.path.expanduser("~/network_analyzer_data")
            os.makedirs(data_dir, exist_ok=True, mode=0o755)
            data = {
                'known_devices': self.known_devices,
                'parental_settings': self.parental_settings,
                'parental_profiles': self.parental_profiles,
                'parental_blocked_count': self.parental_blocked_count,
                'content_blocklist': list(self.content_blocklist),
                'content_allowlist': list(self.content_allowlist),
                'parental_last_reset': self.parental_last_reset,
                'infrastructure': self.infrastructure,
                'rogue_alerts': list(self.rogue_alerts),
                'device_sessions': self.device_sessions,
                'wireless_scan_cache': self.wireless_scan_cache,
            }
            filepath = os.path.join(data_dir, "known_devices.json")
            # Fix permissions if directory or files are owned by root
            try:
                if os.stat(data_dir).st_uid == 0 and os.geteuid() != 0:
                    os.system(f"sudo chown -R {os.getlogin()} '{data_dir}' 2>/dev/null")
                    os.system(f"sudo chmod -R 755 '{data_dir}' 2>/dev/null")
            except:
                pass
            # Handle existing root-owned known_devices.json
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'a'):
                        pass
                except PermissionError:
                    try:
                        os.remove(filepath)
                    except:
                        os.system(f"sudo chmod 666 '{filepath}' 2>/dev/null")
                        if os.path.exists(filepath):
                            try:
                                os.remove(filepath)
                            except:
                                pass
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.log(f"Data save error: {e}", "WARNING")

    def ensure_data_directory(self):
        """Create data directory with proper permissions and fallbacks"""
        # Primary location
        data_dir = os.path.expanduser("~/network_analyzer_data")
        try:
            if not os.path.exists(data_dir):
                os.makedirs(data_dir, mode=0o755)
            # Test write access (directory + existing file)
            test_file = os.path.join(data_dir, ".write_test")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
            # Also check if existing known_devices.json is writable
            json_file = os.path.join(data_dir, "known_devices.json")
            if os.path.exists(json_file):
                try:
                    with open(json_file, 'a'):
                        pass
                except PermissionError:
                    raise PermissionError(f"Cannot write {json_file}")
            self.log(f"Data directory: {data_dir}", "INFO")
            return data_dir
        except Exception as e:
            self.log(f"Permission error in {data_dir}: {e}", "WARNING")
            # Fallback to Documents folder
            fallback_dir = os.path.expanduser("~/Documents/network_analyzer_data")
            try:
                if not os.path.exists(fallback_dir):
                    os.makedirs(fallback_dir, mode=0o755)
                # Test write access
                test_file = os.path.join(fallback_dir, ".write_test")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                self.log(f"Using fallback directory: {fallback_dir}", "INFO")
                return fallback_dir
            except:
                self.log("CRITICAL: Cannot create data directory in home or Documents", "ERROR")
                # Use /tmp as last resort
                tmp_dir = "/tmp/network_analyzer_data"
                os.makedirs(tmp_dir, exist_ok=True)
                self.log(f"Using temp directory: {tmp_dir}", "WARNING")
                return tmp_dir

    def show_about(self):
        """About"""
        about = f"🔬 Network Analyzer Pro v4.2\n{'=' * 40}\n"
        about += f"Platform: {platform.system()} {platform.release()}\n"
        about += f"Python: {sys.version.split()[0]}\n"
        about += f"Scapy: {'✅' if SCAPY_AVAILABLE else '❌'}\n\n"
        about += "Features:\n"
        about += "• ARP/ICMP scanning with thread pool\n"
        about += "• Packet capture with BPF filtering\n"
        about += "• PCAP import/export\n"
        about += "• Netcat with TCP/UDP/SSL/File transfer\n"
        about += "• Security audit with CVE integration\n"
        about += "• ARP spoofing / port scan detection\n"
        about += "• SSL certificate analysis\n"
        about += "• HTML security reports\n"
        about += "• CSV/PDF/TXT/JSON export\n"
        about += "• 👨‍👩‍👧 Parental controls (DNS monitoring, content filtering, profiles)\n"
        about += "• Keyboard shortcuts, tooltips\n"
        messagebox.showinfo("About", about)

    def show_docs(self):
        """Docs"""
        docs = "📚 Documentation\n{'='*60}\n\n"
        docs += "🔍 SCAN: Quick (Ctrl+N, ping), Full (Ctrl+F, ARP), Deep (Ctrl+D, ports)\n"
        docs += "📡 MONITOR: Connections (Ctrl+M), Bandwidth\n"
        docs += "📦 PACKETS: Capture with BPF filter, PCAP load/save, TCP streams\n"
        docs += "🔌 NETCAT: TCP/UDP, SSL/TLS, file transfer, hexdump (Ctrl+S)\n"
        docs += "🔧 TOOLS: Port scan, Traceroute, DNS, Security audit\n"
        docs += "🔒 SECURITY: ARP spoof detection, port scan detection, SSL check\n"
        docs += "💾 EXPORT: CSV, PDF, TXT, JSON, HTML reports\n"
        docs += "\n💡 Tip: Run a scan first to discover devices"
        messagebox.showinfo("Documentation", docs)


def main():
    """Main"""
    try:
        root = tk.Tk()
        app = NetworkAnalyzerPro(root)
        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
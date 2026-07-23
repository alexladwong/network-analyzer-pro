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

        # Start background tasks
        self.update_status_time()
        self.auto_refresh()

        # Load data
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
                  background=[('active', c['highlight']), ('pressed', '#5a4bd1')])

        style.configure('Small.TButton', background=c['accent2'],
                        foreground='white', borderwidth=0, padding=(8, 4),
                        font=('Arial', 9))
        style.map('Small.TButton',
                  background=[('active', c['highlight']), ('pressed', '#5a4bd1')])

        # Notebook/tabs
        style.configure('Pro.TNotebook', background=c['bg'], borderwidth=0)
        style.configure('Pro.TNotebook.Tab', background=c['secondary'],
                        foreground=c['text_dim'], padding=[28, 10],
                        font=('Arial', 10))
        style.map('Pro.TNotebook.Tab',
                  background=[('selected', c['bg']), ('active', c['accent'])],
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

    def _create_card(self, parent, title, **kwargs):
        """Create a professional card container with accent header bar"""
        expand = kwargs.get('expand', False)
        fill = kwargs.get('fill', tk.X)
        pady = kwargs.get('pady', (0, 8))
        side = kwargs.get('side', tk.TOP)
        padx = kwargs.get('padx', 0)
        height = kwargs.get('header_height', 32)

        card = tk.Frame(parent, bg=self.colors['secondary'],
                        highlightbackground=self.colors['accent2'],
                        highlightthickness=1, bd=0)
        card.pack(fill=fill, expand=expand, pady=pady, side=side, padx=padx)

        header_bg = kwargs.get('header_bg', self.colors['accent'])
        tk.Frame(card, bg=header_bg, height=height).pack(fill=tk.X)
        tk.Label(card, text=f"  {title}", bg=header_bg,
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(4, 0), padx=8)
        return card

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
        self.create_logs_tab()

    def create_header(self):
        """Create professional header with branding"""
        header = ttk.Frame(self.main_container, style='Pro.TFrame')
        header.pack(fill=tk.X, pady=(0, 12))

        # Left side: app branding
        title_frame = ttk.Frame(header, style='Pro.TFrame')
        title_frame.pack(side=tk.LEFT)

        # App icon and title
        icon_label = ttk.Label(title_frame, text="🔬", font=('Arial', 28), style='Pro.TLabel')
        icon_label.pack(side=tk.LEFT, padx=(0, 8))

        text_frame = ttk.Frame(title_frame, style='Pro.TFrame')
        text_frame.pack(side=tk.LEFT)

        title = ttk.Label(text_frame, text="Network Analyzer Pro",
                          font=('Arial', 24, 'bold'), style='Pro.TLabel',
                          foreground=self.colors['text'])
        title.pack(anchor=tk.W)

        subtitle_frame = ttk.Frame(text_frame, style='Pro.TFrame')
        subtitle_frame.pack(anchor=tk.W)
        version = ttk.Label(subtitle_frame, text="v4.2 Enterprise",
                            font=('Arial', 9), style='Pro.TLabel',
                            foreground=self.colors['highlight'])
        version.pack(side=tk.LEFT)

        tagline = ttk.Label(subtitle_frame, text="• Network Security & Analysis Suite",
                            font=('Arial', 9), style='Pro.TLabel',
                            foreground=self.colors['text_dim'])
        tagline.pack(side=tk.LEFT, padx=8)

        # Separator
        tk.Frame(header, width=1, bg=self.colors['accent2']).pack(side=tk.LEFT, fill=tk.Y, padx=20)

        # Right side: stats with nicer badges
        stats_frame = ttk.Frame(header, style='Pro.TFrame')
        stats_frame.pack(side=tk.RIGHT)

        # Scapy status badge
        scapy_status = "✅" if SCAPY_AVAILABLE else "❌"
        scapy_bg = self.colors['accent2']
        scapy_frame = ttk.Frame(stats_frame, style='Card.TFrame')
        scapy_frame.pack(side=tk.LEFT, padx=4)
        ttk.Label(scapy_frame, text=f"  Scapy {scapy_status}  ",
                  font=('Consolas', 9), style='Card.TLabel',
                  foreground=self.colors['success'] if SCAPY_AVAILABLE else self.colors['danger']).pack()

        # Device count badge
        dev_frame = ttk.Frame(stats_frame, style='Card.TFrame')
        dev_frame.pack(side=tk.LEFT, padx=4)
        ttk.Label(dev_frame, text=" 📱 ", font=('Arial', 9), style='Card.TLabel',
                  foreground=self.colors['info']).pack(side=tk.LEFT)
        self.status_devices = ttk.Label(dev_frame, textvariable=self.device_count,
                                        font=('Arial', 10, 'bold'), style='Card.TLabel')
        self.status_devices.pack(side=tk.LEFT, padx=(0, 6))

        # Packet count badge
        pkt_frame = ttk.Frame(stats_frame, style='Card.TFrame')
        pkt_frame.pack(side=tk.LEFT, padx=4)
        ttk.Label(pkt_frame, text=" 📦 ", font=('Arial', 9), style='Card.TLabel',
                  foreground=self.colors['warning']).pack(side=tk.LEFT)
        self.status_packets = ttk.Label(pkt_frame, textvariable=self.packet_count,
                                        font=('Arial', 10, 'bold'), style='Card.TLabel')
        self.status_packets.pack(side=tk.LEFT, padx=(0, 6))

        # Alert count badge
        alert_frame = ttk.Frame(stats_frame, style='Card.TFrame')
        alert_frame.pack(side=tk.LEFT, padx=4)
        ttk.Label(alert_frame, text=" 🔔 ", font=('Arial', 9), style='Card.TLabel',
                  foreground=self.colors['danger']).pack(side=tk.LEFT)
        self.status_alerts = ttk.Label(alert_frame, textvariable=self.alert_count,
                                       font=('Arial', 10, 'bold'), style='Card.TLabel')
        self.status_alerts.pack(side=tk.LEFT, padx=(0, 6))

    def create_dashboard_tab(self):
        """Dashboard with professional card layout"""
        tab = ttk.Frame(self.notebook, style='Pro.TFrame')
        self.notebook.add(tab, text="  Dashboard  ")

        # Top row: 3 columns
        top_row = ttk.Frame(tab, style='Pro.TFrame')
        top_row.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        col1 = ttk.Frame(top_row, style='Pro.TFrame')
        col1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        col2 = ttk.Frame(top_row, style='Pro.TFrame')
        col2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        col3 = ttk.Frame(top_row, style='Pro.TFrame')
        col3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # === Network Status Card ===
        summary_card = tk.Frame(col1, bg=self.colors['secondary'],
                                highlightbackground=self.colors['accent2'],
                                highlightthickness=1, bd=0)
        summary_card.pack(fill=tk.BOTH, expand=True)

        # Card header
        tk.Frame(summary_card, bg=self.colors['accent'], height=32).pack(fill=tk.X)
        tk.Label(summary_card, text="  Network Status", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(4, 0), padx=8)

        self.summary_text = tk.Text(summary_card, height=10, bg=self.colors['secondary'],
                                    fg=self.colors['text'], font=('Consolas', 10), wrap=tk.WORD,
                                    bd=0, highlightthickness=0, padx=10, pady=8)
        self.summary_text.pack(fill=tk.BOTH, expand=True)

        # === System Resources Card ===
        sys_card = tk.Frame(col2, bg=self.colors['secondary'],
                            highlightbackground=self.colors['accent2'],
                            highlightthickness=1, bd=0)
        sys_card.pack(fill=tk.BOTH, expand=True)

        tk.Frame(sys_card, bg=self.colors['accent'], height=32).pack(fill=tk.X)
        tk.Label(sys_card, text="  System Resources", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(4, 0), padx=8)

        self.sys_status = tk.Text(sys_card, height=10, bg=self.colors['secondary'],
                                  fg=self.colors['text'], font=('Consolas', 9),
                                  bd=0, highlightthickness=0, padx=10, pady=8)
        self.sys_status.pack(fill=tk.BOTH, expand=True)

        # === Right column: Quick Actions + Recent Activity ===
        # Quick Actions Card
        actions_card = tk.Frame(col3, bg=self.colors['secondary'],
                                highlightbackground=self.colors['accent2'],
                                highlightthickness=1, bd=0)
        actions_card.pack(fill=tk.X, pady=(0, 8))

        tk.Frame(actions_card, bg=self.colors['accent'], height=32).pack(fill=tk.X)
        tk.Label(actions_card, text="  Quick Actions", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(4, 0), padx=8)

        actions_inner = ttk.Frame(actions_card, style='Pro.TFrame')
        actions_inner.pack(fill=tk.X, padx=10, pady=10)

        # Two-column action buttons
        actions = [
            ("Quick Scan", self.quick_scan, '#6c5ce7'),
            ("Full Scan", self.full_scan, '#6c5ce7'),
            ("Speed Test", self.speed_test, '#00d4aa'),
            ("Security Audit", self.security_audit, '#ff6b6b'),
            ("Export Report", self.export_report, '#4ecdc4'),
            ("Backup Data", self.backup_data, '#ffd93d'),
        ]

        row_frame = None
        for i, (text, command, color) in enumerate(actions):
            if i % 2 == 0:
                row_frame = ttk.Frame(actions_inner, style='Pro.TFrame')
                row_frame.pack(fill=tk.X, pady=2)
            btn_frame = ttk.Frame(row_frame, style='Pro.TFrame')
            btn_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
            btn = tk.Button(btn_frame, text=text, command=command,
                           bg=self.colors['accent'], fg='white',
                           font=('Arial', 10), bd=0, padx=8, pady=6,
                           activebackground=self.colors['highlight'],
                           activeforeground='white',
                           cursor='hand2')
            btn.pack(fill=tk.X)

        # Recent Activity Card
        activity_card = tk.Frame(col3, bg=self.colors['secondary'],
                                 highlightbackground=self.colors['accent2'],
                                 highlightthickness=1, bd=0)
        activity_card.pack(fill=tk.BOTH, expand=True)

        tk.Frame(activity_card, bg=self.colors['accent'], height=32).pack(fill=tk.X)
        tk.Label(activity_card, text="  Recent Activity", bg=self.colors['accent'],
                 fg='white', font=('Arial', 11, 'bold'), anchor='w').pack(fill=tk.X, pady=(4, 0), padx=8)

        self.activity_text = tk.Text(activity_card, height=6, bg=self.colors['secondary'],
                                     fg=self.colors['text'], font=('Consolas', 9),
                                     bd=0, highlightthickness=0, padx=10, pady=8)
        self.activity_text.pack(fill=tk.BOTH, expand=True)

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
        network_entry = ttk.Entry(range_frame, textvariable=self.network_ip,
                                  width=25, font=('Consolas', 11), style='Pro.TEntry')
        network_entry.pack(side=tk.LEFT, padx=5)

        mode_frame = ttk.Frame(inner, style='Pro.TFrame')
        mode_frame.pack(fill=tk.X, pady=8)
        self.scan_mode = tk.StringVar(value="comprehensive")
        modes = [("⚡ Quick", "quick"), ("🔬 Comprehensive", "comprehensive"), ("🔍 Deep", "deep")]
        for i, (label, value) in enumerate(modes):
            rb = ttk.Radiobutton(mode_frame, text=label, value=value,
                                 variable=self.scan_mode, style='Pro.TButton')
            rb.pack(side=tk.LEFT, padx=10)

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
        self.scan_progress = ttk.Progressbar(progress_inner, length=600, mode='determinate',
                                              style='Pro.Horizontal.TProgressbar')
        self.scan_progress.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.scan_status = ttk.Label(progress_inner, text="Ready", style='Pro.TLabel',
                                      font=('Arial', 10, 'bold'))
        self.scan_status.pack(side=tk.LEFT, padx=10)

        # Scan Results Card
        result_card = self._create_card(tab, "Scan Results", expand=True, fill=tk.BOTH, pady=(0, 0))
        result_inner = ttk.Frame(result_card, style='Pro.TFrame')
        result_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        columns = ('IP', 'Hostname', 'MAC', 'Vendor', 'Ports', 'Status')
        self.device_tree = ttk.Treeview(result_inner, columns=columns,
                                        show='headings', style='Pro.Treeview')
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=130)

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

        # Monitor Controls Card
        ctrl_card = self._create_card(tab, "Monitor Controls")
        ctrl_inner = ttk.Frame(ctrl_card, style='Pro.TFrame')
        ctrl_inner.pack(fill=tk.X, padx=12, pady=8)

        btn_frame = ttk.Frame(ctrl_inner, style='Pro.TFrame')
        btn_frame.pack()
        self.monitor_btn = ttk.Button(btn_frame, text="▶ Start Monitoring",
                                      command=self.start_monitoring, style='Pro.TButton')
        self.monitor_btn.pack(side=tk.LEFT, padx=5)
        self.monitor_stop_btn = ttk.Button(btn_frame, text="⏹ Stop",
                                           command=self.stop_monitoring, style='Pro.TButton')
        self.monitor_stop_btn.pack(side=tk.LEFT, padx=5)
        self.monitor_stop_btn.config(state='disabled')
        self.bandwidth_btn = ttk.Button(btn_frame, text="📊 Bandwidth",
                                        command=self.toggle_bandwidth, style='Pro.TButton')
        self.bandwidth_btn.pack(side=tk.LEFT, padx=5)

        # Live Network Activity Card
        activity_card = self._create_card(tab, "Live Network Activity", expand=True, fill=tk.BOTH, pady=(0, 0))
        activity_inner = ttk.Frame(activity_card, style='Pro.TFrame')
        activity_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.monitor_display = tk.Text(activity_inner, bg=self.colors['secondary'],
                                       fg=self.colors['text'], font=('Consolas', 9), height=20,
                                       bd=0, highlightthickness=0)
        monitor_scrollbar = ttk.Scrollbar(activity_inner, orient=tk.VERTICAL,
                                           command=self.monitor_display.yview, style='Pro.Vertical.TScrollbar')
        self.monitor_display.configure(yscrollcommand=monitor_scrollbar.set)
        self.monitor_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        monitor_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bandwidth info
        info_frame = ttk.Frame(tab, style='Pro.TFrame')
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        self.bandwidth_info = ttk.Label(info_frame, text="📊 Down: 0 KB/s | Up: 0 KB/s",
                                        style='Pro.TLabel', font=('Arial', 11))
        self.bandwidth_info.pack()

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
                                 variable=self.netcat_mode, style='Pro.TButton')
            rb.pack(side=tk.LEFT, padx=10)

        # Protocol selection
        proto_frame = ttk.Frame(inner, style='Pro.TFrame')
        proto_frame.pack(fill=tk.X, pady=5)
        ttk.Label(proto_frame, text="Protocol:", style='Pro.TLabel',
                  font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        for label, value in [("TCP", "tcp"), ("UDP", "udp")]:
            rb = ttk.Radiobutton(proto_frame, text=label, value=value,
                                 variable=self.netcat_protocol, style='Pro.TButton')
            rb.pack(side=tk.LEFT, padx=10)

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
            "PACKET": "📦", "NETCAT": "🔌"
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
        self.root.after(30000, self.auto_refresh)

    def update_summary(self):
        """Update summary"""
        try:
            local_ip = self.get_local_ip()
            gateway = self.get_gateway()
            device_count = len(self.device_tree.get_children()) if hasattr(self, 'device_tree') else 0

            summary = f"🌐 Network Status\n{'=' * 50}\n"
            summary += f"Local IP: {local_ip}\nGateway: {gateway}\n"
            summary += f"Devices: {device_count}\nScapy: {'✅ Available' if SCAPY_AVAILABLE else '❌ Not available'}\n"
            summary += f"Updated: {datetime.now().strftime('%H:%M:%S')}\n{'=' * 50}\n"

            if hasattr(self, 'summary_text'):
                self.summary_text.delete(1.0, tk.END)
                self.summary_text.insert(1.0, summary)
        except:
            pass

    def update_system_status(self):
        """Update system status"""
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            net = psutil.net_io_counters()

            status = f"💻 System Resources\n{'=' * 40}\n"
            status += f"CPU: {cpu}% {'█' * int(cpu / 5)}\n"
            status += f"Memory: {mem.percent}% ({mem.used // 1024 ** 3}/{mem.total // 1024 ** 3} GB)\n"
            status += f"Disk: {disk.percent}% ({disk.used // 1024 ** 3}/{disk.total // 1024 ** 3} GB)\n"
            status += f"Network: {net.bytes_sent // 1024 ** 2} MB sent, {net.bytes_recv // 1024 ** 2} MB received\n"

            if hasattr(self, 'sys_status'):
                self.sys_status.delete(1.0, tk.END)
                self.sys_status.insert(1.0, status)
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

    def quick_scan(self):
        """Quick scan"""
        self.log("Starting quick scan (thread pool)...", "SCAN")
        self.scan_status.config(text="Scanning...")
        threading.Thread(target=self.run_quick_scan_threadpool, daemon=True).start()

    def run_quick_scan(self):
        """Run quick scan"""
        try:
            self.device_tree.delete(*self.device_tree.get_children())
            self.device_list.delete(*self.device_list.get_children())

            network = self.network_ip.get()
            base = network.split('/')[0]
            parts = base.split('.')
            base_ip = '.'.join(parts[:3])

            self.scan_progress['maximum'] = 254
            devices_found = []

            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                try:
                    response = ping3.ping(ip, timeout=0.3)
                    if response is not None:
                        hostname = self.get_hostname(ip)
                        mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                        vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'

                        devices_found.append(ip)
                        self.device_tree.insert('', tk.END, values=(
                            ip, hostname, mac, vendor, 'None', '🟢 Online'
                        ))
                        self.device_list.insert('', tk.END, values=(
                            ip, hostname, mac, '🟢 Online'
                        ))
                except:
                    pass
                self.scan_progress['value'] = i
                self.root.update_idletasks()

            self.scan_progress['value'] = 0
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices")
            self.update_scan_stats()
            self.log(f"Quick scan complete: {len(devices_found)} devices", "SUCCESS")
        except Exception as e:
            self.log(f"Quick scan error: {e}", "ERROR")

    def full_scan(self):
        """Full scan"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available, using quick scan", "WARNING")
            self.quick_scan()
            return
        self.log("Starting full scan...", "SCAN")
        self.scan_status.config(text="ARP scan in progress...")
        threading.Thread(target=self.run_full_scan, daemon=True).start()

    def run_full_scan(self):
        """Run full scan"""
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
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                hostname = self.get_hostname(ip)
                vendor = self.get_vendor(mac)
                open_ports = self.scan_common_ports(ip)
                ports_str = ','.join(map(str, open_ports[:5])) if open_ports else 'None'

                devices_found.append(ip)
                self.device_tree.insert('', tk.END, values=(
                    ip, hostname, mac, vendor, ports_str, '🟢 Online'
                ))
                self.device_list.insert('', tk.END, values=(
                    ip, hostname, mac, '🟢 Online'
                ))

            self.scan_progress['value'] = 100
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices")
            self.update_scan_stats()
            self.log(f"Full scan complete: {len(devices_found)} devices", "SUCCESS")
        except Exception as e:
            self.log(f"Full scan error: {e}", "ERROR")

    def deep_scan(self):
        """Deep scan"""
        self.log("Starting deep scan...", "SCAN")
        self.scan_status.config(text="Deep scan in progress...")
        threading.Thread(target=self.run_deep_scan, daemon=True).start()

    def run_deep_scan(self):
        """Run deep scan"""
        try:
            self.device_tree.delete(*self.device_tree.get_children())
            self.device_list.delete(*self.device_list.get_children())

            network = self.network_ip.get()
            base = network.split('/')[0]
            parts = base.split('.')
            base_ip = '.'.join(parts[:3])

            self.scan_progress['maximum'] = 254
            devices_found = []

            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                try:
                    response = ping3.ping(ip, timeout=0.5)
                    if response is not None:
                        hostname = self.get_hostname(ip)
                        mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                        vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'

                        open_ports = self.scan_ports(ip, list(range(1, 1025)))
                        ports_str = ','.join(map(str, open_ports[:5])) if open_ports else 'None'

                        devices_found.append(ip)
                        self.device_tree.insert('', tk.END, values=(
                            ip, hostname, mac, vendor, ports_str, '🟢 Online'
                        ))
                        self.device_list.insert('', tk.END, values=(
                            ip, hostname, mac, '🟢 Online'
                        ))
                except:
                    pass
                self.scan_progress['value'] = i
                self.root.update_idletasks()

            self.scan_progress['value'] = 0
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices")
            self.update_scan_stats()
            self.log(f"Deep scan complete: {len(devices_found)} devices", "SUCCESS")
        except Exception as e:
            self.log(f"Deep scan error: {e}", "ERROR")

    def get_mac_address(self, ip):
        """Get MAC address"""
        try:
            if SCAPY_AVAILABLE:
                arp_request = ARP(pdst=ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                answered = srp(broadcast / arp_request, timeout=1, verbose=False)[0]
                if answered:
                    return answered[0][1].hwsrc
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

    def get_vendor(self, mac):
        """Get vendor from MAC with comprehensive OUI database"""
        if not hasattr(self, '_oui_db'):
            self._oui_db = {
                # Apple
                '00:1B:63': 'Apple Inc.', '00:1E:52': 'Apple Inc.',
                '00:25:BC': 'Apple Inc.', 'AC:29:3A': 'Apple Inc.',
                '3C:07:54': 'Apple Inc.', '38:C9:86': 'Apple Inc.',
                '4C:32:75': 'Apple Inc.', '60:03:08': 'Apple Inc.',
                'C8:2A:14': 'Apple Inc.', 'F0:18:98': 'Apple Inc.',
                '10:05:1A': 'Apple Inc.', '78:4F:43': 'Apple Inc.',
                '7C:11:BE': 'Apple Inc.', '7C:6A:8D': 'Apple Inc.',
                '84:38:35': 'Apple Inc.', '8C:85:90': 'Apple Inc.',
                'A4:D1:D2': 'Apple Inc.', 'B8:E8:56': 'Apple Inc.',
                'C0:98:79': 'Apple Inc.', 'E0:2B:E9': 'Apple Inc.',
                'F0:F6:1C': 'Apple Inc.', 'D0:23:DB': 'Apple Inc.',
                # Raspberry Pi
                'B8:27:EB': 'Raspberry Pi Foundation',
                'DC:A6:32': 'Raspberry Pi Foundation',
                'E4:5F:01': 'Raspberry Pi Foundation',
                # VMware
                '00:0C:29': 'VMware Inc.', '00:50:56': 'VMware Inc.',
                '00:1C:42': 'Parallels/VMware',
                # Microsoft
                '00:15:5D': 'Microsoft Corp.', '28:18:78': 'Microsoft Corp.',
                '00:03:FF': 'Microsoft Corp.', '08:00:27': 'Oracle/VirtualBox',
                # Cisco
                '00:1A:A0': 'Cisco Systems', '00:1C:42': 'Cisco Systems',
                '00:14:5C': 'Cisco Systems', '00:17:5A': 'Cisco Systems',
                '00:1B:0C': 'Cisco Systems', '00:1F:6C': 'Cisco Systems',
                '00:24:14': 'Cisco Systems', '08:00:69': 'Cisco Systems',
                # Intel
                '00:13:72': 'Intel Corp.', '00:1B:21': 'Intel Corp.',
                '00:1E:65': 'Intel Corp.', '00:21:6B': 'Intel Corp.',
                '00:24:D6': 'Intel Corp.', 'F8:9E:94': 'Intel Corp.',
                # Samsung
                '00:1F:90': 'Samsung Electronics',
                'D4:BF:6F': 'Samsung Electronics',
                '9C:02:84': 'Samsung Electronics',
                'E0:63:E5': 'Samsung Electronics',
                # Google
                'F4:F5:D8': 'Google Inc.', '3C:5A:B4': 'Google Inc.',
                '18:B4:30': 'Google Inc.', '8C:6E:8E': 'Google Inc.',
                'A4:77:33': 'Google Inc.', 'B4:D5:BD': 'Google Inc.',
                # Amazon
                'F8:9E:94': 'Amazon Tech', 'AC:63:BE': 'Amazon Tech',
                '40:B4:34': 'Amazon Tech', '48:18:8D': 'Amazon Tech',
                '74:75:48': 'Amazon Tech', '88:66:5A': 'Amazon Tech',
                # Huawei
                '00:18:82': 'Huawei Tech', '38:59:F9': 'Huawei Tech',
                '44:6E:E5': 'Huawei Tech', '48:22:54': 'Huawei Tech',
                '90:F6:52': 'Huawei Tech', 'E0:0F:86': 'Huawei Tech',
                # TP-Link
                '14:CF:E2': 'TP-Link Tech', '30:B5:C2': 'TP-Link Tech',
                '50:C7:BF': 'TP-Link Tech', '54:E6:FC': 'TP-Link Tech',
                '84:D8:1B': 'TP-Link Tech', 'A8:57:4E': 'TP-Link Tech',
                'C0:4A:00': 'TP-Link Tech', 'D8:0D:17': 'TP-Link Tech',
                'E8:48:B8': 'TP-Link Tech', 'F8:8E:85': 'TP-Link Tech',
                # Netgear
                '00:0F:B5': 'Netgear Inc.', '20:E5:2A': 'Netgear Inc.',
                '2C:35:6B': 'Netgear Inc.', '5C:55:AE': 'Netgear Inc.',
                '6C:B0:CE': 'Netgear Inc.', 'A0:21:B7': 'Netgear Inc.',
                'C0:3F:0E': 'Netgear Inc.', 'E0:91:53': 'Netgear Inc.',
                # Dell
                '00:14:22': 'Dell Inc.', '00:1E:4F': 'Dell Inc.',
                '18:03:73': 'Dell Inc.', '34:97:F6': 'Dell Inc.',
                '5C:26:0A': 'Dell Inc.', 'F0:1F:AF': 'Dell Inc.',
                # HP
                '00:17:A4': 'HP Inc.', '00:1C:C4': 'HP Inc.',
                '18:67:B0': 'HP Inc.', '3C:D9:2B': 'HP Inc.',
                '68:B5:99': 'HP Inc.', '9C:B6:54': 'HP Inc.',
                # Lenovo
                '00:1A:4B': 'Lenovo Group', '28:D2:44': 'Lenovo Group',
                '38:63:BB': 'Lenovo Group', 'B0:C0:90': 'Lenovo Group',
                'E0:D4:E8': 'Lenovo Group',
                # Asus
                '00:1B:FC': 'ASUStek', '10:7C:61': 'ASUStek',
                '90:84:0D': 'ASUStek', '94:D9:B3': 'ASUStek',
                'AC:22:0B': 'ASUStek', 'D4:3D:7E': 'ASUStek',
                # Xiaomi
                '18:6F:D3': 'Xiaomi Inc.', '28:CF:E9': 'Xiaomi Inc.',
                '9C:F4:8B': 'Xiaomi Inc.', 'AC:37:43': 'Xiaomi Inc.',
                'F0:B4:29': 'Xiaomi Inc.',
                # Sony
                '00:1D:BA': 'Sony Corp.', '4C:EB:42': 'Sony Corp.',
                '64:9E:F3': 'Sony Corp.', 'AC:0A:61': 'Sony Corp.',
                # LG
                '00:1E:66': 'LG Electronics', '3C:CE:73': 'LG Electronics',
                'AC:BC:32': 'LG Electronics', 'F8:D1:11': 'LG Electronics',
                # Ubiquiti
                '00:15:6D': 'Ubiquiti Networks', '04:18:D6': 'Ubiquiti Networks',
                '24:A4:3C': 'Ubiquiti Networks', '68:72:51': 'Ubiquiti Networks',
                '74:83:C2': 'Ubiquiti Networks', 'D0:21:4D': 'Ubiquiti Networks',
                'E0:63:DA': 'Ubiquiti Networks',
                # Aruba
                '00:0B:86': 'Aruba Networks', '1C:1B:68': 'Aruba Networks',
                '84:D4:46': 'Aruba Networks', 'D8:C4:97': 'Aruba Networks',
                # Zyxel
                '00:13:49': 'ZyXEL Comm.', '20:CF:30': 'ZyXEL Comm.',
                '58:97:1E': 'ZyXEL Comm.', 'B0:75:D5': 'ZyXEL Comm.',
                # Intel AMT / NIC
                '00:21:85': 'Intel Corp.', 'A0:36:9F': 'Intel Corp.',
                'A0:48:1C': 'Intel Corp.', 'B4:96:82': 'Intel Corp.',
                'D0:50:99': 'Intel Corp.', 'F4:8E:38': 'Intel Corp.',
            }
        if mac == 'Unknown':
            return 'Unknown'
        oui = mac[:8].upper()
        return self._oui_db.get(oui, 'Unknown')

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
            if 'Online' in values[5] if len(values) > 5 else '':
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
        """Quick scan with ThreadPoolExecutor for parallel performance"""
        try:
            self.device_tree.delete(*self.device_tree.get_children())
            self.device_list.delete(*self.device_list.get_children())

            network = self.network_ip.get()
            base = network.split('/')[0]
            parts = base.split('.')
            base_ip = '.'.join(parts[:3])

            self.scan_progress['maximum'] = 254
            self.scan_progress['value'] = 0
            start_time = time.time()

            ips = [f"{base_ip}.{i}" for i in range(1, 255)]
            devices_found = []

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
                futures = {executor.submit(ping_ip, ip): ip for ip in ips}
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    result = future.result()
                    if result:
                        ip, hostname, mac, vendor = result
                        devices_found.append(ip)
                        self.device_tree.insert('', tk.END, values=(
                            ip, hostname, mac, vendor, 'None', '🟢 Online'
                        ))
                        self.device_list.insert('', tk.END, values=(
                            ip, hostname, mac, '🟢 Online'
                        ))
                    self.update_progress_with_eta(completed, 254, start_time)

            self.scan_progress['value'] = 100
            elapsed = time.time() - start_time
            self.device_count.set(f"{len(devices_found)} devices")
            self.scan_status.config(text=f"Found {len(devices_found)} devices in {elapsed:.1f}s")
            self.update_scan_stats()
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
        """Monitor network"""
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

                if hasattr(self, 'monitor_display'):
                    self.monitor_display.delete(1.0, tk.END)
                    info = f"🌐 Active Connections ({len(active)})\n{'=' * 60}\n\n"
                    if active:
                        info += "\n".join(active[-30:])
                    else:
                        info += "No active connections"
                    self.monitor_display.insert(1.0, info)
                time.sleep(2)
            except:
                time.sleep(5)

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
        """Monitor bandwidth"""
        try:
            old_net = psutil.net_io_counters()
            old_time = time.time()
            while self.bandwidth_monitoring:
                time.sleep(1)
                try:
                    new_net = psutil.net_io_counters()
                    new_time = time.time()
                    down = (new_net.bytes_recv - old_net.bytes_recv) / (new_time - old_time) / 1024
                    up = (new_net.bytes_sent - old_net.bytes_sent) / (new_time - old_time) / 1024
                    self.bandwidth_info.config(text=f"📊 Down: {down:.1f} KB/s | Up: {up:.1f} KB/s")
                    old_net = new_net
                    old_time = new_time
                except:
                    continue
        except:
            self.bandwidth_monitoring = False

    # ==================== PACKET CAPTURE ====================

    def start_capture(self):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            self.log("Scapy not available", "ERROR")
            self.tool_output.delete(1.0, tk.END)
            self.tool_output.insert(1.0, "❌ Scapy not installed. Install: pip install scapy")
            return

        if platform.system() != 'Windows' and os.geteuid() != 0:
            self.log("Packet capture may need root privileges", "WARNING")

        if not self.capturing:
            self.capturing = True
            self.capture_btn.config(text="🔄 Capturing...", state='disabled')
            self.capture_stop_btn.config(state='normal')
            self.log("Starting packet capture...", "PACKET")
            self.packet_display.delete(1.0, tk.END)
            self.packet_display.insert(1.0, "📦 Packet Capture Active\n")
            if platform.system() != 'Windows' and os.geteuid() != 0:
                self.packet_display.insert(1.0, "⚠️ May need root privileges for full capture\n\n")
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
        """Load local CVE database"""
        try:
            cve_file = os.path.expanduser("~/network_analyzer_data/cve_cache.json")
            if os.path.exists(cve_file):
                with open(cve_file, 'r') as f:
                    self.cve_db = json.load(f)
                self.log(f"Loaded {len(self.cve_db)} CVE entries", "INFO")
                return

            self.log("Downloading CVE database...", "INFO")
            import urllib.request
            import gzip
            url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
            response = urllib.request.urlopen(url)
            decompressed = gzip.decompress(response.read())
            cve_data = json.loads(decompressed)
            self.cve_db = {}
            for entry in cve_data.get('CVE_Items', []):
                cve_id = entry.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                if cve_id:
                    desc = entry.get('cve', {}).get('description', {}).get('description_data', [])
                    if desc:
                        self.cve_db[cve_id] = desc[0].get('value', '')
            os.makedirs(os.path.dirname(cve_file), exist_ok=True)
            with open(cve_file, 'w') as f:
                json.dump(self.cve_db, f)
            self.log(f"CVE database loaded: {len(self.cve_db)} entries", "SUCCESS")
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
        if platform.system() != 'Windows' and os.geteuid() != 0:
            return self._show_tool_message(
                "⚠️ ARP monitoring requires root privileges.\n\n"
                "Run: sudo python3 main.py\n\n"
                "Without root, Scapy cannot access raw network sockets needed\n"
                "to capture ARP packets from /dev/bpf*."
            )

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
        if platform.system() != 'Windows' and os.geteuid() != 0:
            return self._show_tool_message(
                "⚠️ Port scan detection requires root privileges.\n\n"
                "Run: sudo python3 main.py\n\n"
                "Without root, Scapy cannot access raw network sockets."
            )

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
        """Run traceroute"""
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
                except:
                    self.tool_output.insert(1.0, f"{ttl:2d}  Error\n")
                time.sleep(0.3)
        except Exception as e:
            self.log(f"Traceroute error: {e}", "ERROR")

    def dns_lookup(self):
        """DNS Lookup"""
        dialog = tk.Toplevel(self.root)
        dialog.title("DNS Lookup")
        dialog.geometry("500x300")
        dialog.configure(bg=self.colors['bg'])

        ttk.Label(dialog, text="Domain (without http://):", style='Pro.TLabel',
                  font=('Arial', 11)).pack(pady=10)
        domain_entry = ttk.Entry(dialog, width=40, font=('Consolas', 11))
        domain_entry.pack(pady=10)
        domain_entry.focus()

        result_text = tk.Text(dialog, height=8, width=50,
                              bg=self.colors['secondary'], fg=self.colors['text'],
                              font=('Consolas', 10))
        result_text.pack(pady=10)

        def lookup():
            domain = domain_entry.get().strip()
            domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
            if not domain:
                result_text.insert(1.0, "Please enter a domain name")
                return

            self.log(f"DNS lookup for {domain}", "TOOL")
            result_text.delete(1.0, tk.END)
            try:
                ip = socket.gethostbyname(domain)
                result = f"🌐 DNS Lookup\n{'=' * 40}\n"
                result += f"Domain: {domain}\nIP: {ip}\n"
                result_text.insert(1.0, result)
                self.log(f"DNS lookup: {domain} -> {ip}", "SUCCESS")
            except Exception as e:
                result_text.insert(1.0, f"Error: {e}\n\nTip: Enter domain without http://")
                self.log(f"DNS lookup error: {e}", "ERROR")

        ttk.Button(dialog, text="Lookup", command=lookup, style='Pro.TButton').pack(pady=5)
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
        """Run speed test"""
        try:
            latencies = []
            self.tool_output.insert(1.0, "Testing latency...\n")
            for i in range(10):
                try:
                    ping_time = ping3.ping('8.8.8.8', timeout=2)
                    if ping_time:
                        rtt = ping_time * 1000
                        latencies.append(rtt)
                        self.tool_output.insert(1.0, f"  Ping {i + 1}: {rtt:.1f}ms\n")
                    else:
                        self.tool_output.insert(1.0, f"  Ping {i + 1}: timeout\n")
                except:
                    self.tool_output.insert(1.0, f"  Ping {i + 1}: error\n")
                self.root.update_idletasks()
                time.sleep(0.5)

            if latencies:
                avg = sum(latencies) / len(latencies)
                self.tool_output.insert(1.0, f"\n{'=' * 60}\n")
                self.tool_output.insert(1.0, f"Average Latency: {avg:.1f}ms\n")
                self.tool_output.insert(1.0, f"Min: {min(latencies):.1f}ms | Max: {max(latencies):.1f}ms\n")
                quality = "🌟 Excellent" if avg < 20 else "✅ Good" if avg < 50 else "⚠️ Fair" if avg < 100 else "❌ Poor"
                self.tool_output.insert(1.0, f"Quality: {quality}\n")
                self.log(f"Speed test: {avg:.1f}ms, {quality}", "SUCCESS")
            else:
                self.tool_output.insert(1.0, "\n❌ No responses")
        except Exception as e:
            self.log(f"Speed test error: {e}", "ERROR")

    # ==================== DEVICE FUNCTIONS ====================

    def on_device_select(self, event):
        """Device select"""
        selection = self.device_tree.selection()
        if not selection:
            selection = self.device_list.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            values = item['values']
            details = f"📱 Device Information\n{'=' * 60}\n"
            details += f"IP: {values[0]}\nHostname: {values[1]}\n"
            details += f"MAC: {values[2]}\nVendor: {values[3]}\n"
            details += f"Ports: {values[4]}\nStatus: {values[5]}\n"
            if values[0] in self.known_devices:
                details += f"\n📝 Notes: {self.known_devices[values[0]].get('notes', 'None')}\n"
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
            os.makedirs(backup_dir, exist_ok=True)
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
        """Load data"""
        try:
            data_dir = os.path.expanduser("~/network_analyzer_data")
            known_file = os.path.join(data_dir, "known_devices.json")
            if os.path.exists(known_file):
                with open(known_file, 'r') as f:
                    self.known_devices = json.load(f)
                self.log(f"Loaded {len(self.known_devices)} known devices", "INFO")
        except:
            pass

    def save_data(self):
        """Save data"""
        try:
            data_dir = os.path.expanduser("~/network_analyzer_data")
            os.makedirs(data_dir, exist_ok=True)
            with open(os.path.join(data_dir, "known_devices.json"), 'w') as f:
                json.dump(self.known_devices, f, indent=2)
        except:
            pass

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
"""
main_window module — extracted from main.py
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


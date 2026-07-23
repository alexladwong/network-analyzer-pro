"""
dashboard module — extracted from main.py
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


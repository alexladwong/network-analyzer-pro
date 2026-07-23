"""
network_scan module — extracted from main.py
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
                                      state='normal', style='Pro.TEntry')
    self.network_combo['values'] = self.available_networks
    self.network_combo.pack(side=tk.LEFT, padx=5)
    ttk.Button(range_frame, text="↻", command=self.refresh_networks,
              style='Small.TButton', width=3).pack(side=tk.LEFT, padx=2)
    # Add a validate button for custom CIDR
    self.validate_btn = ttk.Button(range_frame, text="✓ Validate",
                                   command=self._validate_cidr_input,
                                   style='Small.TButton')
    self.validate_btn.pack(side=tk.LEFT, padx=2)
    self.cidr_status = ttk.Label(range_frame, text="", style='Pro.TLabel',
                                 font=('Consolas', 9))
    self.cidr_status.pack(side=tk.LEFT, padx=5)

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

def _validate_cidr_input(self):
    """Validate the CIDR input and provide feedback"""
    raw = self.network_ip.get().strip()
    try:
        network = ipaddress.IPv4Network(raw, strict=False)
        self.cidr_status.config(text=f"✅ {network.network_address}/{network.prefixlen} ({network.num_addresses} hosts)",
                                fg=self.colors['success'])
        # Update the combo value to the normalized form
        self.network_ip.set(f"{network.network_address}/{network.prefixlen}")
        return network
    except ValueError as e:
        self.cidr_status.config(text=f"❌ {e}", fg=self.colors['danger'])
        return None
    except Exception as e:
        self.cidr_status.config(text=f"❌ Invalid: {e}", fg=self.colors['danger'])
        return None

def _get_scan_targets(self):
    """Return list of valid CIDR network strings using proper parsing"""
    seen = set()
    targets = []
    selected = self.network_ip.get().strip()
    try:
        net = ipaddress.IPv4Network(selected, strict=False)
        key = str(net.network_address)
        if key not in seen:
            seen.add(key)
            targets.append(str(net))
    except:
        pass
    for net_str in self.available_networks:
        try:
            net = ipaddress.IPv4Network(net_str, strict=False)
            key = str(net.network_address)
            if key not in seen:
                seen.add(key)
                targets.append(str(net))
        except:
            pass
    if not targets:
        try:
            net = ipaddress.IPv4Network("192.168.1.0/24", strict=False)
            targets.append(str(net))
        except:
            pass
    return targets

def _ips_from_targets(self, targets):
    """Convert CIDR strings to deduplicated IP list"""
    seen = set()
    ips = []
    for net_str in targets:
        try:
            net = ipaddress.IPv4Network(net_str, strict=False)
            for host in net:
                s = str(host)
                if s not in seen:
                    seen.add(s)
                    ips.append(s)
        except:
            pass
    return ips

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


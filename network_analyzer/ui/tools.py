"""
tools module — extracted from main.py
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


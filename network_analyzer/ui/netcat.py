"""
netcat module — extracted from main.py
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


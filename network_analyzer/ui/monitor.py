"""
monitor module — extracted from main.py
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


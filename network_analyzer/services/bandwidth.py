"""
bandwidth module — extracted from main.py
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


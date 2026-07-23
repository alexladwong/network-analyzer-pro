"""
packets module — extracted from main.py
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


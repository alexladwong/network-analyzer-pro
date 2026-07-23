"""
logs module — extracted from main.py
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


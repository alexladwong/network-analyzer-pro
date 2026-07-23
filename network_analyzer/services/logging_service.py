"""
logging_service module — extracted from main.py
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

def log(self, message, level="INFO"):
    """Log message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    levels = {
        "INFO": "ℹ️", "WARNING": "⚠️", "ERROR": "❌", "SUCCESS": "✅",
        "SCAN": "🔍", "MONITOR": "📡", "SECURITY": "🔒", "TOOL": "🔧",
        "PACKET": "📦", "NETCAT": "🔌", "PARENTAL": "🔞"
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


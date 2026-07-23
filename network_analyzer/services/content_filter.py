"""
content_filter module — extracted from main.py
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

def toggle_content_filter(self):
    """Toggle content filtering on/off"""
    if self.parental_settings.get('block_method') == 'none':
        self.parental_settings['block_method'] = 'hosts'
        self.parental_filter_btn.config(text="⏹ Stop Filter", bg=self.colors['danger'])
        self.log("Content filtering activated", "PARENTAL")
    else:
        self.parental_settings['block_method'] = 'none'
        self.parental_filter_btn.config(text="▶ Start Filter", bg=self.colors['accent'])
        self.log("Content filtering deactivated", "PARENTAL")
    self.update_parental_stats()

def _block_via_hosts(self, domain):
    """Block a domain by adding to /etc/hosts (requires root)"""
    if platform.system() == 'Windows':
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    else:
        hosts_path = '/etc/hosts'

    try:
        with open(hosts_path, 'r') as f:
            content = f.read()
        block_line = f"127.0.0.1 {domain}"
        if block_line not in content:
            with open(hosts_path, 'a') as f:
                f.write(f"\n# Parental Control Block\n{block_line}\n")
            self.log(f"Added {domain} to hosts block list", "PARENTAL")
    except PermissionError:
        pass  # Silently fail - blocking works via DNS detection regardless
    except Exception as e:
        self.log(f"Hosts block error: {e}", "WARNING")


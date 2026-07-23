"""
network_discovery module — extracted from main.py
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

def get_local_ip(self):
    """Get local IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_gateway(self):
    """Get gateway"""
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line:
                    gateway = line.split(':')[-1].strip()
                    if gateway and gateway != '':
                        return gateway
        else:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default' in line:
                    parts = line.split()
                    if len(parts) > 2:
                        return parts[2]
    except:
        pass
    return "Unknown"

def _is_gateway(self, ip):
    """Check if an IP address is the default gateway"""
    gateway = self.get_gateway()
    if gateway and gateway != 'Unknown':
        return ip == gateway
    return False

def discover_networks(self):
    """Auto-detect all network subnets from all interfaces"""
    networks = []
    try:
        for name, addrs in psutil.net_if_addrs().items():
            if name.startswith(('lo', 'Loopback')):
                continue
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address and addr.netmask:
                    ip = addr.address
                    netmask = addr.netmask
                    # Compute CIDR prefix length from netmask
                    mask_bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                    # Compute network address
                    ip_parts = [int(x) for x in ip.split('.')]
                    mask_parts = [int(x) for x in netmask.split('.')]
                    network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                    network_addr = '.'.join(str(x) for x in network_parts)
                    cidr = f"{network_addr}/{mask_bits}"
                    if cidr not in networks:
                        networks.append(cidr)
                        self.log(f"Discovered network: {cidr} ({name})", "INFO")
        if not networks:
            self.log("No networks discovered, using default", "WARNING")
    except Exception as e:
        self.log(f"Network discovery error: {e}", "WARNING")
    return networks if networks else ["192.168.1.0/24"]


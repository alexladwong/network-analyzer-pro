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

def monitor_network(self):
    """Monitor network with thread-safe display updates"""
    connection_history = []
    while self.monitoring:
        try:
            connections = psutil.net_connections(kind='inet')
            active = []
            for conn in connections:
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        active.append(f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
                except:
                    continue

            self.root.after(0, self.update_monitor_display, active)
            time.sleep(2)
        except:
            time.sleep(5)

def network_stats(self):
    """Network stats"""
    self.log("Getting network stats...", "TOOL")
    self.tool_output.delete(1.0, tk.END)

    try:
        stats = "📊 Network Statistics\n"
        stats += f"{'=' * 60}\n\n"

        try:
            interfaces = psutil.net_if_addrs()
            stats += "Network Interfaces:\n"
            stats += f"{'-' * 30}\n"
            for name, addrs in list(interfaces.items())[:5]:
                stats += f"  {name}:\n"
                for addr in addrs[:2]:
                    if addr.family == socket.AF_INET:
                        stats += f"    IPv4: {addr.address}\n"
            stats += "\n"
        except:
            pass

        try:
            net_io = psutil.net_io_counters()
            stats += "Network I/O:\n"
            stats += f"{'-' * 30}\n"
            stats += f"  Bytes Sent: {net_io.bytes_sent // 1024 ** 2:,} MB\n"
            stats += f"  Bytes Received: {net_io.bytes_recv // 1024 ** 2:,} MB\n"
            stats += f"  Packets Sent: {net_io.packets_sent:,}\n"
            stats += f"  Packets Received: {net_io.packets_recv:,}\n\n"
        except:
            pass

        try:
            connections = psutil.net_connections()
            stats += f"Active Connections: {len(connections)}\n"
            stats += f"{'-' * 30}\n"
            tcp = len([c for c in connections if c.type == socket.SOCK_STREAM])
            udp = len([c for c in connections if c.type == socket.SOCK_DGRAM])
            stats += f"  TCP: {tcp}\n  UDP: {udp}\n"
        except:
            pass

        self.tool_output.insert(1.0, stats)
        self.log("Network stats displayed", "SUCCESS")
    except Exception as e:
        self.log(f"Network stats error: {str(e)[:50]}", "WARNING")
        self.tool_output.insert(1.0, f"Error: {str(e)[:100]}")

def speed_test(self):
    """Speed test"""
    self.log("Starting speed test...", "TOOL")
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, "📊 Speed Test\n{'='*60}\n")
    threading.Thread(target=self.run_speed_test, daemon=True).start()

def run_speed_test(self):
    """Run speed test with jitter and quality rating"""
    try:
        self.tool_output.insert(1.0, "📊 Speed Test\n{'=' * 60}\n\n")
        self.tool_output.insert(1.0, "📡 Measuring latency (10 pings to 8.8.8.8)...\n")
        self.tool_output.see(tk.END)

        latencies = []
        for i in range(10):
            try:
                ping_time = ping3.ping('8.8.8.8', timeout=2)
                if ping_time:
                    rtt = ping_time * 1000
                    latencies.append(rtt)
                    status = '✅' if rtt < 50 else '⚠️' if rtt < 100 else '❌'
                    self.tool_output.insert(1.0, f"  Ping {i + 1}: {rtt:.1f}ms {status}\n")
                else:
                    self.tool_output.insert(1.0, f"  Ping {i + 1}: Timeout ❌\n")
            except:
                self.tool_output.insert(1.0, f"  Ping {i + 1}: Error\n")
            self.tool_output.see(tk.END)
            self.root.update_idletasks()
            time.sleep(0.5)

        if latencies:
            avg = sum(latencies) / len(latencies)
            min_lat = min(latencies)
            max_lat = max(latencies)
            jitter = max_lat - min_lat
            loss = (10 - len(latencies)) / 10 * 100

            self.tool_output.insert(1.0, f"\n{'=' * 60}\n")
            self.tool_output.insert(1.0, f"📊 Results:\n")
            self.tool_output.insert(1.0, f"  Average: {avg:.1f}ms\n")
            self.tool_output.insert(1.0, f"  Minimum: {min_lat:.1f}ms\n")
            self.tool_output.insert(1.0, f"  Maximum: {max_lat:.1f}ms\n")
            self.tool_output.insert(1.0, f"  Jitter: {jitter:.1f}ms\n")
            self.tool_output.insert(1.0, f"  Packet Loss: {loss:.1f}%\n")

            if avg < 20:
                quality = "🌟 Excellent"
            elif avg < 50:
                quality = "✅ Good"
            elif avg < 100:
                quality = "⚠️ Fair"
            else:
                quality = "❌ Poor"
            self.tool_output.insert(1.0, f"  Quality: {quality}\n")
            self.log(f"Speed test: {avg:.1f}ms, {quality.split()[-1]}", "SUCCESS")
        else:
            self.tool_output.insert(1.0, "\n❌ No responses received\n")
            self.log("Speed test failed - no responses", "ERROR")
    except Exception as e:
        self.log(f"Speed test error: {e}", "ERROR")
        self.tool_output.insert(1.0, f"\n❌ Error: {e}\n")


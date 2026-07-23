"""
dns_monitor module — extracted from main.py
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

def toggle_dns_monitoring(self):
    """Toggle DNS query monitoring on/off"""
    if not SCAPY_AVAILABLE:
        self.log("Scapy required for DNS monitoring", "ERROR")
        messagebox.showinfo("Scapy Required", "DNS monitoring requires Scapy.\nInstall: pip install scapy")
        return

    if self.dns_monitoring:
        self.dns_monitoring = False
        self.parental_dns_btn.config(text="▶ Start DNS Monitor", bg=self.colors['accent'])
        self.log("DNS monitoring stopped", "PARENTAL")
    else:
        self.dns_monitoring = True
        self.parental_dns_btn.config(text="⏹ Stop DNS", bg=self.colors['danger'])
        self.log("Starting DNS monitoring...", "PARENTAL")
        self.parental_activity_text.delete(1.0, tk.END)
        self.parental_activity_text.insert(1.0, "🔞 DNS Monitor Active\n")
        self.parental_activity_text.insert(1.0, f"{'=' * 60}\n")
        self.parental_activity_text.insert(1.0, "Listening for DNS queries...\n\n")
        threading.Thread(target=self.capture_dns_queries, daemon=True).start()
    self.update_parental_stats()

def capture_dns_queries(self):
    """Capture DNS queries using Scapy"""
    if not SCAPY_AVAILABLE:
        return

    def dns_callback(pkt):
        if not self.dns_monitoring:
            return
        try:
            if IP in pkt and UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                timestamp = datetime.now().strftime("%H:%M:%S")
                date_str = datetime.now().strftime("%Y-%m-%d")

                # Try to extract queried domain
                domain = ""
                if hasattr(pkt, 'qd') and pkt.qd:
                    try:
                        domain = pkt.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    except:
                        domain = "Unknown"
                elif Raw in pkt:
                    try:
                        payload = pkt[Raw].load
                        # Simple extraction for DNS queries
                        if len(payload) > 12:
                            qname_start = 12
                            parts = []
                            while qname_start < len(payload):
                                label_len = payload[qname_start]
                                if label_len == 0:
                                    break
                                if label_len > 63:
                                    break
                                qname_start += 1
                                if qname_start + label_len <= len(payload):
                                    parts.append(payload[qname_start:qname_start + label_len].decode('utf-8', errors='ignore'))
                                    qname_start += label_len
                                else:
                                    break
                            if parts:
                                domain = '.'.join(parts)
                    except:
                        pass

                if not domain:
                    return

                # Map device IP to owner/profile
                dev_info = self.known_devices.get(src_ip, {})
                owner = dev_info.get('owner', 'Unknown')
                profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
                device_name = dev_info.get('device_name', src_ip)
                profile = self.parental_profiles.get(profile_name, {})
                blocked_categories = profile.get('block_categories', [])

                # Check domain against block/allow lists
                domain_lower = domain.lower()
                is_blocked = False
                blocked_category = ""
                is_allowed = False

                # Check allowlist first
                if domain_lower in self.content_allowlist or any(d in domain_lower for d in self.content_allowlist):
                    is_allowed = True

                # Check blocklist
                if not is_allowed:
                    if domain_lower in self.content_blocklist or any(d in domain_lower for d in self.content_blocklist):
                        is_blocked = True
                        blocked_category = "manual"

                # Check category blocking
                if not is_blocked and not is_allowed and blocked_categories:
                    for cat in blocked_categories:
                        keywords = self.content_categories.get(cat, [])
                        if any(kw in domain_lower for kw in keywords):
                            is_blocked = True
                            blocked_category = cat
                            break

                # Check curfew
                if not is_blocked and self.parental_settings.get('schedule_active', True):
                    if self.is_curfew_active(profile):
                        is_blocked = True
                        blocked_category = "curfew"

                # Check time limit
                if not is_blocked and profile.get('time_limit', 0) > 0:
                    remaining = self.get_remaining_time(src_ip, profile)
                    if remaining <= 0:
                        is_blocked = True
                        blocked_category = "time_limit"

                # Log the activity
                log_entry = {
                    'time': timestamp,
                    'date': date_str,
                    'ip': src_ip,
                    'domain': domain,
                    'owner': owner,
                    'device_name': device_name,
                    'profile': profile_name,
                    'blocked': is_blocked,
                    'category': blocked_category,
                    'dst_ip': dst_ip,
                    'duration': 1,  # placeholder
                }
                self.activity_log.append(log_entry)
                if is_blocked:
                    self.dns_activity_log.append(log_entry)
                    self.parental_blocked_count += 1

                # Determine category for display
                domain_cat = "Unknown"
                for cat, keywords in self.content_categories.items():
                    if any(kw in domain_lower for kw in keywords):
                        domain_cat = cat.capitalize()
                        break

                # Display on UI with category colors
                cat_icons = {
                    'adult': '🔴', 'violence': '🔴', 'social': '🔵',
                    'gaming': '🟢', 'streaming': '🟡', 'shopping': '🟠',
                    'education': '🟣', 'search': '🔵', 'Unknown': '⚪'
                }
                cat_icon = cat_icons.get(domain_cat.lower(), '⚪')

                if is_blocked:
                    category_tag = f" [{blocked_category}]" if blocked_category else ""
                    line = (f"[{timestamp}] 🛡️ BLOCKED {domain}{category_tag} "
                            f"<- {device_name} ({owner}) [{domain_cat}]\n")
                else:
                    line = (f"[{timestamp}] {cat_icon} {domain} "
                            f"<- {device_name} ({owner}) [{domain_cat}]\n")

                self.parental_activity_text.insert(tk.END, line)
                self.parental_activity_text.see(tk.END)

                # Update blocked attempts treeview
                if is_blocked:
                    self.parental_blocked_tree.insert('', 0, values=(
                        timestamp, device_name, domain, domain_cat, profile_name.capitalize()
                    ))
                    # Keep only last 500 blocked entries
                    while len(self.parental_blocked_tree.get_children()) > 500:
                        self.parental_blocked_tree.delete(
                            self.parental_blocked_tree.get_children()[-1]
                        )

                # Update stats
                self.update_parental_stats()

                # Apply blocking via hosts file if active
                if is_blocked and self.parental_settings.get('block_method') == 'hosts':
                    self._block_via_hosts(domain)

        except Exception as e:
            if self.dns_monitoring:
                self.log(f"DNS capture error: {str(e)[:80]}", "WARNING")

    try:
        self.log("DNS monitor started - listening on port 53", "PARENTAL")
        # Try multi-interface sniffing for macOS with multiple active networks
        try:
            from scapy.all import get_working_ifaces, get_if_list
            try:
                ifaces = [i.name for i in get_working_ifaces()]
            except:
                ifaces = [i for i in get_if_list() if i.startswith(('en', 'bridge', 'eth'))]
            if not ifaces:
                ifaces = get_if_list()
        except:
            ifaces = []
        if ifaces:
            active = [i for i in ifaces if not i.startswith(('lo', 'gif', 'stf', 'utun', 'awdl', 'llw'))][:5]
            if not active:
                active = ifaces[:3]
            self.log(f"DNS monitoring interfaces: {active}", "PARENTAL")
            for iface in active:
                threading.Thread(
                    target=lambda i=iface: sniff(iface=i, filter="udp port 53",
                                                 prn=dns_callback, store=0),
                    daemon=True
                ).start()
            # Keep alive while monitoring
            while self.dns_monitoring:
                time.sleep(1)
        else:
            sniff(filter="udp port 53", prn=dns_callback, store=0)
    except PermissionError:
        self.parental_activity_text.insert(1.0, "\n❌ DNS monitoring requires root privileges.\n")
        self.parental_activity_text.insert(1.0, "Run: sudo python3 main.py\n")
        self.log("DNS monitoring requires root", "ERROR")
    except Exception as e:
        if self.dns_monitoring:
            self.log(f"DNS capture failed: {e}", "ERROR")
    finally:
        if self.dns_monitoring:
            self.dns_monitoring = False
            self.root.after(0, lambda: self.parental_dns_btn.config(
                text="▶ Start DNS Monitor", bg=self.colors['accent']))
            self.update_parental_stats()


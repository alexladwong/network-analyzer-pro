"""
scanner module — extracted from main.py
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

def quick_scan(self):
    """Quick scan"""
    self.log("Starting quick scan (thread pool)...", "SCAN")
    self.scan_status.config(text="Scanning...")
    threading.Thread(target=self.run_quick_scan_threadpool, daemon=True).start()

def run_quick_scan(self):
    """Run quick scan (sequential, all networks, deduplicated)"""
    try:
        self.device_tree.delete(*self.device_tree.get_children())
        self.device_list.delete(*self.device_list.get_children())

        targets = self._get_scan_targets()
        if not targets:
            return

        # Build all IPs using proper CIDR parsing
        all_ips = self._ips_from_targets(targets)
        if not all_ips:
            self.log("No IPs to scan", "WARNING")
            return

        self.scan_progress['maximum'] = len(all_ips)
        devices_found = []
        seen_found = set()

        for idx, ip in enumerate(all_ips):
            try:
                response = ping3.ping(ip, timeout=0.3)
                if response is not None:
                    hostname = self.get_hostname(ip)
                    mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                    vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'

                    if ip not in seen_found:
                        seen_found.add(ip)
                        devices_found.append(ip)
                        status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
                        self.device_tree.insert('', tk.END, values=(
                            ip, hostname, mac, vendor, 'None', status
                        ))
                        self.device_list.insert('', tk.END, values=(
                            ip, hostname, mac, status
                        ))
            except:
                pass
            self.scan_progress['value'] = idx + 1
            self.root.update_idletasks()

        self.scan_progress['value'] = 0
        self.device_count.set(f"{len(devices_found)} devices")
        self.scan_status.config(text=f"Found {len(devices_found)} devices across {len(targets)} network(s)")
        self.update_scan_stats()
        self.root.after(0, self.update_summary)
        self.root.after(0, self.update_system_status)
        self.log(f"Quick scan complete: {len(devices_found)} devices", "SUCCESS")
    except Exception as e:
        self.log(f"Quick scan error: {e}", "ERROR")

def full_scan(self):
    """Full scan with root check"""
    if not SCAPY_AVAILABLE:
        self.log("Scapy not available, using quick scan", "WARNING")
        self.quick_scan()
        return
    if platform.system() != 'Windows' and os.geteuid() != 0:
        self.log("Full scan requires root for ARP packets. Use quick scan instead.", "WARNING")
        self.scan_status.config(text="Need root - use Quick Scan")
        self._show_tool_message("⚠️ Full scan requires root privileges.\n\nRun: sudo python3 main.py\n\nWithout root, use Quick Scan mode instead.")
        return
    self.log("Starting full scan...", "SCAN")
    self.scan_status.config(text="ARP scan in progress...")
    threading.Thread(target=self.run_full_scan, daemon=True).start()

def run_full_scan(self):
    """Run full scan (deduplicated)"""
    try:
        self.device_tree.delete(*self.device_tree.get_children())
        self.device_list.delete(*self.device_list.get_children())

        network = self.network_ip.get()
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        self.scan_progress['maximum'] = 100
        self.scan_progress['value'] = 20

        result = srp(packet, timeout=3, verbose=False)[0]
        self.scan_progress['value'] = 80

        devices_found = []
        seen_ips = set()
        for sent, received in result:
            ip = received.psrc
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            mac = received.hwsrc
            hostname = self.get_hostname(ip)
            vendor = self.get_vendor(mac)
            open_ports = self.scan_common_ports(ip)
            ports_str = ','.join(map(str, open_ports[:5])) if open_ports else 'None'

            devices_found.append(ip)
            status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
            self.device_tree.insert('', tk.END, values=(
                ip, hostname, mac, vendor, ports_str, status
            ))
            self.device_list.insert('', tk.END, values=(
                ip, hostname, mac, status
            ))

        self.scan_progress['value'] = 100
        self.device_count.set(f"{len(devices_found)} devices")
        self.scan_status.config(text=f"Found {len(devices_found)} devices")
        self.update_scan_stats()
        self.root.after(0, self.update_summary)
        self.root.after(0, self.update_system_status)
        self.log(f"Full scan complete: {len(devices_found)} devices", "SUCCESS")
    except Exception as e:
        self.log(f"Full scan error: {e}", "ERROR")

def deep_scan(self):
    """Deep scan"""
    self.log("Starting deep scan...", "SCAN")
    self.scan_status.config(text="Deep scan in progress...")
    threading.Thread(target=self.run_deep_scan, daemon=True).start()

def run_deep_scan(self):
    """Run deep scan across all networks (deduplicated)"""
    try:
        self.device_tree.delete(*self.device_tree.get_children())
        self.device_list.delete(*self.device_list.get_children())

        targets = self._get_scan_targets()
        if not targets:
            return

        all_ips = self._ips_from_targets(targets)
        if not all_ips:
            self.log("No IPs to scan", "WARNING")
            return

        self.scan_progress['maximum'] = len(all_ips)
        devices_found = []
        seen_found = set()

        for idx, ip in enumerate(all_ips):
            try:
                response = ping3.ping(ip, timeout=0.5)
                if response is not None:
                    hostname = self.get_hostname(ip)
                    mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                    vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'

                    open_ports = self.scan_ports(ip, list(range(1, 1025)))
                    ports_str = ','.join(map(str, open_ports[:5])) if open_ports else 'None'

                    if ip not in seen_found:
                        seen_found.add(ip)
                        devices_found.append(ip)
                        status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
                        self.device_tree.insert('', tk.END, values=(
                            ip, hostname, mac, vendor, ports_str, status
                        ))
                        self.device_list.insert('', tk.END, values=(
                            ip, hostname, mac, status
                        ))
            except:
                pass
            self.scan_progress['value'] = idx + 1
            self.root.update_idletasks()

        self.scan_progress['value'] = 0
        self.device_count.set(f"{len(devices_found)} devices")
        self.scan_status.config(text=f"Found {len(devices_found)} devices across {len(targets)} network(s)")
        self.update_scan_stats()
        self.root.after(0, self.update_summary)
        self.root.after(0, self.update_system_status)
        self.log(f"Deep scan complete: {len(devices_found)} devices", "SUCCESS")
    except Exception as e:
        self.log(f"Deep scan error: {e}", "ERROR")

def get_mac_address(self, ip):
    """Get MAC address using multiple methods with fallbacks"""
    # Method 1: Scapy ARP (requires root)
    try:
        if SCAPY_AVAILABLE:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(broadcast / arp_request, timeout=1, verbose=False)[0]
            if answered:
                mac = answered[0][1].hwsrc
                if mac:
                    return mac.upper()
    except:
        pass
    # Method 2: System ARP cache
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=3)
            for line in result.stdout.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                            return part.upper()
        else:
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=3)
            for line in result.stdout.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                            return part.upper()
    except:
        pass
    # Method 3: ping then check ARP table (populates cache)
    try:
        ping3.ping(ip, timeout=1)
        time.sleep(0.1)
        result = subprocess.run(['arp', '-n', ip] if platform.system() != 'Windows' else ['arp', '-a', ip],
                                capture_output=True, text=True, timeout=3)
        for line in result.stdout.split('\n'):
            if ip in line:
                parts = line.split()
                for part in parts:
                    if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                        return part.upper()
    except:
        pass
    # Method 4: Full arp -a scan for neighbor table (macOS/Linux)
    try:
        if platform.system() != 'Windows':
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if ip in line:
                    match = re.search(r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', line)
                    if match:
                        return match.group(1).upper()
    except:
        pass
    return 'Unknown'

def scan_common_ports(self, ip):
    """Scan common ports"""
    common = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
    return self.scan_ports(ip, common)

def scan_ports(self, ip, ports):
    """Scan ports"""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

def get_hostname(self, ip):
    """Get hostname with caching and multiple resolution methods"""
    if not hasattr(self, '_hostname_cache'):
        self._hostname_cache = {}
    if ip in self._hostname_cache:
        return self._hostname_cache[ip]
    # Method 1: Reverse DNS
    try:
        result = socket.gethostbyaddr(ip)
        name = result[0].split('.')[0]
        if name and name != ip:
            self._hostname_cache[ip] = name
            return name
    except (socket.herror, socket.gaierror, OSError):
        pass
    # Method 2: NetBIOS name lookup (Windows)
    if platform.system() == 'Windows':
        try:
            result = subprocess.run(
                ['nbtstat', '-A', ip],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'UNIQUE' in line:
                    name = line.split()[0]
                    self._hostname_cache[ip] = name
                    return name
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    # Method 3: mdns lookup (macOS/Linux)
    if platform.system() != 'Windows':
        try:
            result = subprocess.run(
                ['dns-sd', '-Q', ip, 'ptr', '--timeout', '1'],
                capture_output=True, text=True, timeout=2
            )
            for line in result.stdout.split('\n'):
                if 'PTR' in line and 'local' in line:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        name = parts[-1].split('.')[0]
                        self._hostname_cache[ip] = name
                        return name
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    self._hostname_cache[ip] = 'Unknown'
    return 'Unknown'

def classify_device(self, mac, hostname='', ports=None):
    """Classify device type based on MAC OUI, hostname patterns, and open ports"""
    vendor = self.get_vendor(mac)
    apple_v = ['Apple Inc.', 'Apple']
    samsung_v = ['Samsung']
    google_v = ['Google']
    amazon_v = ['Amazon']
    pc_v = ['Dell', 'HP', 'Lenovo', 'ASUS', 'Acer', 'MSI']
    net_v = ['Cisco', 'Netgear', 'TP-Link', 'Ubiquiti', 'Aruba', 'ZyXEL', 'D-Link', 'Linksys']
    if any(v in vendor for v in apple_v):
        if hostname and any(h in hostname.lower() for h in ['iphone', 'ipad']):
            return 'iPad' if 'iPad' in hostname else 'iPhone'
        return 'Apple Device'
    elif any(v in vendor for v in samsung_v):
        return 'Samsung Device'
    elif any(v in vendor for v in google_v):
        return 'Google Home' if any(x in hostname.lower() for x in ['nest', 'home']) else 'Google Device'
    elif any(v in vendor for v in amazon_v):
        return 'Amazon Device'
    elif any(v in vendor for v in net_v):
        return 'Router/AP' if ports and 80 in ports else 'Network Device'
    elif any(v in vendor for v in pc_v):
        return 'Desktop' if ports and 3389 in ports else 'Laptop'
    elif 'Raspberry' in vendor:
        return 'Raspberry Pi'
    elif 'Microsoft' in vendor:
        return 'Xbox' if 'xbox' in hostname.lower() else 'Windows Device'
    elif 'Sony' in vendor:
        return 'PlayStation'
    elif 'LG' in vendor or 'Samsung' in vendor:
        return 'Smart TV'
    if hostname:
        hl = hostname.lower()
        if any(x in hl for x in ['phone', 'iphone', 'android', 'galaxy']):
            return 'Phone'
        elif any(x in hl for x in ['ipad', 'tablet']):
            return 'Tablet'
        elif any(x in hl for x in ['laptop', 'notebook', 'macbook']):
            return 'Laptop'
        elif any(x in hl for x in ['desktop', 'pc', 'desk']):
            return 'Desktop'
        elif any(x in hl for x in ['playstation', 'ps4', 'ps5', 'xbox', 'nintendo', 'switch']):
            return 'Gaming Console'
        elif any(x in hl for x in ['tv', 'television', 'roku', 'firestick', 'chromecast']):
            return 'Smart TV'
        elif any(x in hl for x in ['printer', 'brother', 'hp ', 'epson', 'canon']):
            return 'Printer'
    if ports:
        if 80 in ports or 443 in ports:
            return 'Server' if 22 in ports else 'Web Device'
    return 'Unknown Device'

def get_vendor(self, mac):
    """Get vendor from MAC with comprehensive OUI database"""
    if not hasattr(self, '_oui_db'):
        self._init_oui_db()
    if mac == 'Unknown':
        return 'Unknown'
    clean = mac.replace(':', '').replace('-', '').upper()
    if len(clean) < 6:
        return 'Unknown'
    oui = clean[:6]
    vendor = self._oui_db.get(oui)
    if vendor:
        return vendor
    # Fallback: check colon-separated OUI database
    if hasattr(self, '_oui_db_colon'):
        oui_colon = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
        vendor = self._oui_db_colon.get(oui_colon)
        if vendor:
            return vendor
    return 'Unknown'

def _init_oui_db(self):
    """Initialize comprehensive OUI vendor database"""
    self._oui_db = {
        '001B63': 'Apple Inc.', '001E52': 'Apple Inc.', '00251F': 'Apple Inc.',
        '0025BC': 'Apple Inc.', 'AC293A': 'Apple Inc.', '3C0754': 'Apple Inc.',
        '38C986': 'Apple Inc.', '4C3275': 'Apple Inc.', '600308': 'Apple Inc.',
        'C82A14': 'Apple Inc.', 'F01898': 'Apple Inc.', '10051A': 'Apple Inc.',
        '784F43': 'Apple Inc.', '7C11BE': 'Apple Inc.', '7C6A8D': 'Apple Inc.',
        '843835': 'Apple Inc.', '8C8590': 'Apple Inc.', 'A4D1D2': 'Apple Inc.',
        'B8E856': 'Apple Inc.', 'C09879': 'Apple Inc.', 'E02BE9': 'Apple Inc.',
        'F0F61C': 'Apple Inc.', 'D023DB': 'Apple Inc.', '0026B0': 'Apple Inc.',
        '0026BB': 'Apple Inc.', '0023DF': 'Apple Inc.', '0026D0': 'Apple Inc.',
        '8081F7': 'Apple Inc.', '90B0ED': 'Apple Inc.', 'A82066': 'Apple Inc.',
        'ACE010': 'Apple Inc.', 'B0B2DC': 'Apple Inc.', 'B8C7A5': 'Apple Inc.',
        'C0305B': 'Apple Inc.', 'C809A8': 'Apple Inc.', 'CC863D': 'Apple Inc.',
        'DCA904': 'Apple Inc.', 'E0508B': 'Apple Inc.', 'E81CA0': 'Apple Inc.',
        'F060E6': 'Apple Inc.', 'F0D1A9': 'Apple Inc.', 'F40248': 'Apple Inc.',
        'F8CA40': 'Apple Inc.',
        'D4BF6F': 'Samsung Electronics', '9C0284': 'Samsung Electronics',
        'E063E5': 'Samsung Electronics', '001F90': 'Samsung Electronics',
        '001EC8': 'Samsung Electronics', '0021CD': 'Samsung Electronics',
        '0050F2': 'Samsung Electronics', '080064': 'Samsung Electronics',
        '0C74C2': 'Samsung Electronics', '1C66AA': 'Samsung Electronics',
        '242E40': 'Samsung Electronics', '2C102B': 'Samsung Electronics',
        '3497F6': 'Samsung Electronics', '3C5A37': 'Samsung Electronics',
        '4C519E': 'Samsung Electronics', '5488E5': 'Samsung Electronics',
        '601943': 'Samsung Electronics', '644BC7': 'Samsung Electronics',
        '6C2E33': 'Samsung Electronics', '74F065': 'Samsung Electronics',
        '7C110B': 'Samsung Electronics', '8019F8': 'Samsung Electronics',
        '8C7712': 'Samsung Electronics', '9828B7': 'Samsung Electronics',
        'A884F7': 'Samsung Electronics', 'AC5F3E': 'Samsung Electronics',
        'B07908': 'Samsung Electronics', 'BC2C6D': 'Samsung Electronics',
        'C4F312': 'Samsung Electronics', 'D03742': 'Samsung Electronics',
        'E07515': 'Samsung Electronics', 'EC3091': 'Samsung Electronics',
        'F09454': 'Samsung Electronics', 'F848C4': 'Samsung Electronics',
        'F4F5D8': 'Google Inc.', '3C5AB4': 'Google Inc.', '18B430': 'Google Inc.',
        '8C6E8E': 'Google Inc.', 'A47733': 'Google Inc.', 'B4D5BD': 'Google Inc.',
        '10A932': 'Google Inc.', '14EB33': 'Google Inc.', '1C2B6C': 'Google Inc.',
        '2872F0': 'Google Inc.', '2CF0A2': 'Google Inc.', '38F7B2': 'Google Inc.',
        '3CE5A6': 'Google Inc.', '4860BC': 'Google Inc.', '50A6E6': 'Google Inc.',
        '548998': 'Google Inc.', '5C0206': 'Google Inc.', '688E9E': 'Google Inc.',
        '6C541B': 'Google Inc.', '7059A6': 'Google Inc.', '746A8B': 'Google Inc.',
        '7CC537': 'Google Inc.', '849964': 'Google Inc.', '88035B': 'Google Inc.',
        '8C8EA2': 'Google Inc.', 'A4353D': 'Google Inc.', 'A89FBA': 'Google Inc.',
        'ACB640': 'Google Inc.', 'B0A737': 'Google Inc.', 'BC0F2B': 'Google Inc.',
        'C8D15E': 'Google Inc.', 'D08DDF': 'Google Inc.', 'D4F93C': 'Google Inc.',
        'E0D31A': 'Google Inc.', 'F099BF': 'Google Inc.',
        'F89E94': 'Amazon Tech', 'AC63BE': 'Amazon Tech', '40B434': 'Amazon Tech',
        '48188D': 'Amazon Tech', '747548': 'Amazon Tech', '88665A': 'Amazon Tech',
        '00A07B': 'Amazon Tech', '047D50': 'Amazon Tech', '0C47C9': 'Amazon Tech',
        '10300A': 'Amazon Tech', '1C9919': 'Amazon Tech', '288915': 'Amazon Tech',
        '2C33F7': 'Amazon Tech', '3812FF': 'Amazon Tech', '44B271': 'Amazon Tech',
        '4C21D0': 'Amazon Tech', '506F9A': 'Amazon Tech', '543A1B': 'Amazon Tech',
        '60380F': 'Amazon Tech', '64AE0C': 'Amazon Tech', '68F728': 'Amazon Tech',
        '74C246': 'Amazon Tech', '78C2C0': 'Amazon Tech', '7CE9D3': 'Amazon Tech',
        '8410D0': 'Amazon Tech', '84D6D0': 'Amazon Tech', '8CAAB5': 'Amazon Tech',
        '9404D6': 'Amazon Tech', 'A01FB1': 'Amazon Tech', 'A40CC3': 'Amazon Tech',
        'B0F11C': 'Amazon Tech', 'B461FF': 'Amazon Tech', 'BCA9D6': 'Amazon Tech',
        'C84C75': 'Amazon Tech', 'D08737': 'Amazon Tech', 'DC7810': 'Amazon Tech',
        'E02F6D': 'Amazon Tech', 'E447E4': 'Amazon Tech', 'E872EA': 'Amazon Tech',
        'F09CBB': 'Amazon Tech',
        '00155D': 'Microsoft Corp.', '281878': 'Microsoft Corp.', '0003FF': 'Microsoft Corp.',
        '0022B3': 'Microsoft Corp.', '002442': 'Microsoft Corp.', '00254B': 'Microsoft Corp.',
        '0026A1': 'Microsoft Corp.', '002791': 'Microsoft Corp.', '0029D7': 'Microsoft Corp.',
        '002A36': 'Microsoft Corp.', '002C89': 'Microsoft Corp.', '002DE7': 'Microsoft Corp.',
        '002F20': 'Microsoft Corp.', '0030D3': 'Microsoft Corp.', '0033DE': 'Microsoft Corp.',
        '0034D4': 'Microsoft Corp.', '0039DC': 'Microsoft Corp.', '003B7D': 'Microsoft Corp.',
        '003F01': 'Microsoft Corp.', '004019': 'Microsoft Corp.', '004138': 'Microsoft Corp.',
        '004557': 'Microsoft Corp.', '004734': 'Microsoft Corp.', '004A60': 'Microsoft Corp.',
        '0051AF': 'Microsoft Corp.', '005B01': 'Microsoft Corp.', '005CBD': 'Microsoft Corp.',
        '0060B3': 'Microsoft Corp.', '00616A': 'Microsoft Corp.', '00652A': 'Microsoft Corp.',
        '042AE2': 'Microsoft Corp.', '048C03': 'Microsoft Corp.', '04A01E': 'Microsoft Corp.',
        '0C54B9': 'Microsoft Corp.', '10D0A4': 'Microsoft Corp.', '14A62C': 'Microsoft Corp.',
        '14ABD5': 'Microsoft Corp.', '18D66A': 'Microsoft Corp.', '1C5C55': 'Microsoft Corp.',
        '1CF065': 'Microsoft Corp.', '2002AF': 'Microsoft Corp.', '24E917': 'Microsoft Corp.',
        '28D244': 'Microsoft Corp.', '2CAE24': 'Microsoft Corp.', '2CD1CC': 'Microsoft Corp.',
        '30222B': 'Microsoft Corp.', '34A183': 'Microsoft Corp.', '38B12E': 'Microsoft Corp.',
        '3C0CE8': 'Microsoft Corp.', '404A03': 'Microsoft Corp.', '44AF28': 'Microsoft Corp.',
        '48F97C': 'Microsoft Corp.', '4C76A2': 'Microsoft Corp.', '4CC752': 'Microsoft Corp.',
        '507781': 'Microsoft Corp.', '58486A': 'Microsoft Corp.', '58C624': 'Microsoft Corp.',
        '600292': 'Microsoft Corp.', '6405DD': 'Microsoft Corp.', '68050A': 'Microsoft Corp.',
        '6C886B': 'Microsoft Corp.', '705DCC': 'Microsoft Corp.', '781921': 'Microsoft Corp.',
        '78D6F0': 'Microsoft Corp.', '800B51': 'Microsoft Corp.', '842BFB': 'Microsoft Corp.',
        '883600': 'Microsoft Corp.', '8C1F94': 'Microsoft Corp.', '90F052': 'Microsoft Corp.',
        '98D6F8': 'Microsoft Corp.', 'A0CE4E': 'Microsoft Corp.', 'A43A22': 'Microsoft Corp.',
        '001AA0': 'Cisco Systems', '001442': 'Cisco Systems', '00145C': 'Cisco Systems',
        '00175A': 'Cisco Systems', '001B0C': 'Cisco Systems', '001F6C': 'Cisco Systems',
        '002414': 'Cisco Systems', '080069': 'Cisco Systems', '000B5F': 'Cisco Systems',
        '000B85': 'Cisco Systems', '000BB0': 'Cisco Systems', '000C85': 'Cisco Systems',
        '000CCE': 'Cisco Systems', '000D29': 'Cisco Systems', '000DBC': 'Cisco Systems',
        '000E38': 'Cisco Systems', '000E83': 'Cisco Systems', '000ED7': 'Cisco Systems',
        '000F34': 'Cisco Systems', '000F8F': 'Cisco Systems', '000FFE': 'Cisco Systems',
        '001019': 'Cisco Systems', '001053': 'Cisco Systems', '0010F9': 'Cisco Systems',
        '001125': 'Cisco Systems', '001150': 'Cisco Systems', '0011BB': 'Cisco Systems',
        '0011FC': 'Cisco Systems', '001223': 'Cisco Systems', '001279': 'Cisco Systems',
        '0012D9': 'Cisco Systems', '00131A': 'Cisco Systems', '00137C': 'Cisco Systems',
        '0013C4': 'Cisco Systems', '00141C': 'Cisco Systems', '00146A': 'Cisco Systems',
        '0014DC': 'Cisco Systems', '00151C': 'Cisco Systems', '001590': 'Cisco Systems',
        '0015F1': 'Cisco Systems', '001632': 'Cisco Systems', '001699': 'Cisco Systems',
        '0016C8': 'Cisco Systems', '001725': 'Cisco Systems', '001795': 'Cisco Systems',
        '0017D6': 'Cisco Systems', '001836': 'Cisco Systems', '00189D': 'Cisco Systems',
        '0018EE': 'Cisco Systems', '001960': 'Cisco Systems', '0019AD': 'Cisco Systems',
        '001A2F': 'Cisco Systems', '001A6C': 'Cisco Systems', '001AE9': 'Cisco Systems',
        '001B2A': 'Cisco Systems', '001B8C': 'Cisco Systems', '001CBC': 'Cisco Systems',
        '001D45': 'Cisco Systems', '001DA1': 'Cisco Systems', '001E7C': 'Cisco Systems',
        '001EBD': 'Cisco Systems', '001F3B': 'Cisco Systems', '001F9D': 'Cisco Systems',
        '001FF6': 'Cisco Systems', '002062': 'Cisco Systems', '002110': 'Cisco Systems',
        '00215B': 'Cisco Systems', '0021C2': 'Cisco Systems', '00223B': 'Cisco Systems',
        '0022BD': 'Cisco Systems', '0022CB': 'Cisco Systems', '00238C': 'Cisco Systems',
        '0023EA': 'Cisco Systems', '00244E': 'Cisco Systems', '0024B4': 'Cisco Systems',
        '001372': 'Intel Corp.', '001B21': 'Intel Corp.', '001E65': 'Intel Corp.',
        '00216B': 'Intel Corp.', '0024D6': 'Intel Corp.', 'F89E94': 'Intel Corp.',
        '002185': 'Intel Corp.', 'A0369F': 'Intel Corp.', 'A0481C': 'Intel Corp.',
        'B49682': 'Intel Corp.', 'D05099': 'Intel Corp.', 'F48E38': 'Intel Corp.',
        '14CFE2': 'TP-Link Tech', '30B5C2': 'TP-Link Tech', '50C7BF': 'TP-Link Tech',
        '54E6FC': 'TP-Link Tech', '84D81B': 'TP-Link Tech', 'A8574E': 'TP-Link Tech',
        'C04A00': 'TP-Link Tech', 'D80D17': 'TP-Link Tech', 'E848B8': 'TP-Link Tech',
        'F88E85': 'TP-Link Tech',
        '000FB5': 'Netgear Inc.', '20E52A': 'Netgear Inc.', '2C356B': 'Netgear Inc.',
        '5C55AE': 'Netgear Inc.', '6CB0CE': 'Netgear Inc.', 'A021B7': 'Netgear Inc.',
        'C03F0E': 'Netgear Inc.', 'E09153': 'Netgear Inc.',
        '001422': 'Dell Inc.', '001E4F': 'Dell Inc.', '180373': 'Dell Inc.',
        '3497F6': 'Dell Inc.', '5C260A': 'Dell Inc.', 'F01FAF': 'Dell Inc.',
        '0017A4': 'HP Inc.', '001CC4': 'HP Inc.', '1867B0': 'HP Inc.',
        '3CD92B': 'HP Inc.', '68B599': 'HP Inc.', '9CB654': 'HP Inc.',
        '001A4B': 'Lenovo Group', '002844': 'Lenovo Group', '3863BB': 'Lenovo Group',
        'B0C090': 'Lenovo Group', 'E0D4E8': 'Lenovo Group',
        '001BFC': 'ASUStek', '107C61': 'ASUStek', '90840D': 'ASUStek',
        '94D9B3': 'ASUStek', 'AC220B': 'ASUStek', 'D43D7E': 'ASUStek',
        '186FD3': 'Xiaomi Inc.', '28CFE9': 'Xiaomi Inc.', '9CF48B': 'Xiaomi Inc.',
        'AC3743': 'Xiaomi Inc.', 'F0B429': 'Xiaomi Inc.',
        '001DBA': 'Sony Corp.', '4CEB42': 'Sony Corp.', '649EF3': 'Sony Corp.',
        'AC0A61': 'Sony Corp.',
        '001E66': 'LG Electronics', '3CCE73': 'LG Electronics', 'ACBC32': 'LG Electronics',
        'F8D111': 'LG Electronics',
        '00156D': 'Ubiquiti Networks', '0418D6': 'Ubiquiti Networks',
        '24A43C': 'Ubiquiti Networks', '687251': 'Ubiquiti Networks',
        '7483C2': 'Ubiquiti Networks', 'D0214D': 'Ubiquiti Networks',
        'E063DA': 'Ubiquiti Networks',
        '000B86': 'Aruba Networks', '1C1B68': 'Aruba Networks',
        '84D446': 'Aruba Networks', 'D8C497': 'Aruba Networks',
        '001349': 'ZyXEL Comm.', '20CF30': 'ZyXEL Comm.',
        '58971E': 'ZyXEL Comm.', 'B075D5': 'ZyXEL Comm.',
        'B827EB': 'Raspberry Pi Foundation', 'DCA632': 'Raspberry Pi Foundation',
        'E45F01': 'Raspberry Pi Foundation',
        '000C29': 'VMware Inc.', '005056': 'VMware Inc.', '001C42': 'Parallels/VMware',
        '080027': 'Oracle/VirtualBox',
        '000393': 'Apple',
        '000502': 'Apple',
        '000A27': 'Apple',
        '000C15': 'Apple',
        '000D93': 'Apple',
        '0010FA': 'Apple',
        '001124': 'Apple',
        '001451': 'Apple',
        '0016CB': 'Apple',
        '0017F2': 'Apple',
        '0019E3': 'Apple',
        '001B63': 'Apple',
        '001CB3': 'Apple',
        '001D4F': 'Apple',
        '001E52': 'Apple',
        '001F03': 'Apple',
        '001FF3': 'Apple',
        '002332': 'Apple',
        '002436': 'Apple',
        '002500': 'Apple',
        '0025BC': 'Apple',
        '002608': 'Apple',
        '00264A': 'Apple',
        '0026BB': 'Apple',
        '00270C': 'Apple',
        '002764': 'Apple',
        '0027D0': 'Apple',
        '003065': 'Apple',
        '003090': 'Apple',
        '003EE1': 'Apple',
        '0050E2': 'Apple',
        '005BBA': 'Apple',
        '006171': 'Apple',
        '006D52': 'Apple',
        '007DDF': 'Apple',
        '008FCA': 'Apple',
        '00900C': 'Apple',
        '00A040': 'Apple',
        '00B03C': 'Apple',
        '00C006': 'Apple',
        '00D059': 'Apple',
        '00E04C': 'Apple',
        '00F064': 'Apple',
        '040CCE': 'Apple',
        '041552': 'Apple',
        '041BBA': 'Apple',
        '04241C': 'Apple',
        '042548': 'Apple',
        '042C05': 'Apple',
        '043582': 'Apple',
        '046C59': 'Apple',
        '048FEC': 'Apple',
        '049226': 'Apple',
        '049A16': 'Apple',
        '04B167': 'Apple',
        '04B434': 'Apple',
        '04B715': 'Apple',
        '04B7C3': 'Apple',
        '04D4C4': 'Apple',
        '04D9F5': 'Apple',
        '04DE3E': 'Apple',
        '04DF6D': 'Apple',
        '04E676': 'Apple',
        '04E954': 'Apple',
        '04EA56': 'Apple',
        '04F13E': 'Apple',
        '04F55C': 'Apple',
        '04F8E8': 'Apple',
        '04FA65': 'Apple',
        '04FE31': 'Apple',
        '080007': 'Apple',
        '084F0C': 'Apple',
        '0866AB': 'Apple',
        '086D41': 'Apple',
        '0870D0': 'Apple',
        '087893': 'Apple',
        '0881F4': 'Apple',
        '088756': 'Apple',
        '08882C': 'Apple',
        '08893D': 'Apple',
        '089834': 'Apple',
        '089B4B': 'Apple',
        '089E01': 'Apple',
        '08A21C': 'Apple',
        '08A284': 'Apple',
        '08A95B': 'Apple',
        '08B13B': 'Apple',
        '08B491': 'Apple',
        '08B61F': 'Apple',
        '08BA2B': 'Apple',
        '08BD43': 'Apple',
        '08BE6D': 'Apple',
        '08C12C': 'Apple',
        '08C33C': 'Apple',
        '08C428': 'Apple',
        '08C71E': 'Apple',
        '08C736': 'Apple',
        '08C836': 'Apple',
        '08CB8B': 'Apple',
        '08CC68': 'Apple',
        '08CD9B': 'Apple',
        '08CF3A': 'Apple',
        '08D09F': 'Apple',
        '08D119': 'Apple',
        '08D23A': 'Apple',
        '08D27A': 'Apple',
        '08D463': 'Apple',
        '08D633': 'Apple',
        '08D81A': 'Apple',
        '08D833': 'Apple',
        '08D91B': 'Apple',
        '08DA8E': 'Apple',
        '08DD0E': 'Apple',
        '08DE3A': 'Apple',
        '08E044': 'Apple',
        '08E12A': 'Apple',
        '08E22C': 'Apple',
        '08E30C': 'Apple',
        '08E6EA': 'Apple',
        '08E8F7': 'Apple',
        '08E929': 'Apple',
        '08EA44': 'Apple',
        '08ECF5': 'Apple',
        '08EEDE': 'Apple',
        '08EF20': 'Apple',
        '08F03D': 'Apple',
        '08F1EA': 'Apple',
        '08F28D': 'Apple',
        '08F55C': 'Apple',
        '08F650': 'Apple',
        '08F720': 'Apple',
        '08F8E0': 'Apple',
        '08F931': 'Apple',
        '08FAE3': 'Apple',
        '08FC88': 'Apple',
        '08FD0E': 'Apple',
        '08FE8C': 'Apple',
        '0C0438': 'Apple',
        '0C082D': 'Apple',
        '0C0FFB': 'Apple',
        '0C1521': 'Apple',
        '0C167D': 'Apple',
        '0C189E': 'Apple',
        '0C1A73': 'Apple',
        '0C1C31': 'Apple',
        '0C1D0C': 'Apple',
        '0C1D4C': 'Apple',
        '0C1D98': 'Apple',
        '0C1E2B': 'Apple',
        '0C1E3C': 'Apple',
        '0C1E5F': 'Apple',
        '0C1F38': 'Apple',
        '0C1F83': 'Apple',
        '0C2004': 'Apple',
        '0C211F': 'Apple',
        '0C2310': 'Apple',
        '0C2435': 'Apple',
        '0C26B8': 'Apple',
        '0C2751': 'Apple',
        '0C2924': 'Apple',
        '0C293A': 'Apple',
        '0C2A69': 'Apple',
        '0C2C34': 'Apple',
        '0C2D34': 'Apple',
        '0C2E1C': 'Apple',
        '0C2E7F': 'Apple',
        '0C2E8A': 'Apple',
        '0C2F8E': 'Apple',
        '0C301B': 'Apple',
        '0C30B4': 'Apple',
        '0C316E': 'Apple',
        '0C3260': 'Apple',
        '0C3273': 'Apple',
        '0C3343': 'Apple',
        '0C335F': 'Apple',
        '0C3372': 'Apple',
        '0C34B6': 'Apple',
        '0C3647': 'Apple',
        '0C36A5': 'Apple',
        '0C36D7': 'Apple',
        '0C3876': 'Apple',
        '0C38B9': 'Apple',
        '0C3A35': 'Apple',
        '0C3AED': 'Apple',
        '0C3B56': 'Apple',
        '0C3BAE': 'Apple',
        '0C3C01': 'Apple',
        '0C3C5D': 'Apple',
        '0C3D3F': 'Apple',
        '0C3D98': 'Apple',
        '0C3D9A': 'Apple',
        '0C3E6F': 'Apple',
        '0C3F96': 'Apple',
        '0C3FCA': 'Apple',
        '001F90': 'Samsung',
        '041B2C': 'Samsung',
        '041C0A': 'Samsung',
        '041C68': 'Samsung',
        '041F23': 'Samsung',
        '041FE1': 'Samsung',
        '042009': 'Samsung',
        '042130': 'Samsung',
        '04237C': 'Samsung',
        '042728': 'Samsung',
        '04285F': 'Samsung',
        '042870': 'Samsung',
        '042B59': 'Samsung',
        '042C90': 'Samsung',
        '042E08': 'Samsung',
        '042F45': 'Samsung',
        '04306A': 'Samsung',
        '043219': 'Samsung',
        '04345E': 'Samsung',
        '04374C': 'Samsung',
        '043914': 'Samsung',
        '043B9C': 'Samsung',
        '043C34': 'Samsung',
        '043C5B': 'Samsung',
        '043DAA': 'Samsung',
        '043E8F': 'Samsung',
        '043F25': 'Samsung',
        '043F5B': 'Samsung',
        '04404A': 'Samsung',
        '0441D4': 'Samsung',
        '044434': 'Samsung',
        '04452D': 'Samsung',
        '04467E': 'Samsung',
        '044794': 'Samsung',
        '044935': 'Samsung',
        '044A1D': 'Samsung',
        '044B3F': 'Samsung',
        '044C7E': 'Samsung',
        '044D41': 'Samsung',
        '044DFC': 'Samsung',
        '044E3A': 'Samsung',
        '044F9F': 'Samsung',
        '045086': 'Samsung',
        '04513B': 'Samsung',
        '045174': 'Samsung',
        '045240': 'Samsung',
        '0452C5': 'Samsung',
        '04531D': 'Samsung',
        '0453C7': 'Samsung',
        '0454BA': 'Samsung',
        '04555D': 'Samsung',
        '045643': 'Samsung',
        '04566B': 'Samsung',
        '045757': 'Samsung',
        '045794': 'Samsung',
        '04582D': 'Samsung',
        '04584F': 'Samsung',
        '0459A1': 'Samsung',
        '045A02': 'Samsung',
        '045A3F': 'Samsung',
        '045ACE': 'Samsung',
        '045B11': 'Samsung',
        '045B1A': 'Samsung',
        '045B3C': 'Samsung',
        '045C1A': 'Samsung',
        '045C9D': 'Samsung',
        '045D09': 'Samsung',
        '045DC5': 'Samsung',
        '045E45': 'Samsung',
        '045FA9': 'Samsung',
        '046073': 'Samsung',
        '0460E0': 'Samsung',
        '046139': 'Samsung',
        '046147': 'Samsung',
        '0461D8': 'Samsung',
        '04627C': 'Samsung',
        '046289': 'Samsung',
        '046339': 'Samsung',
        'D4BF6F': 'Google',
        'F89E94': 'Google',
        'F4F5D8': 'Google',
        'FCA89A': 'Google',
        'AC220B': 'Google',
        '747548': 'Amazon',
        'F01898': 'Amazon',
        '54BF64': 'Amazon',
        'B06EBF': 'Amazon',
        'B49CDF': 'Amazon',
        'D0ABD5': 'Amazon',
        '1C1C15': 'Amazon',
        '1C3A6C': 'Amazon',
        '1CBFCE': 'Amazon',
        '2421AB': 'Amazon',
        '286A38': 'Amazon',
        '2C44FD': 'Amazon',
        '2C550E': 'Amazon',
        '340286': 'Amazon',
        '34D017': 'Amazon',
        '385351': 'Amazon',
        '38D25C': 'Amazon',
        '3C15C2': 'Amazon',
        '3C3D30': 'Amazon',
        '3C7901': 'Amazon',
        '3C9D0B': 'Amazon',
        '3C9E05': 'Amazon',
        '3CF81B': 'Amazon',
        '405007': 'Amazon',
        '4051A6': 'Amazon',
        '405C33': 'Amazon',
        '40B076': 'Amazon',
        '40C5A6': 'Amazon',
        '40E70A': 'Amazon',
        '440965': 'Amazon',
        '44237C': 'Amazon',
        '44253B': 'Amazon',
        '442C81': 'Amazon',
        '44360B': 'Amazon',
        '443B86': 'Amazon',
        '443C6F': 'Amazon',
        '44445E': 'Amazon',
        '444512': 'Amazon',
        '44461A': 'Amazon',
        '4447AB': 'Amazon',
        '444925': 'Amazon',
        '444CCD': 'Amazon',
        '444D7E': 'Amazon',
        '444E1E': 'Amazon',
        '444F54': 'Amazon',
        '445025': 'Amazon',
        '44520A': 'Amazon',
        '44526C': 'Amazon',
        '44537C': 'Amazon',
        '445508': 'Amazon',
        '445593': 'Amazon',
        '4456A8': 'Amazon',
        '445756': 'Amazon',
        '4458EE': 'Amazon',
        '4459E3': 'Amazon',
        '445A6E': 'Amazon',
        '445B5A': 'Amazon',
        '445C3F': 'Amazon',
        '445E74': 'Amazon',
        '446002': 'Amazon',
        '00155D': 'Microsoft',
        '001CAE': 'Microsoft',
        '001DD8': 'Microsoft',
        '001F3E': 'Microsoft',
        '00202F': 'Microsoft',
        '0023AE': 'Microsoft',
        '002417': 'Microsoft',
        '00254D': 'Microsoft',
        '002612': 'Microsoft',
        '00263C': 'Microsoft',
        '0026DB': 'Microsoft',
        '002710': 'Microsoft',
        '00271D': 'Microsoft',
        '0028A3': 'Microsoft',
        '002914': 'Microsoft',
        '002A9D': 'Microsoft',
        '002B6D': 'Microsoft',
        '002CD9': 'Microsoft',
        '002D59': 'Microsoft',
        '002E9E': 'Microsoft',
        '002FC8': 'Microsoft',
        '0030AB': 'Microsoft',
        '00312A': 'Microsoft',
        '003243': 'Microsoft',
        '003371': 'Microsoft',
        '003453': 'Microsoft',
        '003514': 'Microsoft',
        '003676': 'Microsoft',
        '00371A': 'Microsoft',
        '003836': 'Microsoft',
        '003911': 'Microsoft',
        '003A5C': 'Microsoft',
        '003B6C': 'Microsoft',
        '003C15': 'Microsoft',
        '003D25': 'Microsoft',
        '003EAB': 'Microsoft',
        '003F5B': 'Microsoft',
        '00408C': 'Microsoft',
        '00416A': 'Microsoft',
        '004278': 'Microsoft',
        '004387': 'Microsoft',
        '004444': 'Microsoft',
        '0045A2': 'Microsoft',
        '004671': 'Microsoft',
        '00478E': 'Microsoft',
        '004819': 'Microsoft',
        '004974': 'Microsoft',
        '004A1A': 'Microsoft',
        '001AA0': 'Cisco',
        '001C42': 'Cisco',
        '001D45': 'Cisco',
        '001E14': 'Cisco',
        '001F4C': 'Cisco',
        '00200F': 'Cisco',
        '00214D': 'Cisco',
        '00224E': 'Cisco',
        '00234B': 'Cisco',
        '002419': 'Cisco',
        '0025A8': 'Cisco',
        '00264D': 'Cisco',
        '00271E': 'Cisco',
        '00283B': 'Cisco',
        '002958': 'Cisco',
        '002A2B': 'Cisco',
        '002B67': 'Cisco',
        '002C5E': 'Cisco',
        '002D18': 'Cisco',
        '002E18': 'Cisco',
        '002F3A': 'Cisco',
        '003012': 'Cisco',
        '00311B': 'Cisco',
        '00327C': 'Cisco',
        '0033AB': 'Cisco',
        '003484': 'Cisco',
        '00351A': 'Cisco',
        '00363B': 'Cisco',
        '00372C': 'Cisco',
        '003821': 'Cisco',
        '00390E': 'Cisco',
        '003A5E': 'Cisco',
        '003B5C': 'Cisco',
        '003C1E': 'Cisco',
        '003D94': 'Cisco',
        '003EE5': 'Cisco',
        '003F8A': 'Cisco',
        '004016': 'Cisco',
        '0041AE': 'Cisco',
        '004217': 'Cisco',
        '00436E': 'Cisco',
        '004468': 'Cisco',
        '00451D': 'Cisco',
        '004664': 'Cisco',
        '00478D': 'Cisco',
        '0048FA': 'Cisco',
        '00493A': 'Cisco',
        '004A79': 'Cisco',
        '001372': 'Intel',
        '001500': 'Intel',
        '00163E': 'Intel',
        '00172C': 'Intel',
        '00180E': 'Intel',
        '00198D': 'Intel',
        '001A6B': 'Intel',
        '001B21': 'Intel',
        '001B77': 'Intel',
        '001CBF': 'Intel',
        '001D09': 'Intel',
        '001DE8': 'Intel',
        '001E37': 'Intel',
        '001E64': 'Intel',
        '001EAB': 'Intel',
        '001F3A': 'Intel',
        '001FD8': 'Intel',
        '00206B': 'Intel',
        '00215A': 'Intel',
        '002186': 'Intel',
        '00222A': 'Intel',
        '0022FA': 'Intel',
        '002347': 'Intel',
        '0023CD': 'Intel',
        '00242B': 'Intel',
        '0024AB': 'Intel',
        '002548': 'Intel',
        '00259C': 'Intel',
        '0025DB': 'Intel',
        '002601': 'Intel',
        '002686': 'Intel',
        '00270E': 'Intel',
        '00278C': 'Intel',
        '00282E': 'Intel',
        '00289E': 'Intel',
        '00291C': 'Intel',
        '00299E': 'Intel',
        '002A0A': 'Intel',
        '002A98': 'Intel',
        '002B1C': 'Intel',
        '002B9A': 'Intel',
        '002C0C': 'Intel',
        '000C29': 'VMware',
        '005056': 'VMware',
        '000569': 'VMware',
        '001C42': 'VMware',
        '001CD0': 'VMware',
        '001D3B': 'VMware',
        '001E28': 'VMware',
        '001F3A': 'VMware',
        '002020': 'VMware',
        '00210A': 'VMware',
        '002148': 'VMware',
        '00220F': 'VMware',
        '00225C': 'VMware',
        '00230D': 'VMware',
        '002335': 'VMware',
        '002367': 'VMware',
        '002383': 'VMware',
        '0023AF': 'VMware',
        '0023C6': 'VMware',
        '0023E0': 'VMware',
        '00244B': 'VMware',
        '00246D': 'VMware',
        '00250B': 'VMware',
        '002514': 'VMware',
        '00251F': 'VMware',
        '002541': 'VMware',
        '00257C': 'VMware',
        '00258D': 'VMware',
        '0025A0': 'VMware',
        '0025B2': 'VMware',
        '0025C3': 'VMware',
        '0025D1': 'VMware',
        '0025E0': 'VMware',
        '04BF6D': 'Xiaomi',
        '0C1C95': 'Xiaomi',
        '0CF99E': 'Xiaomi',
        '143C12': 'Xiaomi',
        '143C4E': 'Xiaomi',
        '143C6A': 'Xiaomi',
        '143C90': 'Xiaomi',
        '143CA0': 'Xiaomi',
        '143CE1': 'Xiaomi',
        '143CF6': 'Xiaomi',
        '183C0B': 'Xiaomi',
        '183C2F': 'Xiaomi',
        '183C4E': 'Xiaomi',
        '183C6F': 'Xiaomi',
        '183C98': 'Xiaomi',
        '183CA5': 'Xiaomi',
        '183CB4': 'Xiaomi',
        '183CDA': 'Xiaomi',
        '183CE6': 'Xiaomi',
        '183CF8': 'Xiaomi',
        '1C3C0F': 'Xiaomi',
        '1C3C27': 'Xiaomi',
        '1C3C3C': 'Xiaomi',
        '1C3C54': 'Xiaomi',
        '1C3C6E': 'Xiaomi',
        '1C3C81': 'Xiaomi',
        '1C3C9A': 'Xiaomi',
        '1C3CB2': 'Xiaomi',
        '1C3CCD': 'Xiaomi',
        '1C3CE4': 'Xiaomi',
        '1C3CF9': 'Xiaomi',
        '203C1B': 'Xiaomi',
        '203C30': 'Xiaomi',
        '203C48': 'Xiaomi',
        '203C62': 'Xiaomi',
        '203C7C': 'Xiaomi',
        '203C98': 'Xiaomi',
        '203CB0': 'Xiaomi',
        '203CCA': 'Xiaomi',
        '203CE4': 'Xiaomi',
        '203CFE': 'Xiaomi',
        '2C3C0B': 'Xiaomi',
        '2C3C24': 'Xiaomi',
        '2C3C40': 'Xiaomi',
        '2C3C5C': 'Xiaomi',
        '2C3C78': 'Xiaomi',
        '2C3C94': 'Xiaomi',
        '2C3CB0': 'Xiaomi',
        '2C3CCC': 'Xiaomi',
        '2C3CE8': 'Xiaomi',
        '2C3CFF': 'Xiaomi',
        '303C0C': 'Xiaomi',
        '303C22': 'Xiaomi',
        '303C3A': 'Xiaomi',
        '303C52': 'Xiaomi',
        '303C6A': 'Xiaomi',
        '303C82': 'Xiaomi',
        '303C9A': 'Xiaomi',
        '303CB2': 'Xiaomi',
        '303CCA': 'Xiaomi',
        '303CE2': 'Xiaomi',
        '303CFA': 'Xiaomi',
        '343C05': 'Xiaomi',
        '343C10': 'Xiaomi',
        '343C1B': 'Xiaomi',
        '343C26': 'Xiaomi',
        '343C31': 'Xiaomi',
        '343C3C': 'Xiaomi',
        '343C47': 'Xiaomi',
        '343C52': 'Xiaomi',
        '343C5D': 'Xiaomi',
        '343C68': 'Xiaomi',
        '343C73': 'Xiaomi',
        '343C7E': 'Xiaomi',
        '343C89': 'Xiaomi',
        '343C94': 'Xiaomi',
        '343C9F': 'Xiaomi',
        '343CAA': 'Xiaomi',
        '343CB5': 'Xiaomi',
        '343CC0': 'Xiaomi',
        '343CCB': 'Xiaomi',
        '343CD6': 'Xiaomi',
        '343CE1': 'Xiaomi',
        '343CEC': 'Xiaomi',
        '343CF7': 'Xiaomi',
        '383C0B': 'Xiaomi',
        '383C1C': 'Xiaomi',
        '001E2A': 'Sony',
        '001FD8': 'Sony',
        '00201A': 'Sony',
        '00212D': 'Sony',
        '00223A': 'Sony',
        '00233D': 'Sony',
        '00242D': 'Sony',
        '00254A': 'Sony',
        '00263A': 'Sony',
        '00273D': 'Sony',
        '00283A': 'Sony',
        '00293D': 'Sony',
        '002A3A': 'Sony',
        '002B3D': 'Sony',
        '002C3A': 'Sony',
        '002D3D': 'Sony',
        '002E3A': 'Sony',
        '002F3D': 'Sony',
        '00303A': 'Sony',
        '00313D': 'Sony',
        '00323A': 'Sony',
        '00333D': 'Sony',
        '00343A': 'Sony',
        '00353D': 'Sony',
        '00363A': 'Sony',
        '00373D': 'Sony',
        '00383A': 'Sony',
        '00393D': 'Sony',
        '003A3A': 'Sony',
        '003B3D': 'Sony',
        '003C3A': 'Sony',
        '003D3D': 'Sony',
        '003E3A': 'Sony',
        '003F3D': 'Sony',
        '00403A': 'Sony',
        '00413D': 'Sony',
        '00423A': 'Sony',
        '00433D': 'Sony',
        '00443A': 'Sony',
        '00453D': 'Sony',
        '00463A': 'Sony',
        '00473D': 'Sony',
        '00483A': 'Sony',
        '00493D': 'Sony',
        '004A3A': 'Sony',
        '004B3D': 'Sony',
        '004C3A': 'Sony',
        '004D3D': 'Sony',
        '004E3A': 'Sony',
        '004F3D': 'Sony',
        '00503A': 'Sony',
        '00513D': 'Sony',
        '00523A': 'Sony',
        '00533D': 'Sony',
        '001E27': 'LG',
        '001F2D': 'LG',
        '00203A': 'LG',
        '00212D': 'LG',
        '00223A': 'LG',
        '00232D': 'LG',
        '00243A': 'LG',
        '00252D': 'LG',
        '00263A': 'LG',
        '00272D': 'LG',
        '00283A': 'LG',
        '00292D': 'LG',
        '002A3A': 'LG',
        '002B2D': 'LG',
        '002C3A': 'LG',
        '002D2D': 'LG',
        '002E3A': 'LG',
        '002F2D': 'LG',
        '00303A': 'LG',
        '00312D': 'LG',
        '00323A': 'LG',
        '00332D': 'LG',
        '00343A': 'LG',
        '00352D': 'LG',
        '00363A': 'LG',
        '00372D': 'LG',
        '00383A': 'LG',
        '00392D': 'LG',
        '003A3A': 'LG',
        '003B2D': 'LG',
        '003C3A': 'LG',
        '003D2D': 'LG',
        '003E3A': 'LG',
        '003F2D': 'LG',
        '00403A': 'LG',
        '00412D': 'LG',
        '00423A': 'LG',
        '00432D': 'LG',
        '00443A': 'LG',
        '00452D': 'LG',
        '00463A': 'LG',
        '00472D': 'LG',
        '00483A': 'LG',
        '00492D': 'LG',
        '004A3A': 'LG',
        '004B2D': 'LG',
        '004C3A': 'LG',
        '004D2D': 'LG',
        '004E3A': 'LG',
        '004F2D': 'LG',
        '00503A': 'LG',
        '00512D': 'LG',
        '00523A': 'LG',
        '00532D': 'LG',
        '001617': 'HP',
        '0017A4': 'HP',
        '001841': 'HP',
        '00192F': 'HP',
        '001A04': 'HP',
        '001AB7': 'HP',
        '001B44': 'HP',
        '001C23': 'HP',
        '001CC6': 'HP',
        '001D09': 'HP',
        '001D72': 'HP',
        '001E0B': 'HP',
        '001E39': 'HP',
        '001F0C': 'HP',
        '001F29': 'HP',
        '001F46': 'HP',
        '002012': 'HP',
        '00202F': 'HP',
        '00204C': 'HP',
        '002069': 'HP',
        '002086': 'HP',
        '0020A3': 'HP',
        '0020C0': 'HP',
        '0020DD': 'HP',
        '0020FA': 'HP',
        '002117': 'HP',
        '002134': 'HP',
        '002151': 'HP',
        '00216E': 'HP',
        '00218B': 'HP',
        '0021A8': 'HP',
        '0021C5': 'HP',
        '0021E2': 'HP',
        '0021FF': 'HP',
        '00221C': 'HP',
        '002239': 'HP',
        '002256': 'HP',
        '002273': 'HP',
        '002290': 'HP',
        '0022AD': 'HP',
        '0022CA': 'HP',
        '0022E7': 'HP',
        '002304': 'HP',
        '002321': 'HP',
        '00233E': 'HP',
        '00235B': 'HP',
        '002378': 'HP',
        '002395': 'HP',
        '0023B2': 'HP',
        '0023CF': 'HP',
        '0023EC': 'HP',
        '00155D': 'Dell',
        '001634': 'Dell',
        '00170B': 'Dell',
        '0017E2': 'Dell',
        '00188B': 'Dell',
        '00191E': 'Dell',
        '0019B1': 'Dell',
        '001A2B': 'Dell',
        '001ABC': 'Dell',
        '001B24': 'Dell',
        '001B35': 'Dell',
        '001B46': 'Dell',
        '001C03': 'Dell',
        '001C14': 'Dell',
        '001C25': 'Dell',
        '001D09': 'Dell',
        '001D1A': 'Dell',
        '001D2B': 'Dell',
        '001D3C': 'Dell',
        '001D4D': 'Dell',
        '001D5E': 'Dell',
        '001D6F': 'Dell',
        '001D80': 'Dell',
        '001D91': 'Dell',
        '001DA2': 'Dell',
        '001DB3': 'Dell',
        '001DC4': 'Dell',
        '001DD5': 'Dell',
        '001DE6': 'Dell',
        '001DF7': 'Dell',
        '001E08': 'Dell',
        '001E19': 'Dell',
        '001E2A': 'Dell',
        '001E3B': 'Dell',
        '001E4C': 'Dell',
        '001E5D': 'Dell',
        '001E6E': 'Dell',
        '001E7F': 'Dell',
        '001E90': 'Dell',
        '001EA1': 'Dell',
        '001EB2': 'Dell',
        '001EC3': 'Dell',
        '001ED4': 'Dell',
        '001EE5': 'Dell',
        '001EF6': 'Dell',
        '001F07': 'Dell',
        '001F18': 'Dell',
        '001F29': 'Dell',
        '001636': 'Lenovo',
        '00165C': 'Lenovo',
        '001697': 'Lenovo',
        '001706': 'Lenovo',
        '001743': 'Lenovo',
        '001794': 'Lenovo',
        '0018F9': 'Lenovo',
        '00197E': 'Lenovo',
        '001A2B': 'Lenovo',
        '001A83': 'Lenovo',
        '001B24': 'Lenovo',
        '001B7C': 'Lenovo',
        '001C25': 'Lenovo',
        '001C7D': 'Lenovo',
        '001D09': 'Lenovo',
        '001D61': 'Lenovo',
        '001D92': 'Lenovo',
        '001E08': 'Lenovo',
        '001E59': 'Lenovo',
        '001E8A': 'Lenovo',
        '001F07': 'Lenovo',
        '001F58': 'Lenovo',
        '001F89': 'Lenovo',
        '001FBA': 'Lenovo',
        '00200C': 'Lenovo',
        '00205D': 'Lenovo',
        '00208E': 'Lenovo',
        '0020BF': 'Lenovo',
        '0020F0': 'Lenovo',
        '002121': 'Lenovo',
        '002152': 'Lenovo',
        '002183': 'Lenovo',
        '0021B4': 'Lenovo',
        '0021E5': 'Lenovo',
        '002216': 'Lenovo',
        '002247': 'Lenovo',
        '002278': 'Lenovo',
        '0022A9': 'Lenovo',
        '0022DA': 'Lenovo',
        '00230B': 'Lenovo',
        '00233C': 'Lenovo',
        '00236D': 'Lenovo',
        '00239E': 'Lenovo',
        '0023CF': 'Lenovo',
        '002400': 'Lenovo',
        '002431': 'Lenovo',
        '002462': 'Lenovo',
        '002493': 'Lenovo',
        '0024C4': 'Lenovo',
        '0024F5': 'Lenovo',
        '002526': 'Lenovo',
    }

def run_quick_scan_threadpool(self):
    """Quick scan with ThreadPoolExecutor — scans all discovered networks (deduplicated)"""
    try:
        self.device_tree.delete(*self.device_tree.get_children())
        self.device_list.delete(*self.device_list.get_children())

        targets = self._get_scan_targets()
        if not targets:
            self.log("No networks to scan", "WARNING")
            return

        # Build list of all IPs across all networks using proper CIDR parsing
        all_ips = self._ips_from_targets(targets)
        if not all_ips:
            self.log("No IPs to scan", "WARNING")
            return

        total_ips = len(all_ips)
        self.scan_progress['maximum'] = total_ips
        self.scan_progress['value'] = 0
        start_time = time.time()
        devices_found = []
        seen_found = set()  # Prevent duplicate insertions

        def ping_ip(ip):
            try:
                response = ping3.ping(ip, timeout=0.3)
                if response is not None:
                    hostname = self.get_hostname(ip)
                    mac = self.get_mac_address(ip) if SCAPY_AVAILABLE else 'Unknown'
                    vendor = self.get_vendor(mac) if mac != 'Unknown' else 'Unknown'
                    return (ip, hostname, mac, vendor)
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_ip, ip): ip for ip in all_ips}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    ip, hostname, mac, vendor = result
                    if ip not in seen_found:
                        seen_found.add(ip)
                        devices_found.append(ip)
                        status = '🌐 Gateway' if self._is_gateway(ip) else '🟢 Online'
                        self.device_tree.insert('', tk.END, values=(
                            ip, hostname, mac, vendor, 'None', status
                        ))
                        self.device_list.insert('', tk.END, values=(
                            ip, hostname, mac, status
                        ))
                self.update_progress_with_eta(completed, total_ips, start_time)

        self.scan_progress['value'] = 100
        elapsed = time.time() - start_time
        self.device_count.set(f"{len(devices_found)} devices")
        self.scan_status.config(text=f"Found {len(devices_found)} devices across {len(targets)} network(s) in {elapsed:.1f}s")
        self.update_scan_stats()
        self.root.after(0, self.update_summary)
        self.root.after(0, self.update_system_status)
        self.log(f"Quick scan complete: {len(devices_found)} devices in {elapsed:.1f}s", "SUCCESS")
    except Exception as e:
        self.log(f"Quick scan error: {e}", "ERROR")

def port_scan_tool(self):
    """Port scan tool"""
    selection = self.device_tree.selection()
    if not selection:
        selection = self.device_list.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a device first")
        return
    item = self.device_tree.item(selection[0])
    ip = item['values'][0]
    self.log(f"Port scan on {ip}...", "TOOL")
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, f"🔍 Port Scan: {ip}\n{'=' * 60}\n")
    threading.Thread(target=self.run_port_scan, args=(ip,), daemon=True).start()

def run_port_scan(self, ip):
    """Run port scan"""
    try:
        open_ports = []
        for port in range(1, 1025):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    self.tool_output.insert(1.0, f"✅ Port {port} open\n")
                sock.close()
            except:
                pass
            if port % 100 == 0:
                self.tool_output.insert(1.0, f"Progress: {port}/1024\n")
                self.root.update_idletasks()
        self.tool_output.insert(1.0, f"\n{'=' * 60}\n")
        if open_ports:
            self.tool_output.insert(1.0, f"Found {len(open_ports)} open ports\n")
            self.tool_output.insert(1.0, f"Ports: {', '.join(map(str, open_ports))}\n")
        else:
            self.tool_output.insert(1.0, "No open ports found\n")
        self.log(f"Port scan complete: {len(open_ports)} open ports", "SUCCESS")
    except Exception as e:
        self.log(f"Port scan error: {e}", "ERROR")
        self.tool_output.insert(1.0, f"\nError: {e}")

def traceroute(self):
    """Traceroute"""
    selection = self.device_tree.selection()
    if not selection:
        selection = self.device_list.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a device first")
        return
    item = self.device_tree.item(selection[0])
    ip = item['values'][0]
    self.log(f"Traceroute to {ip}...", "TOOL")
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, f"📡 Traceroute to {ip}\n{'=' * 60}\n")
    threading.Thread(target=self.run_traceroute, args=(ip,), daemon=True).start()

def run_traceroute(self, target):
    """Run traceroute with root check"""
    if not self._check_root("Traceroute"):
        return
    try:
        for ttl in range(1, 31):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                sock.settimeout(2)
                packet = struct.pack('!BBHHH', 8, 0, 0, 0, 0)
                start = time.time()
                sock.sendto(packet, (target, 0))
                try:
                    data, addr = sock.recvfrom(1024)
                    rtt = (time.time() - start) * 1000
                    self.tool_output.insert(1.0, f"{ttl:2d}  {addr[0]}  {rtt:.1f}ms\n")
                    if addr[0] == target:
                        self.tool_output.insert(1.0, "\n✅ Complete!\n")
                        break
                except socket.timeout:
                    self.tool_output.insert(1.0, f"{ttl:2d}  * * *\n")
                sock.close()
            except PermissionError:
                self.tool_output.insert(1.0, f"{ttl:2d}  ❌ Permission denied (need root)\n")
                break
            except:
                self.tool_output.insert(1.0, f"{ttl:2d}  Error\n")
            time.sleep(0.3)
    except Exception as e:
        self.log(f"Traceroute error: {e}", "ERROR")

def ping_tool(self):
    """Ping tool"""
    selection = self.device_tree.selection()
    if not selection:
        selection = self.device_list.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a device first")
        return
    item = self.device_tree.item(selection[0])
    ip = item['values'][0]
    self.log(f"Pinging {ip}...", "TOOL")
    self.tool_output.delete(1.0, tk.END)
    threading.Thread(target=self.run_ping, args=(ip,), daemon=True).start()

def run_ping(self, ip):
    """Run ping"""
    try:
        result = f"📡 Ping Results: {ip}\n{'=' * 60}\n"
        times = []
        for i in range(5):
            response = ping3.ping(ip, timeout=2)
            if response:
                rtt = response * 1000
                times.append(rtt)
                result += f"Reply: {rtt:.1f}ms\n"
            else:
                result += "Timeout\n"
            self.tool_output.delete(1.0, tk.END)
            self.tool_output.insert(1.0, result)
            self.root.update_idletasks()
            time.sleep(1)
        if times:
            result += f"\nAvg: {sum(times) / len(times):.1f}ms | Min: {min(times):.1f}ms | Max: {max(times):.1f}ms\n"
            self.tool_output.insert(1.0, result)
        self.log(f"Ping complete to {ip}", "SUCCESS")
    except Exception as e:
        self.log(f"Ping error: {e}", "ERROR")


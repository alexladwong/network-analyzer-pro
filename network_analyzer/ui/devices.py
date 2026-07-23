"""
devices module — extracted from main.py
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

def create_devices_tab(self):
    """Devices tab with professional card layout"""
    tab = ttk.Frame(self.notebook, style='Pro.TFrame')
    self.notebook.add(tab, text="📱 Devices")

    # Action buttons bar
    action_bar = ttk.Frame(tab, style='Pro.TFrame')
    action_bar.pack(fill=tk.X, padx=10, pady=(10, 5))
    controls = [("🔄 Refresh", self.refresh_devices), ("📊 Analyze", self.analyze_devices),
                ("📝 Add Note", self.add_device_note), ("🔍 Port Scan", self.port_scan_tool),
                ("📡 Ping", self.ping_tool), ("💾 Export", self.export_device_data)]
    for text, command in controls:
        ttk.Button(action_bar, text=text, command=command,
                   style='Pro.TButton').pack(side=tk.LEFT, padx=3)

    # Main content: two cards side by side
    content_row = ttk.Frame(tab, style='Pro.TFrame')
    content_row.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

    # Device List Card
    list_card = self._create_card(content_row, "Device List", expand=True, fill=tk.BOTH,
                                   pady=(0, 0), side=tk.LEFT, padx=(0, 5))
    list_inner = ttk.Frame(list_card, style='Pro.TFrame')
    list_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    columns = ('IP', 'Hostname', 'MAC', 'Status')
    self.device_list = ttk.Treeview(list_inner, columns=columns,
                                    show='headings', style='Pro.Treeview', height=20)
    for col in columns:
        self.device_list.heading(col, text=col)
        self.device_list.column(col, width=120)
    scrollbar = ttk.Scrollbar(list_inner, orient=tk.VERTICAL, command=self.device_list.yview,
                               style='Pro.Vertical.TScrollbar')
    self.device_list.configure(yscrollcommand=scrollbar.set)
    self.device_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    self.device_list.bind('<<TreeviewSelect>>', self.on_device_select)

    # Device Details Card
    detail_card = self._create_card(content_row, "Device Details", expand=True, fill=tk.BOTH,
                                     pady=(0, 0), side=tk.RIGHT, padx=(5, 0))
    detail_inner = ttk.Frame(detail_card, style='Pro.TFrame')
    detail_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
    self.device_details = tk.Text(detail_inner, bg=self.colors['secondary'],
                                  fg=self.colors['text'], font=('Consolas', 10), wrap=tk.WORD,
                                  bd=0, highlightthickness=0)
    details_scrollbar = ttk.Scrollbar(detail_inner, orient=tk.VERTICAL,
                                       command=self.device_details.yview, style='Pro.Vertical.TScrollbar')
    self.device_details.configure(yscrollcommand=details_scrollbar.set)
    self.device_details.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

def on_device_select(self, event):
    """Device select with rich security details"""
    selection = self.device_tree.selection()
    if not selection:
        selection = self.device_list.selection()
    if selection:
        item = self.device_tree.item(selection[0])
        values = item['values']
        ip = values[0]
        hostname = values[1]
        mac = values[2]
        vendor = values[3]
        ports = values[4]
        status = values[5]

        is_gw = self._is_gateway(ip)
        details = ""
        if is_gw:
            details += "🌐 Gateway Router\n"
        details += f"{'─' * 50}\n"
        details += f"  IP        {ip}\n"
        details += f"  Hostname  {hostname}\n"
        details += f"  MAC       {mac}\n"
        details += f"  Vendor    {vendor}\n"
        details += f"  Ports     {ports}\n"
        details += f"  Status    {status}\n"

        if is_gw:
            details += f"\n  🔒 This device is the network gateway.\n"
            details += f"     Routes traffic between your network and the internet.\n"

        # Security analysis for all devices with ports
        if ports and ports != 'None':
            try:
                port_list = [int(p) for p in ports.split(',') if p.strip().isdigit()]
                if port_list:
                    details += f"\n🔐 Security Analysis\n"
                    details += f"{'─' * 50}\n"
                    # Port descriptions
                    port_desc = {
                        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
                        3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
                    }
                    for p in port_list:
                        desc = port_desc.get(p, "")
                        risk = ""
                        if p in (21, 23, 25):
                            risk = " ⚠️ Insecure"
                        elif p == 445:
                            risk = " ⚠️ RCE Risk"
                        elif p == 3389:
                            risk = " ⚠️ BlueKeep Risk"
                        elif p == 22:
                            risk = " 🔒 Secure"
                        elif p == 443:
                            risk = " 🔒 Encrypted"
                        details += f"     Port {p:5d}  {desc}{risk}\n"

                    vulns = self.check_device_vulnerabilities(ip)
                    if vulns:
                        details += f"\n  ⚠ Vulnerabilities:\n"
                        for v in vulns[:5]:
                            details += f"     • {v}\n"
                    else:
                        details += f"\n  ✅ No known vulnerabilities detected\n"
            except:
                pass

        if ip in self.known_devices:
            details += f"\n📝 Notes:\n"
            details += f"     {self.known_devices[ip].get('notes', 'None')}\n"

        # Parental control info
        if ip in self.known_devices:
            dev_info = self.known_devices[ip]
            if dev_info.get('owner') or dev_info.get('profile'):
                details += f"\n🔞 Parental Control\n"
                details += f"{'─' * 50}\n"
                details += f"     Owner:  {dev_info.get('owner', 'Not set')}\n"
                details += f"     Profile: {dev_info.get('profile', 'Not set').capitalize()}\n"
                details += f"     Device:  {dev_info.get('device_name', 'Unknown')}\n"
                details += f"     Type:    {dev_info.get('device_type', 'Unknown')}\n"
                details += f"     Location: {dev_info.get('location', 'Unknown')}\n"
                details += f"     Blocked: {'Yes 🔒' if dev_info.get('blocked', False) else 'No'}\n"

        self.device_details.delete(1.0, tk.END)
        self.device_details.insert(1.0, details)

def refresh_devices(self):
    """Refresh"""
    self.log("Refreshing devices...", "INFO")
    self.quick_scan()

def analyze_devices(self):
    """Analyze"""
    self.log("Analyzing devices...", "TOOL")
    self.tool_output.delete(1.0, tk.END)
    devices = []
    for item in self.device_tree.get_children():
        values = self.device_tree.item(item)['values']
        devices.append({'ip': values[0], 'hostname': values[1]})
    if devices:
        analysis = f"📊 Device Analysis\n{'=' * 60}\n"
        analysis += f"Total: {len(devices)}\n"
        unknown = len([d for d in devices if d['hostname'] == 'Unknown'])
        analysis += f"Unknown: {unknown}\n"
        self.tool_output.insert(1.0, analysis)

def add_device_note(self):
    """Add note"""
    selection = self.device_tree.selection()
    if not selection:
        selection = self.device_list.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a device first")
        return
    item = self.device_tree.item(selection[0])
    ip = item['values'][0]

    dialog = tk.Toplevel(self.root)
    dialog.title(f"Add Note - {ip}")
    dialog.geometry("500x300")
    dialog.configure(bg=self.colors['bg'])
    ttk.Label(dialog, text=f"Device: {ip}", style='Pro.TLabel').pack(pady=10)
    note_entry = tk.Text(dialog, height=8, width=50, bg=self.colors['secondary'], fg='white')
    note_entry.pack(pady=10)
    if ip in self.known_devices and 'notes' in self.known_devices[ip]:
        note_entry.insert(1.0, self.known_devices[ip]['notes'])

    def save_note():
        note = note_entry.get(1.0, tk.END).strip()
        if ip not in self.known_devices:
            self.known_devices[ip] = {}
        self.known_devices[ip]['notes'] = note
        self.known_devices[ip]['date'] = datetime.now().isoformat()
        self.save_data()
        self.log(f"Note saved for {ip}", "SUCCESS")
        dialog.destroy()

    ttk.Button(dialog, text="Save", command=save_note, style='Pro.TButton').pack(pady=10)

def export_device_data(self):
    """Export device data"""
    try:
        filename = filedialog.asksaveasfilename(defaultextension=".json",
                                                filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if filename:
            devices = []
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                devices.append({'ip': values[0], 'hostname': values[1], 'status': values[5]})
            with open(filename, 'w') as f:
                json.dump(devices, f, indent=2)
            self.log(f"Device data exported", "SUCCESS")
            messagebox.showinfo("Export Complete", f"Saved to:\n{filename}")
    except Exception as e:
        self.log(f"Export error: {e}", "ERROR")


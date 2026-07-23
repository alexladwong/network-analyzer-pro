"""
parental module — extracted from main.py
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

def create_parental_tab(self):
    """Parental control tab with device profiles, activity monitoring, and restriction management"""
    tab = ttk.Frame(self.notebook, style='Pro.TFrame')
    self.notebook.add(tab, text="👨\u200d👩\u200d👧 Parental")

    # === Top Status Bar ===
    status_bar = tk.Frame(tab, bg=self.colors['secondary'],
                          highlightbackground=self.colors['accent2'],
                          highlightthickness=1, bd=0)
    status_bar.pack(fill=tk.X, padx=10, pady=(10, 5))

    status_inner = tk.Frame(status_bar, bg=self.colors['secondary'])
    status_inner.pack(fill=tk.X, padx=12, pady=6)

    stats_data = [
        ("👤 Devices", "parental_devices_lbl", "0"),
        ("🔞 Blocked Today", "parental_blocked_lbl", "0"),
        ("📡 DNS Monitor", "parental_dns_lbl", "Off"),
        ("🛡️ Content Filter", "parental_filter_lbl", "Inactive"),
    ]
    for label, attr, default in stats_data:
        f = tk.Frame(status_inner, bg=self.colors['secondary'])
        f.pack(side=tk.LEFT, padx=(0, 20))
        tk.Label(f, text=label, bg=self.colors['secondary'],
                 fg=self.colors['text_dim'], font=('Arial', 9)).pack(side=tk.LEFT)
        lbl = tk.Label(f, text=default, bg=self.colors['secondary'],
                       fg=self.colors['text'], font=('Arial', 10, 'bold'))
        lbl.pack(side=tk.LEFT, padx=4)
        setattr(self, attr, lbl)

    # Quick action buttons
    action_frame = tk.Frame(status_inner, bg=self.colors['secondary'])
    action_frame.pack(side=tk.RIGHT)
    self.parental_dns_btn = tk.Button(action_frame, text="▶ Start DNS Monitor",
                                      command=self.toggle_dns_monitoring,
                                      bg=self.colors['accent'], fg='white',
                                      font=('Arial', 10), bd=0, padx=10, pady=4,
                                      cursor='hand2', highlightthickness=0)
    self.parental_dns_btn.pack(side=tk.LEFT, padx=2)
    self.parental_filter_btn = tk.Button(action_frame, text="▶ Start Filter",
                                         command=self.toggle_content_filter,
                                         bg=self.colors['accent'], fg='white',
                                         font=('Arial', 10), bd=0, padx=10, pady=4,
                                         cursor='hand2', highlightthickness=0)
    self.parental_filter_btn.pack(side=tk.LEFT, padx=2)

    # === Main content: 2 columns ===
    content_frame = ttk.Frame(tab, style='Pro.TFrame')
    content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    left_col = ttk.Frame(content_frame, style='Pro.TFrame')
    left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
    right_col = ttk.Frame(content_frame, style='Pro.TFrame')
    right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

    # === LEFT COLUMN ===

    # 1. Device Profiles Card
    profile_card = self._create_card(left_col, "Device Profiles (Parental)", expand=True, fill=tk.BOTH)
    profile_inner = ttk.Frame(profile_card, style='Pro.TFrame')
    profile_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    columns = ('Device', 'Owner', 'Profile', 'Status', 'Online')
    self.parental_device_tree = ttk.Treeview(profile_inner, columns=columns,
                                              show='headings', style='Pro.Treeview', height=10)
    col_w = {'Device': 130, 'Owner': 100, 'Profile': 80, 'Status': 100, 'Online': 70}
    for col in columns:
        self.parental_device_tree.heading(col, text=col)
        self.parental_device_tree.column(col, width=col_w[col])
    self.parental_device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    psb = ttk.Scrollbar(profile_inner, orient=tk.VERTICAL, command=self.parental_device_tree.yview,
                        style='Pro.Vertical.TScrollbar')
    self.parental_device_tree.configure(yscrollcommand=psb.set)
    psb.pack(side=tk.RIGHT, fill=tk.Y)
    self.parental_device_tree.bind('<<TreeviewSelect>>', self.on_parental_device_select)

    # Profile control buttons
    ctrl_frame = ttk.Frame(left_col, style='Pro.TFrame')
    ctrl_frame.pack(fill=tk.X, pady=5)
    ttk.Button(ctrl_frame, text="👤 Assign Profile", command=self.parental_assign_profile,
               style='Pro.TButton').pack(side=tk.LEFT, padx=2)
    ttk.Button(ctrl_frame, text="🔒 Block Device", command=self.parental_toggle_block,
               style='Pro.TButton').pack(side=tk.LEFT, padx=2)
    ttk.Button(ctrl_frame, text="📝 Edit Details", command=self.parental_edit_device,
               style='Pro.TButton').pack(side=tk.LEFT, padx=2)

    # 2. Activity Monitor Card
    activity_card = self._create_card(left_col, "Internet Activity (DNS)", expand=True, fill=tk.BOTH,
                                       pady=(5, 0))
    act_inner = ttk.Frame(activity_card, style='Pro.TFrame')
    act_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    # Filter bar
    filterbar = ttk.Frame(act_inner, style='Pro.TFrame')
    filterbar.pack(fill=tk.X)
    ttk.Label(filterbar, text="Filter:", style='Pro.TLabel').pack(side=tk.LEFT, padx=2)
    self.parental_activity_filter = ttk.Entry(filterbar, width=20, font=('Consolas', 10))
    self.parental_activity_filter.pack(side=tk.LEFT, padx=2)
    self.parental_activity_filter.bind('<KeyRelease>', self.parental_filter_activity)
    self.parental_activity_clear_btn = ttk.Button(filterbar, text="🗑 Clear",
                                                   command=self.parental_clear_activity,
                                                   style='Small.TButton')
    self.parental_activity_clear_btn.pack(side=tk.RIGHT, padx=2)

    self.parental_activity_text = tk.Text(act_inner, bg='#000000',
                                          fg=self.colors['terminal'],
                                          font=('Consolas', 9), height=10,
                                          bd=0, highlightthickness=0)
    self.parental_activity_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=(4, 0))
    asb = ttk.Scrollbar(act_inner, orient=tk.VERTICAL, command=self.parental_activity_text.yview,
                        style='Pro.Vertical.TScrollbar')
    self.parental_activity_text.configure(yscrollcommand=asb.set)
    asb.pack(side=tk.RIGHT, fill=tk.Y)

    self.parental_activity_text.insert(1.0, "🔞 Parental Control Monitor\n")
    self.parental_activity_text.insert(tk.END, f"{'=' * 60}\n")
    self.parental_activity_text.insert(tk.END, "Start DNS Monitor to capture device internet activity.\n")
    if SCAPY_AVAILABLE:
        self.parental_activity_text.insert(tk.END, "DNS queries will appear here in real-time.\n")
    else:
        self.parental_activity_text.insert(tk.END, "⚠️ Scapy required for DNS monitoring.\n")

    # === RIGHT COLUMN ===

    # 3. Blocked Attempts Card
    blocked_card = self._create_card(right_col, "Blocked Attempts", expand=True, fill=tk.BOTH)
    blocked_inner = ttk.Frame(blocked_card, style='Pro.TFrame')
    blocked_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    columns2 = ('Time', 'Device', 'Domain', 'Category', 'Profile')
    self.parental_blocked_tree = ttk.Treeview(blocked_inner, columns=columns2,
                                               show='headings', style='Pro.Treeview', height=6)
    cw2 = {'Time': 80, 'Device': 100, 'Domain': 140, 'Category': 80, 'Profile': 70}
    for col in columns2:
        self.parental_blocked_tree.heading(col, text=col)
        self.parental_blocked_tree.column(col, width=cw2[col])
    self.parental_blocked_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    bsb = ttk.Scrollbar(blocked_inner, orient=tk.VERTICAL, command=self.parental_blocked_tree.yview,
                        style='Pro.Vertical.TScrollbar')
    self.parental_blocked_tree.configure(yscrollcommand=bsb.set)
    bsb.pack(side=tk.RIGHT, fill=tk.Y)

    # 4. Profiles & Settings Card
    settings_card = self._create_card(right_col, "Profiles & Settings", expand=True, fill=tk.BOTH,
                                       pady=(5, 0))
    set_inner = ttk.Frame(settings_card, style='Pro.TFrame')
    set_inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    # Profile selector
    prof_row = ttk.Frame(set_inner, style='Pro.TFrame')
    prof_row.pack(fill=tk.X, pady=3)
    ttk.Label(prof_row, text="Edit Profile:", style='Pro.TLabel').pack(side=tk.LEFT, padx=2)
    self.parental_profile_combo = ttk.Combobox(prof_row, values=list(self.parental_profiles.keys()),
                                                state='readonly', width=12, font=('Consolas', 10))
    self.parental_profile_combo.pack(side=tk.LEFT, padx=2)
    self.parental_profile_combo.set('child')
    ttk.Button(prof_row, text="View", command=self.parental_view_profile,
               style='Small.TButton').pack(side=tk.LEFT, padx=2)

    # Profile detail display
    self.parental_profile_detail = tk.Text(set_inner, bg=self.colors['secondary'],
                                            fg=self.colors['text'], font=('Consolas', 9),
                                            height=8, bd=0, highlightthickness=0)
    self.parental_profile_detail.pack(fill=tk.BOTH, expand=True, pady=4)

    # Settings summary
    set_summary = tk.Frame(set_inner, bg=self.colors['secondary'],
                           highlightbackground=self.colors['accent2'],
                           highlightthickness=1, bd=0)
    set_summary.pack(fill=tk.X, pady=4)
    self.parental_settings_text = tk.Label(set_summary, bg=self.colors['secondary'],
                                           fg=self.colors['text_dim'],
                                           font=('Consolas', 8), justify=tk.LEFT, anchor='w')
    self.parental_settings_text.pack(fill=tk.X, padx=6, pady=4)

    # 5. Reports section
    report_frame = ttk.Frame(right_col, style='Pro.TFrame')
    report_frame.pack(fill=tk.X, pady=5)
    ttk.Button(report_frame, text="📊 Daily Report", command=self.parental_daily_report,
               style='Pro.TButton').pack(side=tk.LEFT, padx=2)
    ttk.Button(report_frame, text="📈 Weekly Summary", command=self.parental_weekly_report,
               style='Pro.TButton').pack(side=tk.LEFT, padx=2)
    ttk.Button(report_frame, text="📋 Export Report", command=self.parental_export_report,
               style='Pro.TButton').pack(side=tk.LEFT, padx=2)
    ttk.Button(report_frame, text="⚙ Settings", command=self.parental_settings_dialog,
               style='Pro.TButton').pack(side=tk.LEFT, padx=2)

    # Initial population
    self.refresh_parental_display()
    self.update_parental_stats()

    # === INFRASTRUCTURE & ROGUE DETECTION SECTION ===
    infra_section = ttk.Frame(tab, style='Pro.TFrame')
    infra_section.pack(fill=tk.X, padx=10, pady=(0, 10))

    # Infrastructure monitor toggle
    infra_controls = tk.Frame(infra_section, bg=self.colors['secondary'],
                              highlightbackground=self.colors['accent2'],
                              highlightthickness=1, bd=0)
    infra_controls.pack(fill=tk.X, pady=(0, 5))

    ctrl_inner = tk.Frame(infra_controls, bg=self.colors['secondary'])
    ctrl_inner.pack(fill=tk.X, padx=12, pady=6)
    tk.Label(ctrl_inner, text="🛡️ Infrastructure Monitor", bg=self.colors['secondary'],
            fg=self.colors['text'], font=('Arial', 11, 'bold')).pack(side=tk.LEFT, padx=(0, 10))
    self.parental_infra_monitor_btn = tk.Button(ctrl_inner, text="▶ Start Infra Monitor",
                                                 command=self.toggle_infrastructure_monitoring,
                                                 bg=self.colors['accent'], fg='white',
                                                 font=('Arial', 10), bd=0, padx=10, pady=3,
                                                 cursor='hand2', highlightthickness=0)
    self.parental_infra_monitor_btn.pack(side=tk.LEFT, padx=2)
    ttk.Button(ctrl_inner, text="➕ Add Approved", command=self.infrastructure_add_dialog,
               style='Small.TButton').pack(side=tk.LEFT, padx=2)
    ttk.Button(ctrl_inner, text="🗑 Clear Alerts", command=self.rogue_clear_all,
               style='Small.TButton').pack(side=tk.LEFT, padx=2)

    # Infrastructure stats indicators
    self.infra_status_lbl = tk.Label(ctrl_inner, text="🌐 0 routers", bg=self.colors['secondary'],
                                     fg=self.colors['text_dim'], font=('Arial', 9))
    self.infra_status_lbl.pack(side=tk.RIGHT, padx=5)
    self.rogue_status_lbl = tk.Label(ctrl_inner, text="⚠️ 0 alerts", bg=self.colors['secondary'],
                                     fg=self.colors['text_dim'], font=('Arial', 9))
    self.rogue_status_lbl.pack(side=tk.RIGHT, padx=5)

    # Two-column layout for infra sections
    infra_content = ttk.Frame(infra_section, style='Pro.TFrame')
    infra_content.pack(fill=tk.X)

    infra_left = ttk.Frame(infra_content, style='Pro.TFrame')
    infra_left.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

    infra_right = ttk.Frame(infra_content, style='Pro.TFrame')
    infra_right.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))

    # === 6. Approved Infrastructure Card ===
    infra_card = self._create_card(infra_left, "Approved Infrastructure", expand=False)
    infra_inner = ttk.Frame(infra_card, style='Pro.TFrame')
    infra_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

    infra_cols = ('Name', 'IP', 'MAC', 'Type', 'Status', 'Approved', 'Location')
    self.parental_infra_tree = ttk.Treeview(infra_inner, columns=infra_cols,
                                              show='headings', style='Pro.Treeview', height=5)
    infra_w = {'Name': 80, 'IP': 100, 'MAC': 100, 'Type': 70, 'Status': 70, 'Approved': 60, 'Location': 70}
    for col in infra_cols:
        self.parental_infra_tree.heading(col, text=col)
        self.parental_infra_tree.column(col, width=infra_w[col])
    self.parental_infra_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    isb = ttk.Scrollbar(infra_inner, orient=tk.VERTICAL, command=self.parental_infra_tree.yview,
                        style='Pro.Vertical.TScrollbar')
    self.parental_infra_tree.configure(yscrollcommand=isb.set)
    isb.pack(side=tk.RIGHT, fill=tk.Y)
    self.parental_infra_tree.bind('<Double-1>', lambda e: self._on_infra_tree_double_click())

    infra_btn_row = ttk.Frame(infra_left, style='Pro.TFrame')
    infra_btn_row.pack(fill=tk.X, pady=(2, 0))
    ttk.Button(infra_btn_row, text="✏ Edit", command=lambda: self._on_infra_tree_double_click(),
               style='Small.TButton').pack(side=tk.LEFT, padx=1)
    ttk.Button(infra_btn_row, text="❌ Remove", command=self._infra_remove_selected,
               style='Small.TButton').pack(side=tk.LEFT, padx=1)
    ttk.Button(infra_btn_row, text="🔄 Scan Now", command=lambda: threading.Thread(
               target=self.update_topology, daemon=True).start(),
               style='Small.TButton').pack(side=tk.LEFT, padx=1)

    # === 7. Rogue Alerts Card ===
    rogue_card = self._create_card(infra_right, "Rogue Alerts", expand=False)
    rogue_inner = ttk.Frame(rogue_card, style='Pro.TFrame')
    rogue_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

    rogue_cols = ('Time', 'Device', 'Severity', 'Type', 'Confidence', 'Ack')
    self.parental_rogue_tree = ttk.Treeview(rogue_inner, columns=rogue_cols,
                                              show='headings', style='Pro.Treeview', height=5)
    rogue_w = {'Time': 70, 'Device': 120, 'Severity': 70, 'Type': 90, 'Confidence': 70, 'Ack': 40}
    for col in rogue_cols:
        self.parental_rogue_tree.heading(col, text=col)
        self.parental_rogue_tree.column(col, width=rogue_w[col])
    self.parental_rogue_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    rsb = ttk.Scrollbar(rogue_inner, orient=tk.VERTICAL, command=self.parental_rogue_tree.yview,
                        style='Pro.Vertical.TScrollbar')
    self.parental_rogue_tree.configure(yscrollcommand=rsb.set)
    rsb.pack(side=tk.RIGHT, fill=tk.Y)
    self.parental_rogue_tree.bind('<Double-1>', lambda e: self.rogue_investigate())

    rogue_btn_row = ttk.Frame(infra_right, style='Pro.TFrame')
    rogue_btn_row.pack(fill=tk.X, pady=(2, 0))
    ttk.Button(rogue_btn_row, text="🔍 Investigate", command=lambda: self.rogue_investigate(),
               style='Small.TButton').pack(side=tk.LEFT, padx=1)
    ttk.Button(rogue_btn_row, text="✅ Acknowledge", command=self.rogue_acknowledge,
               style='Small.TButton').pack(side=tk.LEFT, padx=1)
    ttk.Button(rogue_btn_row, text="🗑 Clear All", command=self.rogue_clear_all,
               style='Small.TButton').pack(side=tk.LEFT, padx=1)

    # === Second row: Transitions + Topology ===
    infra_row2 = ttk.Frame(infra_section, style='Pro.TFrame')
    infra_row2.pack(fill=tk.X, pady=(5, 0))

    infra_left2 = ttk.Frame(infra_row2, style='Pro.TFrame')
    infra_left2.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

    infra_right2 = ttk.Frame(infra_row2, style='Pro.TFrame')
    infra_right2.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))

    # === 8. Child Network Transitions Card ===
    trans_card = self._create_card(infra_left2, "Child Network Transitions", expand=False)
    trans_inner = ttk.Frame(trans_card, style='Pro.TFrame')
    trans_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

    trans_cols = ('Time', 'Device', 'From', 'To', 'DNS Cov')
    self.parental_transitions_tree = ttk.Treeview(trans_inner, columns=trans_cols,
                                                   show='headings', style='Pro.Treeview', height=4)
    trans_w = {'Time': 70, 'Device': 130, 'From': 100, 'To': 100, 'DNS Cov': 60}
    for col in trans_cols:
        self.parental_transitions_tree.heading(col, text=col)
        self.parental_transitions_tree.column(col, width=trans_w[col])
    self.parental_transitions_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # === 9. Network Topology Card ===
    topo_card = self._create_card(infra_right2, "Network Topology", expand=False)
    topo_inner = ttk.Frame(topo_card, style='Pro.TFrame')
    topo_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

    topo_cols = ('Type', 'Identifier', 'Name', 'Status')
    self.parental_topology_tree = ttk.Treeview(topo_inner, columns=topo_cols,
                                                show='tree', style='Pro.Treeview', height=4)
    topo_w = {'Type': 100, 'Identifier': 120, 'Name': 100, 'Status': 60}
    for col in topo_cols:
        self.parental_topology_tree.heading(col, text=col)
        self.parental_topology_tree.column(col, width=topo_w[col])
    self.parental_topology_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # === 10. Investigation Timeline (full width) ===
    timeline_card = self._create_card(infra_section, "Investigation Timeline", expand=False,
                                      pady=(5, 0))
    tl_inner = ttk.Frame(timeline_card, style='Pro.TFrame')
    tl_inner.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

    self.parental_timeline_text = tk.Text(tl_inner, bg='#000000',
                                          fg=self.colors['terminal'],
                                          font=('Consolas', 8), height=6,
                                          bd=0, highlightthickness=0)
    self.parental_timeline_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    tsb = ttk.Scrollbar(tl_inner, orient=tk.VERTICAL, command=self.parental_timeline_text.yview,
                        style='Pro.Vertical.TScrollbar')
    self.parental_timeline_text.configure(yscrollcommand=tsb.set)
    tsb.pack(side=tk.RIGHT, fill=tk.Y)

    # Initial display
    self.refresh_infrastructure_display()
    self.refresh_rogue_alerts_display()
    self.refresh_topology_display()
    self.refresh_timeline_display()

def refresh_parental_display(self):
    """Refresh the parental device tree from scanned devices and known devices"""
    try:
        self.parental_device_tree.delete(*self.parental_device_tree.get_children())

        # Merge scanned devices with known device data
        seen_ips = set()
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item)['values']
            ip = values[0]
            seen_ips.add(ip)
            mac = values[2] if len(values) > 2 else ''
            hostname = values[1] if len(values) > 1 else 'Unknown'
            status = values[5] if len(values) > 5 else '🟢 Online'
            online = '🟢' if 'Online' in status or 'Gateway' in status else '🔴'
            ports_str = values[4] if len(values) > 4 else ''
            ports = [int(p) for p in ports_str.split(',') if p.strip().isdigit()] if ports_str else []

            # Check if we have known device data
            dev_info = self.known_devices.get(ip, {})
            owner = dev_info.get('owner', 'Unknown')
            profile = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
            device_name = dev_info.get('device_name', hostname)
            device_type = dev_info.get('device_type', '')
            blocked = dev_info.get('blocked', False)

            # Auto-classify if not yet assigned
            if not dev_info.get('owner') or dev_info.get('owner') == 'Unknown':
                # Auto-detect based on hostname patterns
                hl = hostname.lower()
                if any(x in hl for x in ['phone', 'iphone', 'android', 'galaxy', 'ipad', 'tablet']):
                    device_type = self.classify_device(mac, hostname, ports)
                elif any(x in hl for x in ['laptop', 'notebook', 'macbook', 'desktop', 'pc']):
                    device_type = self.classify_device(mac, hostname, ports)
                elif mac != 'Unknown':
                    device_type = self.classify_device(mac, hostname, ports)
                if device_type and device_type != 'Unknown Device':
                    if ip not in self.known_devices:
                        self.known_devices[ip] = {}
                    self.known_devices[ip]['device_type'] = device_type
                    self.known_devices[ip]['device_name'] = device_name
                    if not dev_info.get('owner'):
                        # Generate owner from device type
                        self.known_devices[ip]['owner'] = 'Unknown'

            # Build display name with type
            display_name = device_name
            if device_type and device_type != 'Unknown Device':
                display_name = f"{device_name} ({device_type})"

            status_text = f"{'🔒 ' if blocked else ''}{'✅' if 'Online' in status or 'Gateway' in status else '❌'}"
            self.parental_device_tree.insert('', tk.END, values=(
                display_name, owner, profile.capitalize(), status_text, online
            ), tags=(ip,))

            # Save auto-detected info
            if ip not in self.known_devices:
                self.known_devices[ip] = {}
            if not self.known_devices[ip].get('device_type') and device_type:
                self.known_devices[ip]['device_type'] = device_type
            if not self.known_devices[ip].get('device_name') or self.known_devices[ip].get('device_name') == ip:
                self.known_devices[ip]['device_name'] = hostname if hostname != 'Unknown' else ip
            if mac and mac != 'Unknown':
                self.known_devices[ip]['mac'] = mac

        # Add known-only devices (not currently on network)
        for ip, dev_info in self.known_devices.items():
            if ip not in seen_ips:
                owner = dev_info.get('owner', 'Unknown')
                profile = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
                device_name = dev_info.get('device_name', ip)
                device_type = dev_info.get('device_type', '')
                blocked = dev_info.get('blocked', False)
                display_name = f"{device_name} ({device_type})" if device_type and device_type != 'Unknown Device' else device_name
                status_text = f"{'🔒 ' if blocked else ''}Offline"
                self.parental_device_tree.insert('', tk.END, values=(
                    display_name, owner, profile.capitalize(), status_text, '⚫'
                ), tags=(ip,))

        # Auto-save any new device identifications
        self.save_data()
        self.update_parental_stats()
    except Exception as e:
        self.log(f"Parental display refresh error: {e}", "WARNING")

def update_parental_stats(self):
    """Update parental control status indicators"""
    try:
        total = len(self.parental_device_tree.get_children())
        if hasattr(self, 'parental_devices_lbl'):
            self.parental_devices_lbl.config(text=str(total))
        if hasattr(self, 'parental_blocked_lbl'):
            self.parental_blocked_lbl.config(text=str(self.parental_blocked_count))
        if hasattr(self, 'parental_dns_lbl'):
            dns_status = "🟢 On" if self.dns_monitoring else "🔴 Off"
            self.parental_dns_lbl.config(text=dns_status)
        if hasattr(self, 'parental_filter_lbl'):
            filter_status = "🟢 Active" if self.parental_settings.get('block_method') != 'none' else "🔴 Off"
            self.parental_filter_lbl.config(text=filter_status)
    except:
        pass

def on_parental_device_select(self, event=None):
    """Show device details when selected in parental tree"""
    selection = self.parental_device_tree.selection()
    if not selection:
        return
    item = self.parental_device_tree.item(selection[0])
    values = item['values']
    device_name = values[0] if values else ''
    # Find IP from tags
    tags = item.get('tags', ())
    ip = tags[0] if tags else ''

    dev_info = self.known_devices.get(ip, {})
    detail = f"Device: {device_name}\n"
    detail += f"{'─' * 40}\n"
    detail += f"  IP: {ip}\n"
    detail += f"  Owner: {dev_info.get('owner', 'Unknown')}\n"
    detail += f"  Profile: {dev_info.get('profile', 'child').capitalize()}\n"
    detail += f"  Type: {dev_info.get('device_type', 'Unknown')}\n"
    detail += f"  Location: {dev_info.get('location', 'Unknown')}\n"
    detail += f"  Blocked: {'Yes 🔒' if dev_info.get('blocked', False) else 'No'}\n"
    detail += f"  Notes: {dev_info.get('notes', 'None')}\n"

    # Show today's activity count
    today = datetime.now().strftime("%Y-%m-%d")
    activity_count = sum(1 for entry in self.activity_log
                         if entry.get('ip') == ip and entry.get('date', '').startswith(today))
    blocked_count = sum(1 for entry in self.activity_log
                        if entry.get('ip') == ip and entry.get('blocked', False)
                        and entry.get('date', '').startswith(today))
    detail += f"\n  Today's Activity: {activity_count} queries\n"
    detail += f"  Blocked Today: {blocked_count}\n"

    # Show time limit info
    profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
    profile = self.parental_profiles.get(profile_name, {})
    time_left = self.get_remaining_time(ip, profile)
    if time_limit := profile.get('time_limit', 0):
        detail += f"  Time Remaining: {max(0, time_limit - (time_limit - time_left))}m / {time_limit}m\n"

    if hasattr(self, 'parental_profile_detail'):
        self.parental_profile_detail.delete(1.0, tk.END)
        self.parental_profile_detail.insert(1.0, detail)

def parental_filter_activity(self, event=None):
    """Filter activity display by keyword"""
    filter_text = self.parental_activity_filter.get().strip().lower()
    if not filter_text:
        return

    self.parental_activity_text.delete(1.0, tk.END)
    count = 0
    for entry in reversed(self.activity_log):
        if filter_text in entry.get('domain', '').lower() or \
           filter_text in entry.get('device_name', '').lower() or \
           filter_text in entry.get('owner', '').lower():
            status = "🛡️ BLOCKED" if entry.get('blocked') else "✅ ALLOWED"
            line = f"[{entry['time']}] {status} {entry['domain']} <- {entry.get('device_name', '')}\n"
            self.parental_activity_text.insert(tk.END, line)
            count += 1
            if count >= 200:
                break

def parental_clear_activity(self):
    """Clear activity log"""
    if messagebox.askyesno("Clear Activity", "Clear all activity logs?"):
        self.activity_log.clear()
        self.parental_activity_text.delete(1.0, tk.END)
        self.parental_activity_text.insert(1.0, "🔞 Activity Log Cleared\n")
        self.log("Activity log cleared", "PARENTAL")

def parental_assign_profile(self):
    """Assign a profile to a selected device"""
    selection = self.parental_device_tree.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a device first")
        return
    item = self.parental_device_tree.item(selection[0])
    tags = item.get('tags', ())
    ip = tags[0] if tags else ''
    if not ip:
        return

    dialog = tk.Toplevel(self.root)
    dialog.title(f"Assign Profile - {item['values'][0]}")
    dialog.geometry("400x350")
    dialog.configure(bg=self.colors['bg'])

    ttk.Label(dialog, text=f"Device: {item['values'][0]}", style='Pro.TLabel',
              font=('Arial', 11, 'bold')).pack(pady=10)

    fields_frame = ttk.Frame(dialog, style='Pro.TFrame')
    fields_frame.pack(padx=20, pady=10, fill=tk.X)

    # Owner name
    ttk.Label(fields_frame, text="Owner:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
    owner_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('owner', ''))
    ttk.Entry(fields_frame, textvariable=owner_var, font=('Consolas', 11),
              width=30).pack(fill=tk.X, pady=2)

    # Profile selection
    ttk.Label(fields_frame, text="Profile:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
    profile_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('profile',
                                 self.parental_settings.get('default_profile', 'child')))
    profile_combo = ttk.Combobox(fields_frame, textvariable=profile_var,
                                  values=list(self.parental_profiles.keys()),
                                  state='readonly', width=28, font=('Consolas', 11))
    profile_combo.pack(fill=tk.X, pady=2)

    # Device type
    ttk.Label(fields_frame, text="Device Type:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
    type_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('device_type', 'Unknown'))
    type_combo = ttk.Combobox(fields_frame, textvariable=type_var,
                               values=['Phone', 'Tablet', 'Laptop', 'Desktop', 'Gaming Console',
                                       'Smart TV', 'IoT', 'Other'],
                               state='readonly', width=28, font=('Consolas', 11))
    type_combo.pack(fill=tk.X, pady=2)

    # Location
    ttk.Label(fields_frame, text="Location (Floor/Room):", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
    loc_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('location', ''))
    ttk.Entry(fields_frame, textvariable=loc_var, font=('Consolas', 11),
              width=30).pack(fill=tk.X, pady=2)

    # Device name
    ttk.Label(fields_frame, text="Device Name:", style='Pro.TLabel').pack(anchor=tk.W, pady=2)
    name_var = tk.StringVar(value=self.known_devices.get(ip, {}).get('device_name',
                             self.get_hostname(ip)))
    ttk.Entry(fields_frame, textvariable=name_var, font=('Consolas', 11),
              width=30).pack(fill=tk.X, pady=2)

    def save_assignment():
        if ip not in self.known_devices:
            self.known_devices[ip] = {}
        self.known_devices[ip]['owner'] = owner_var.get()
        self.known_devices[ip]['profile'] = profile_var.get()
        self.known_devices[ip]['device_type'] = type_var.get()
        self.known_devices[ip]['location'] = loc_var.get()
        self.known_devices[ip]['device_name'] = name_var.get()
        self.known_devices[ip]['date_added'] = datetime.now().isoformat()
        self.save_data()
        self.refresh_parental_display()
        self.log(f"Profile assigned to {ip}: {profile_var.get()}", "PARENTAL")
        dialog.destroy()

    ttk.Button(dialog, text="💾 Save", command=save_assignment,
               style='Pro.TButton').pack(pady=15)

def parental_toggle_block(self):
    """Toggle block on a device"""
    selection = self.parental_device_tree.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a device first")
        return
    item = self.parental_device_tree.item(selection[0])
    tags = item.get('tags', ())
    ip = tags[0] if tags else ''
    if not ip:
        return

    if ip not in self.known_devices:
        self.known_devices[ip] = {}
    blocked = not self.known_devices[ip].get('blocked', False)
    self.known_devices[ip]['blocked'] = blocked
    self.save_data()
    self.refresh_parental_display()
    action = "Blocked" if blocked else "Unblocked"
    self.log(f"{action} device {ip}", "PARENTAL")

def parental_edit_device(self):
    """Edit device details"""
    selection = self.parental_device_tree.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a device first")
        return
    item = self.parental_device_tree.item(selection[0])
    tags = item.get('tags', ())
    ip = tags[0] if tags else ''
    if not ip:
        return
    # Reuse assign profile dialog logic
    self.parental_assign_profile()

def parental_view_profile(self):
    """View selected profile details"""
    profile_name = self.parental_profile_combo.get()
    profile = self.parental_profiles.get(profile_name)
    if not profile:
        return

    detail = f"Profile: {profile['name']}\n"
    detail += f"{'─' * 40}\n"
    detail += f"  Blocked Categories: {', '.join(profile.get('block_categories', ['None'])) or 'None'}\n"
    detail += f"  Time Limit: {profile.get('time_limit', 0)} min/day" if profile.get('time_limit') else "  Time Limit: Unlimited\n"
    detail += "\n"
    detail += f"  Curfew: {profile.get('curfew_start', 'N/A')} - {profile.get('curfew_end', 'N/A')}\n"
    if profile.get('weekend_diff'):
        detail += f"  Weekend: {profile.get('weekend_time_limit', 0)} min, "
        detail += f"{profile.get('weekend_curfew_start', 'N/A')} - {profile.get('weekend_curfew_end', 'N/A')}\n"
    detail += f"  Block Domains: {', '.join(profile.get('block_domains', [])) or 'None'}\n"
    detail += f"  Allow Domains: {', '.join(profile.get('allow_domains', [])) or 'None'}\n"

    if hasattr(self, 'parental_profile_detail'):
        self.parental_profile_detail.delete(1.0, tk.END)
        self.parental_profile_detail.insert(1.0, detail)

def parental_settings_dialog(self):
    """Open parental control settings dialog"""
    dialog = tk.Toplevel(self.root)
    dialog.title("Parental Control Settings")
    dialog.geometry("550x500")
    dialog.configure(bg=self.colors['bg'])

    frame = ttk.Frame(dialog, style='Pro.TFrame')
    frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

    ttk.Label(frame, text="Parental Control Settings", style='Heading.TLabel').pack(anchor=tk.W, pady=5)

    settings_list = [
        ("Default Profile", 'default_profile', ['child', 'teen', 'guest', 'admin']),
        ("Block Method", 'block_method', ['none', 'hosts']),
    ]
    for label, key, options in settings_list:
        row = ttk.Frame(frame, style='Pro.TFrame')
        row.pack(fill=tk.X, pady=4)
        ttk.Label(row, text=f"{label}:", style='Pro.TLabel').pack(side=tk.LEFT, padx=5)
        var = tk.StringVar(value=self.parental_settings.get(key, options[0]))
        combo = ttk.Combobox(row, textvariable=var, values=options, state='readonly', width=20)
        combo.pack(side=tk.LEFT, padx=5)
        setattr(self, f'_ps_{key}', var)

    # Checkboxes
    bool_settings = [
        ("Notifications", 'notifications'),
        ("Alert on Blocked Content", 'alert_blocked'),
        ("Alert on New Connection", 'alert_connect'),
        ("Auto-Assign Profile", 'auto_profile'),
        ("Enable Schedule", 'schedule_active'),
        ("Email Alerts", 'email_alerts'),
    ]
    bool_vars = {}
    for label, key in bool_settings:
        var = tk.BooleanVar(value=self.parental_settings.get(key, False))
        cb = ttk.Checkbutton(frame, text=label, variable=var, style='Pro.TButton')
        cb.pack(anchor=tk.W, pady=2, padx=5)
        bool_vars[key] = var

    # Email field
    email_row = ttk.Frame(frame, style='Pro.TFrame')
    email_row.pack(fill=tk.X, pady=4)
    ttk.Label(email_row, text="Alert Email:", style='Pro.TLabel').pack(side=tk.LEFT, padx=5)
    email_var = tk.StringVar(value=self.parental_settings.get('alert_email', ''))
    ttk.Entry(email_row, textvariable=email_var, width=30, font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

    def save_settings():
        for key in ['default_profile', 'block_method']:
            var = getattr(self, f'_ps_{key}', None)
            if var:
                self.parental_settings[key] = var.get()
        for key, var in bool_vars.items():
            self.parental_settings[key] = var.get()
        self.parental_settings['alert_email'] = email_var.get()
        self.save_data()
        self.update_parental_stats()
        self.log("Parental settings saved", "PARENTAL")
        dialog.destroy()

    ttk.Button(frame, text="💾 Save Settings", command=save_settings,
               style='Pro.TButton').pack(pady=15)

    # Update settings display
    self._update_parental_settings_display()

def _get_alert_count_by_severity(self, severity):
    """Count alerts by severity level"""
    return len([a for a in self.rogue_alerts if a.get('severity') == severity])

def infrastructure_add_dialog(self):
    """Dialog to add approved infrastructure"""
    dialog = tk.Toplevel(self.root)
    dialog.title("Add Approved Infrastructure")
    dialog.geometry("500x420")
    dialog.configure(bg=self.colors['bg'])

    fields_frame = ttk.Frame(dialog, style='Pro.TFrame')
    fields_frame.pack(padx=20, pady=10, fill=tk.X)

    fields = [
        ('Name/Label:', 'name_var', ''),
        ('Type (router/ap/gateway/collector):', 'type_var', 'router'),
        ('IP Address:', 'ip_var', ''),
        ('MAC Address:', 'mac_var', ''),
        ('SSID (for wireless):', 'ssid_var', ''),
        ('Subnet (CIDR):', 'subnet_var', ''),
        ('Location/Floor:', 'loc_var', ''),
    ]
    vars_dict = {}
    for label_text, var_name, default in fields:
        ttk.Label(fields_frame, text=label_text, style='Pro.TLabel').pack(anchor=tk.W, pady=(5, 0))
        var = tk.StringVar(value=default)
        vars_dict[var_name] = var
        ttk.Entry(fields_frame, textvariable=var, font=('Consolas', 11), width=40).pack(fill=tk.X, pady=2)

    def save_infrastructure():
        name = vars_dict['name_var'].get().strip()
        ip = vars_dict['ip_var'].get().strip()
        mac = vars_dict['mac_var'].get().strip()
        if not name and not ip:
            messagebox.showwarning("Input", "Enter a name or IP address")
            return
        inf_id = mac.upper() if mac else ip
        now = datetime.now().isoformat()
        self.infrastructure[inf_id] = {
            'name': name or ip,
            'type': vars_dict['type_var'].get(),
            'ip': ip,
            'mac': mac.upper() if mac else '',
            'ssid': vars_dict['ssid_var'].get(),
            'subnet': vars_dict['subnet_var'].get(),
            'location': vars_dict['loc_var'].get(),
            'first_seen': now,
            'last_seen': now,
            'active': True,
            'approved': True,
        }
        self.save_data()
        self.log(f"Infrastructure added: {name or ip}", "SUCCESS")
        self.refresh_infrastructure_display()
        dialog.destroy()

    btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
    btn_frame.pack(pady=15)
    ttk.Button(btn_frame, text="✅ Save", command=save_infrastructure, style='Pro.TButton').pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="❌ Cancel", command=dialog.destroy, style='Pro.TButton').pack(side=tk.LEFT, padx=5)

def infrastructure_edit_dialog(self, inf_id):
    """Edit existing infrastructure entry"""
    info = self.infrastructure.get(inf_id, {})
    if not info:
        return

    dialog = tk.Toplevel(self.root)
    dialog.title(f"Edit Infrastructure - {info.get('name', inf_id)}")
    dialog.geometry("500x450")
    dialog.configure(bg=self.colors['bg'])

    fields_frame = ttk.Frame(dialog, style='Pro.TFrame')
    fields_frame.pack(padx=20, pady=10, fill=tk.X)

    fields = {
        'name_var': ('Name/Label:', info.get('name', '')),
        'type_var': ('Type (router/ap/gateway/collector):', info.get('type', 'router')),
        'ip_var': ('IP Address:', info.get('ip', '')),
        'mac_var': ('MAC Address:', info.get('mac', '')),
        'ssid_var': ('SSID:', info.get('ssid', '')),
        'subnet_var': ('Subnet:', info.get('subnet', '')),
        'loc_var': ('Location:', info.get('location', '')),
    }
    vars_dict = {}
    for var_name, (label_text, default) in fields.items():
        ttk.Label(fields_frame, text=label_text, style='Pro.TLabel').pack(anchor=tk.W, pady=(5, 0))
        var = tk.StringVar(value=default)
        vars_dict[var_name] = var
        ttk.Entry(fields_frame, textvariable=var, font=('Consolas', 11), width=40).pack(fill=tk.X, pady=2)

    # Approved checkbox
    approve_var = tk.BooleanVar(value=info.get('approved', True))
    approve_frame = ttk.Frame(fields_frame, style='Pro.TFrame')
    approve_frame.pack(fill=tk.X, pady=10)
    tk.Checkbutton(approve_frame, text="Approved", variable=approve_var,
                  bg=self.colors['bg'], fg=self.colors['text'],
                  selectcolor=self.colors['bg'], font=('Arial', 10)).pack(anchor=tk.W)

    def save_changes():
        self.infrastructure[inf_id]['name'] = vars_dict['name_var'].get()
        self.infrastructure[inf_id]['type'] = vars_dict['type_var'].get()
        self.infrastructure[inf_id]['ip'] = vars_dict['ip_var'].get()
        self.infrastructure[inf_id]['mac'] = vars_dict['mac_var'].get().upper()
        self.infrastructure[inf_id]['ssid'] = vars_dict['ssid_var'].get()
        self.infrastructure[inf_id]['subnet'] = vars_dict['subnet_var'].get()
        self.infrastructure[inf_id]['location'] = vars_dict['loc_var'].get()
        self.infrastructure[inf_id]['approved'] = approve_var.get()
        self.infrastructure[inf_id]['last_seen'] = datetime.now().isoformat()
        self.save_data()
        self.refresh_infrastructure_display()
        dialog.destroy()

    btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
    btn_frame.pack(pady=15)
    ttk.Button(btn_frame, text="💾 Save", command=save_changes, style='Pro.TButton').pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="❌ Cancel", command=dialog.destroy, style='Pro.TButton').pack(side=tk.LEFT, padx=5)

def infrastructure_remove(self, inf_id):
    """Remove infrastructure entry"""
    info = self.infrastructure.get(inf_id, {})
    if messagebox.askyesno("Remove", f"Remove {info.get('name', inf_id)} from infrastructure?"):
        del self.infrastructure[inf_id]
        self.save_data()
        self.refresh_infrastructure_display()
        self.log(f"Infrastructure removed: {info.get('name', inf_id)}", "INFO")

def rogue_investigate(self, alert_idx=None):
    """Show investigation details for a rogue alert"""
    if alert_idx is None:
        selection = self.parental_rogue_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Select a rogue alert first")
            return
        item = self.parental_rogue_tree.item(selection[0])
        tags = item.get('tags', ())
        alert_idx = int(tags[0]) if tags else 0

    try:
        if 0 <= alert_idx < len(self.rogue_alerts):
            alert = list(self.rogue_alerts)[alert_idx]
            msg = (
                f"🔍 Investigation Details\n"
                f"{'=' * 50}\n"
                f"Timestamp: {alert.get('timestamp', 'N/A')}\n"
                f"Device:    {alert.get('device_id', 'N/A')}\n"
                f"Location:  {alert.get('location', 'Unknown')}\n"
                f"Evidence:  {alert.get('evidence', 'N/A')}\n"
                f"Previous:  {alert.get('prev_state', 'N/A')}\n"
                f"New:       {alert.get('new_state', 'N/A')}\n"
                f"Severity:  {alert.get('severity', 'N/A')}\n"
                f"Confidence: {alert.get('confidence', 'N/A')}\n"
                f"\nRecommended: {alert.get('investigation_step', 'N/A')}\n"
            )
            messagebox.showinfo("Investigation", msg)
    except Exception as e:
        self.log(f"Investigation error: {e}", "WARNING")

def rogue_acknowledge(self):
    """Acknowledge selected rogue alert"""
    selection = self.parental_rogue_tree.selection()
    if not selection:
        messagebox.showinfo("Info", "Select a rogue alert first")
        return
    try:
        item = self.parental_rogue_tree.item(selection[0])
        tags = item.get('tags', ())
        if tags:
            idx = int(tags[0])
            alerts_list = list(self.rogue_alerts)
            if 0 <= idx < len(alerts_list):
                alerts_list[idx]['acknowledged'] = True
                self.rogue_alerts = deque(alerts_list, maxlen=5000)
                self.refresh_rogue_alerts_display()
    except Exception as e:
        self.log(f"Acknowledge error: {e}", "WARNING")

def rogue_clear_all(self):
    """Clear all rogue alerts"""
    if messagebox.askyesno("Clear Alerts", "Clear all rogue infrastructure alerts?"):
        self.rogue_alerts.clear()
        self.refresh_rogue_alerts_display()
        self.log("Rogue alerts cleared", "INFO")

def refresh_infrastructure_display(self):
    """Refresh the approved infrastructure treeview"""
    try:
        if not hasattr(self, 'parental_infra_tree'):
            return
        self.parental_infra_tree.delete(*self.parental_infra_tree.get_children())
        for inf_id, info in sorted(self.infrastructure.items()):
            status = '🟢 Online' if info.get('active') else '🔴 Offline'
            approved = '✅' if info.get('approved') else '❌'
            self.parental_infra_tree.insert('', tk.END, values=(
                info.get('name', inf_id),
                info.get('ip', ''),
                info.get('mac', ''),
                info.get('type', ''),
                status,
                approved,
                info.get('location', ''),
            ), tags=(inf_id,))
    except Exception as e:
        self.log(f"Infra display error: {e}", "WARNING")

def refresh_rogue_alerts_display(self):
    """Refresh the rogue alerts treeview"""
    try:
        if not hasattr(self, 'parental_rogue_tree'):
            return
        self.parental_rogue_tree.delete(*self.parental_rogue_tree.get_children())
        for idx, alert in enumerate(self.rogue_alerts):
            ts = alert.get('timestamp', '')
            if len(ts) > 19:
                ts = ts[11:19]  # HH:MM:SS
            device_id = alert.get('device_id', '')
            if len(device_id) > 20:
                device_id = device_id[:17] + '...'
            severity = alert.get('severity', 'medium')
            sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
            confidence = alert.get('confidence', 'low')
            conf_icon = {'high': '✅', 'medium': '◐', 'low': '○'}.get(confidence, '?')
            new_state = alert.get('new_state', '')
            acked = '✓' if alert.get('acknowledged') else '○'
            self.parental_rogue_tree.insert('', 0, values=(
                ts, device_id, f"{sev_icon} {severity}",
                new_state, f"{conf_icon} {confidence}", acked
            ), tags=(str(idx),))
    except Exception as e:
        self.log(f"Rogue display error: {e}", "WARNING")

def refresh_child_transitions_display(self):
    """Refresh the child network transitions treeview"""
    try:
        if not hasattr(self, 'parental_transitions_tree'):
            return
        self.parental_transitions_tree.delete(*self.parental_transitions_tree.get_children())
        # Show recent transitions from rogue alerts that relate to child devices
        for alert in list(self.rogue_alerts)[-50:]:
            if 'child' in alert.get('investigation_step', '').lower() or                    'device' in alert.get('evidence', '').lower():
                ts = alert.get('timestamp', '')
                if len(ts) > 19:
                    ts = ts[11:19]
                self.parental_transitions_tree.insert('', 0, values=(
                    ts,
                    alert.get('device_id', ''),
                    alert.get('prev_state', ''),
                    alert.get('new_state', ''),
                    '✅' if alert.get('dns_coverage') else '❌',
                ))
    except Exception as e:
        self.log(f"Transitions display error: {e}", "WARNING")

def refresh_topology_display(self):
    """Refresh the network topology treeview"""
    try:
        if not hasattr(self, 'parental_topology_tree'):
            return
        self.parental_topology_tree.delete(*self.parental_topology_tree.get_children())

        # Add gateway as root
        gw = self.get_gateway()
        if gw and gw != 'Unknown':
            gw_node = self.parental_topology_tree.insert('', tk.END, values=(
                '🌐 Gateway', gw, self.get_hostname(gw), '🟢',
            ), open=True)

            # Add subnets
            for net in self.available_networks:
                subnet_node = self.parental_topology_tree.insert(gw_node, tk.END, values=(
                    '📡 Subnet', net, '', '🟢',
                ), open=True)

                # Add devices on this subnet
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item)['values']
                    ip = values[0]
                    try:
                        network = ipaddress.IPv4Network(net, strict=False)
                        if ipaddress.IPv4Address(ip) in network:
                            hostname = values[1] if len(values) > 1 else ''
                            status = '🟢' if 'Online' in values[5] else '🔴'
                            self.parental_topology_tree.insert(subnet_node, tk.END, values=(
                                '💻 Device', ip, hostname, status,
                            ))
                    except:
                        pass

            # Add known infrastructure
            for inf_id, info in self.infrastructure.items():
                if info.get('approved'):
                    inf_type = {'router': '🌐', 'ap': '📶', 'gateway': '🌐', 'collector': '📡'}.get(info.get('type', ''), '🖥')
                    status = '🟢' if info.get('active') else '🔴'
                    self.parental_topology_tree.insert('', tk.END, values=(
                        f'{inf_type} {info.get("type", "device")}',
                        info.get('ip', ''),
                        info.get('name', ''),
                        status,
                    ))
    except Exception as e:
        self.log(f"Topology display error: {e}", "WARNING")

def refresh_timeline_display(self):
    """Refresh the investigation timeline text"""
    try:
        if not hasattr(self, 'parental_timeline_text'):
            return
        self.parental_timeline_text.delete(1.0, tk.END)
        self.parental_timeline_text.insert(1.0, "📋 Investigation Timeline\n")
        self.parental_timeline_text.insert(tk.END, f"{'=' * 70}\n")

        if not self.rogue_alerts:
            self.parental_timeline_text.insert(tk.END, "\nNo events recorded. Infrastructure monitoring idle.\n")
            return

        for alert in list(self.rogue_alerts)[-100:]:
            ts = alert.get('timestamp', '')
            if len(ts) > 19:
                ts_display = ts[:19]
            else:
                ts_display = ts
            sev = alert.get('severity', 'medium')
            sev_str = {'critical': '🔴 CRIT', 'high': '🟠 HIGH', 'medium': '🟡 MED', 'low': '🟢 LOW'}.get(sev, '⚪ ???')
            line = (
                f"[{ts_display}] {sev_str} | {alert.get('new_state', '')}\n"
                f"    Device: {alert.get('device_id', '')} | Location: {alert.get('location', 'Unknown')}\n"
                f"    Evidence: {alert.get('evidence', '')}\n"
                f"    {alert.get('prev_state', '')} → {alert.get('new_state', '')}\n"
                f"    Confidence: {alert.get('confidence', '')} | Step: {alert.get('investigation_step', '')}\n"
                f"{'─' * 70}\n"
            )
            self.parental_timeline_text.insert(tk.END, line)

        self.parental_timeline_text.see(tk.END)
    except Exception as e:
        self.log(f"Timeline display error: {e}", "WARNING")

def toggle_infrastructure_monitoring(self):
    """Toggle infrastructure monitoring on/off"""
    if self.infrastructure_monitoring:
        self.infrastructure_monitoring = False
        self.parental_infra_monitor_btn.config(text="▶ Start Infra Monitor", bg=self.colors['accent'])
        self.log("Infrastructure monitoring stopped", "INFO")
    else:
        self.infrastructure_monitoring = True
        self.parental_infra_monitor_btn.config(text="⏹ Stop Infra Monitor", bg=self.colors['danger'])
        self.log("Starting infrastructure monitoring...", "INFO")
        # Run initial discovery
        threading.Thread(target=self.update_topology, daemon=True).start()

def _on_infra_tree_double_click(self):
    """Handle double-click on infrastructure tree"""
    try:
        selection = self.parental_infra_tree.selection()
        if selection:
            item = self.parental_infra_tree.item(selection[0])
            tags = item.get('tags', ())
            if tags:
                self.infrastructure_edit_dialog(tags[0])
    except Exception as e:
        self.log(f"Infra tree click error: {e}", "WARNING")

def _infra_remove_selected(self):
    """Remove selected infrastructure entry"""
    try:
        selection = self.parental_infra_tree.selection()
        if selection:
            item = self.parental_infra_tree.item(selection[0])
            tags = item.get('tags', ())
            if tags:
                self.infrastructure_remove(tags[0])
    except Exception as e:
        self.log(f"Infra remove error: {e}", "WARNING")


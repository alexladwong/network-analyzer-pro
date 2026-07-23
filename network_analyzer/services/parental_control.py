"""
parental_control module — extracted from main.py
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

def get_remaining_time(self, ip, profile):
    """Calculate remaining screen time for a device today"""
    if not profile.get('time_limit', 0):
        return 999
    today = datetime.now().strftime("%Y-%m-%d")
    used = 0
    for entry in self.activity_log:
        if entry.get('ip') == ip and entry.get('date', '').startswith(today):
            used += entry.get('duration', 1)
    return max(0, profile['time_limit'] - used)

def is_curfew_active(self, profile):
    """Check if current time falls within curfew for a profile"""
    if not profile:
        return False
    now = datetime.now()
    is_weekend = now.weekday() >= 5  # Saturday=5, Sunday=6

    if is_weekend and profile.get('weekend_diff', False):
        curfew_start = profile.get('weekend_curfew_start', '')
        curfew_end = profile.get('weekend_curfew_end', '')
    else:
        curfew_start = profile.get('curfew_start', '')
        curfew_end = profile.get('curfew_end', '')

    if not curfew_start or not curfew_end:
        return False

    try:
        start_h, start_m = map(int, curfew_start.split(':'))
        end_h, end_m = map(int, curfew_end.split(':'))
        now_min = now.hour * 60 + now.minute
        start_min = start_h * 60 + start_m
        end_min = end_h * 60 + end_m

        if start_min <= end_min:
            # Normal range (e.g., 07:00-21:00 means active during day)
            # For curfew, we check if outside this range
            return now_min < start_min or now_min > end_min
        else:
            # Overnight range (e.g., 21:00-07:00)
            return now_min >= start_min or now_min <= end_min
    except:
        return False

def _update_parental_settings_display(self):
    """Update the settings summary text in the tab"""
    try:
        s = self.parental_settings
        text = (f"Profile: {s.get('default_profile','child')} | "
                f"Filter: {s.get('block_method','none')} | "
                f"Schedule: {'On' if s.get('schedule_active',True) else 'Off'} | "
                f"Alerts: {'On' if s.get('alert_blocked',True) else 'Off'}")
        if hasattr(self, 'parental_settings_text'):
            self.parental_settings_text.config(text=text)
    except:
        pass

def _get_activity_stats(self, device_ip=None, days=1):
    """Get activity statistics for reporting"""
    today = datetime.now()
    cutoff = today.strftime("%Y-%m-%d")
    if days > 1:
        from datetime import timedelta
        cutoff_date = today - timedelta(days=days)
        cutoff = cutoff_date.strftime("%Y-%m-%d")

    filtered = []
    for entry in self.activity_log:
        entry_date = entry.get('date', '')
        if entry_date >= cutoff:
            if device_ip and entry.get('ip') != device_ip:
                continue
            filtered.append(entry)

    return filtered

def parental_daily_report(self):
    """Generate daily activity report"""
    report = self._build_report(days=1)
    self._show_report("📊 Daily Activity Report", report)

def parental_weekly_report(self):
    """Generate weekly activity summary"""
    report = self._build_report(days=7)
    self._show_report("📈 Weekly Summary Report", report)

def _build_report(self, days=1):
    """Build a text report for the given number of days"""
    activities = self._get_activity_stats(days=days)
    today = datetime.now().strftime("%Y-%m-%d")

    report = f"Parental Control Report\n"
    report += f"{'=' * 60}\n"
    report += f"Period: Last {days} day(s) ({today})\n"
    report += f"Total Queries: {len(activities)}\n"
    report += f"Blocked: {sum(1 for e in activities if e.get('blocked'))}\n"
    report += f"Allowed: {sum(1 for e in activities if not e.get('blocked'))}\n\n"

    # Per device breakdown
    devices = {}
    for entry in activities:
        dev = entry.get('device_name', entry.get('ip', 'Unknown'))
        if dev not in devices:
            devices[dev] = {'total': 0, 'blocked': 0, 'domains': {}}
        devices[dev]['total'] += 1
        if entry.get('blocked'):
            devices[dev]['blocked'] += 1
        domain = entry.get('domain', 'Unknown')
        if domain not in devices[dev]['domains']:
            devices[dev]['domains'][domain] = 0
        devices[dev]['domains'][domain] += 1

    for dev_name, stats in sorted(devices.items()):
        report += f"\n📱 {dev_name}\n"
        report += f"{'─' * 40}\n"
        report += f"  Queries: {stats['total']} | Blocked: {stats['blocked']}\n"
        if stats['domains']:
            top = sorted(stats['domains'].items(), key=lambda x: -x[1])[:10]
            report += f"  Top Domains:\n"
            for domain, count in top:
                report += f"    {domain}: {count}\n"

    # Blocked attempts
    blocked = [e for e in activities if e.get('blocked')]
    if blocked:
        report += f"\n🛡️ Blocked Attempts ({len(blocked)})\n"
        report += f"{'─' * 40}\n"
        for entry in blocked[-20:]:
            report += f"  [{entry.get('time','')}] {entry.get('domain','')} "
            report += f"({entry.get('category','')}) - {entry.get('device_name','')}\n"

    # Time spent estimate (rough)
    online_time = len(activities) * 0.5  # rough estimate: 30s per query
    hours = int(online_time // 60)
    minutes = int(online_time % 60)
    report += f"\n⏱ Estimated Online Time: {hours}h {minutes}m\n"

    return report

def _show_report(self, title, report):
    """Display a report in a dialog"""
    dialog = tk.Toplevel(self.root)
    dialog.title(title)
    dialog.geometry("650x500")
    dialog.configure(bg=self.colors['bg'])

    text_widget = tk.Text(dialog, bg=self.colors['secondary'], fg=self.colors['text'],
                          font=('Consolas', 10), wrap=tk.WORD, bd=0, highlightthickness=0)
    text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    text_widget.insert(1.0, report)

    btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
    btn_frame.pack(fill=tk.X, padx=10, pady=10)
    ttk.Button(btn_frame, text="💾 Save", style='Pro.TButton',
               command=lambda: self._save_report(report)).pack(side=tk.LEFT, padx=2)
    ttk.Button(btn_frame, text="Close", style='Pro.TButton',
               command=dialog.destroy).pack(side=tk.RIGHT, padx=2)

def _save_report(self, report):
    """Save report to file"""
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            with open(filename, 'w') as f:
                f.write(report)
            self.log(f"Report saved to {filename}", "SUCCESS")
            messagebox.showinfo("Saved", f"Report saved to:\n{filename}")
    except Exception as e:
        self.log(f"Report save error: {e}", "ERROR")

def parental_export_report(self):
    """Export parental report as text/HTML"""
    report = self._build_report(days=1)
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("HTML files", "*.html"), ("All files", "*.*")]
        )
        if not filename:
            return

        ext = os.path.splitext(filename)[1].lower()
        if ext == '.html':
            html = self._report_to_html(report)
            with open(filename, 'w') as f:
                f.write(html)
        else:
            with open(filename, 'w') as f:
                f.write(report)

        self.log(f"Report exported to {filename}", "SUCCESS")
        messagebox.showinfo("Export Complete", f"Report saved to:\n{filename}")
    except Exception as e:
        self.log(f"Report export error: {e}", "ERROR")

def _report_to_html(self, report):
    """Convert report text to simple HTML"""
    lines = report.split('\n')
    html_parts = [
        '<!DOCTYPE html><html><head><meta charset="utf-8">',
        '<title>Parental Control Report</title>',
        '<style>body{background:#0a0a12;color:#e0e0e0;font-family:Arial;padding:20px}',
        'h1{color:#6c5ce7}pre{color:#00d4aa;font-family:Consolas}',
        '.blocked{color:#ff6b6b}.allowed{color:#00d4aa}</style></head><body>',
        f'<h1>🔞 Parental Control Report</h1>',
        f'<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>',
        f'<pre>',
    ]
    for line in lines:
        escaped = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        if 'BLOCKED' in line or 'Blocked' in line:
            html_parts.append(f'<span class="blocked">{escaped}</span>')
        else:
            html_parts.append(escaped)
    html_parts.append('</pre></body></html>')
    return '\n'.join(html_parts)

def periodic_parental_check(self):
    """Periodic check for schedule enforcement and alerts (called from auto_refresh)"""
    try:
        if not self.parental_settings.get('schedule_active', True):
            return

        # Check curfew for all known devices
        for ip, dev_info in self.known_devices.items():
            profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
            profile = self.parental_profiles.get(profile_name, {})
            if self.is_curfew_active(profile):
                # Log curfew activity if device is online
                for item in self.device_tree.get_children():
                    values = self.device_tree.item(item)['values']
                    if values[0] == ip and ('Online' in values[5] or 'Gateway' in values[5]):
                        self.log(f"Curfew active for {dev_info.get('device_name', ip)}", "PARENTAL")
                        break

        # Refresh parental display
        self.refresh_parental_display()
        self.update_parental_stats()
        self._update_parental_settings_display()
    except:
        pass

def discover_routers(self):
    """Discover all routers/gateways on all active subnets"""
    routers = {}
    try:
        current_gw = self.get_gateway()
        if current_gw and current_gw != 'Unknown':
            gw_mac = self.get_mac_address(current_gw)
            routers[current_gw] = {
                'ip': current_gw,
                'mac': gw_mac,
                'type': 'gateway',
                'source': 'route_table',
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'active': True,
            }
        # Check all discovered networks for their gateways
        for net in self.available_networks:
            try:
                network = ipaddress.IPv4Network(net, strict=False)
                gw_candidate = str(network[1])  # Usually .1 is gateway
                if gw_candidate != current_gw:
                    gw_mac2 = self.get_mac_address(gw_candidate)
                    if gw_mac2 != 'Unknown':
                        routers[gw_candidate] = {
                            'ip': gw_candidate,
                            'mac': gw_mac2,
                            'type': 'gateway',
                            'source': 'subnet_discovery',
                            'first_seen': datetime.now().isoformat(),
                            'last_seen': datetime.now().isoformat(),
                            'active': True,
                        }
            except:
                pass
    except Exception as e:
        self.log(f"Router discovery error: {e}", "WARNING")
    return routers

def discover_dhcp_servers(self):
    """Detect DHCP servers via ARP and known gateway MACs"""
    dhcp_servers = {}
    try:
        # Check ARP table for DHCP-related activity
        if platform.system() != 'Windows':
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if ':' in line:
                    match = re.search(r'(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))', line)
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if match and ip_match:
                        mac = match.group(1).upper()
                        ip = ip_match.group()
                        # Known DHCP server ports (67/68)
                        if self._is_port_open(ip, 67, timeout=0.5):
                            dhcp_servers[ip] = {
                                'ip': ip, 'mac': mac,
                                'type': 'dhcp_server',
                                'source': 'port_67_scan',
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                            }
        # The current gateway is often the DHCP server
        gw = self.get_gateway()
        if gw and gw != 'Unknown' and gw not in dhcp_servers:
            dhcp_servers[gw] = {
                'ip': gw, 'mac': self.get_mac_address(gw),
                'type': 'dhcp_server',
                'source': 'gateway_assumption',
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
            }
    except Exception as e:
        self.log(f"DHCP discovery error: {e}", "WARNING")
    return dhcp_servers

def _is_port_open(self, ip, port, timeout=0.3):
    """Quick TCP port check"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def wireless_scan(self):
    """Perform passive wireless scan (macOS airport or Scapy)"""
    results = {}
    try:
        # macOS: Use airport command
        if platform.system() == 'Darwin':
            airport_path = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
            if os.path.exists(airport_path):
                result = subprocess.run([airport_path, '-s'], capture_output=True, text=True, timeout=15)
                for line in result.stdout.split('\n')[1:]:
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        ssid = parts[0]
                        bssid = parts[1] if len(parts) > 1 else ''
                        rssi = parts[2] if len(parts) > 2 else '0'
                        channel = parts[3] if len(parts) > 3 else '0'
                        if bssid:
                            bssid_upper = bssid.upper()
                            now = datetime.now().isoformat()
                            if bssid_upper in self.wireless_scan_cache:
                                self.wireless_scan_cache[bssid_upper]['last_seen'] = now
                                self.wireless_scan_cache[bssid_upper]['rssi'] = rssi
                            else:
                                self.wireless_scan_cache[bssid_upper] = {
                                    'ssid': ssid, 'bssid': bssid_upper, 'rssi': rssi,
                                    'channel': channel, 'first_seen': now, 'last_seen': now,
                                    'approved': False,
                                }
                            results[bssid_upper] = self.wireless_scan_cache[bssid_upper]
        # Linux: Use iwlist or nmcli
        elif platform.system() == 'Linux':
            try:
                result = subprocess.run(['iwlist', 'scan'], capture_output=True, text=True, timeout=20)
                current_bssid = None
                for line in result.stdout.split('\n'):
                    if 'Address:' in line:
                        current_bssid = line.split('Address:')[-1].strip().upper()
                    elif 'ESSID:' in line and current_bssid:
                        ssid = line.split('ESSID:"')[1].split('"')[0] if '"' in line else ''
                        now = datetime.now().isoformat()
                        if current_bssid not in self.wireless_scan_cache:
                            self.wireless_scan_cache[current_bssid] = {
                                'ssid': ssid, 'bssid': current_bssid, 'rssi': '0',
                                'channel': '0', 'first_seen': now, 'last_seen': now,
                                'approved': False,
                            }
                        results[current_bssid] = self.wireless_scan_cache[current_bssid]
            except:
                pass
    except Exception as e:
        self.log(f"Wireless scan error: {e}", "WARNING")
    return results

def discover_topology(self):
    """Map network topology: gateway -> APs -> subnets -> devices"""
    topology = {}
    try:
        gw = self.get_gateway()
        if gw and gw != 'Unknown':
            entry = {
                'mac': self.get_mac_address(gw),
                'name': self.get_hostname(gw),
                'subnets': list(self.available_networks),
                'aps': [],
                'devices': [],
                'dhcp_servers': [],
                'last_seen': datetime.now().isoformat(),
            }
            # Add known devices
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                ip = values[0]
                if self._is_same_subnet(ip, gw):
                    entry['devices'].append(ip)
            # Check for DHCP servers
            dhcp = self.discover_dhcp_servers()
            for dhcp_ip in dhcp:
                entry['dhcp_servers'].append(dhcp_ip)
            topology[gw] = entry
        self.network_topology = topology
    except Exception as e:
        self.log(f"Topology discovery error: {e}", "WARNING")
    return topology

def _is_same_subnet(self, ip1, ip2):
    """Check if two IPs are on the same subnet"""
    try:
        for net in self.available_networks:
            network = ipaddress.IPv4Network(net, strict=False)
            if ipaddress.IPv4Address(ip1) in network and ipaddress.IPv4Address(ip2) in network:
                return True
    except:
        pass
    return False

def _get_device_subnet(self, ip):
    """Get the subnet a device belongs to"""
    try:
        for net in self.available_networks:
            network = ipaddress.IPv4Network(net, strict=False)
            if ipaddress.IPv4Address(ip) in network:
                return net
    except:
        pass
    return 'Unknown'

def detect_rogue_dhcp(self, approved_list=None):
    """Detect unauthorized DHCP servers"""
    if approved_list is None:
        approved_list = [v.get('ip') for v in self.infrastructure.values()
                       if v.get('approved') and v.get('type') == 'dhcp_server']
    alerts = []
    try:
        detected = self.discover_dhcp_servers()
        for dhcp_ip, dhcp_info in detected.items():
            if dhcp_ip not in approved_list:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'device_id': dhcp_ip,
                    'location': 'Unknown',
                    'evidence': f"DHCP server detected on port 67 at {dhcp_ip}",
                    'prev_state': 'unknown',
                    'new_state': 'rogue_dhcp',
                    'severity': 'high',
                    'confidence': 'medium',
                    'investigation_step': f"Check if {dhcp_ip} is a known router. Verify with 'arp -a' on gateway.",
                }
                alerts.append(alert)
                self.rogue_alerts.append(alert)
                self.log(f"⚠️ Rogue DHCP detected: {dhcp_ip}", "SECURITY")
    except Exception as e:
        self.log(f"Rogue DHCP detection error: {e}", "WARNING")
    return alerts

def detect_rogue_ssid(self, approved_bssids=None, approved_ssids=None):
    """Detect unauthorized wireless networks"""
    if approved_bssids is None:
        approved_bssids = {v.get('mac', '').upper() for v in self.infrastructure.values()
                         if v.get('approved') and v.get('type') in ('ap', 'router')}
    if approved_ssids is None:
        approved_ssids = {v.get('ssid', '') for v in self.infrastructure.values()
                        if v.get('approved') and v.get('ssid')}
    alerts = []
    try:
        scan_results = self.wireless_scan()
        for bssid, info in scan_results.items():
            is_approved_bssid = bssid in approved_bssids
            is_approved_ssid = info.get('ssid', '') in approved_ssids
            if not is_approved_bssid:
                # Check for SSID spoofing
                if is_approved_ssid:
                    severity = 'critical'
                    step = f"SSID '{info.get('ssid')}' is spoofed by unknown BSSID {bssid}. Verify with physical inspection."
                else:
                    severity = 'medium'
                    step = f"Unknown AP {bssid} ({info.get('ssid')}) detected. Check if it belongs to a neighbor."
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'device_id': bssid,
                    'location': 'Unknown',
                    'evidence': f"Wireless scan detected BSSID {bssid} with SSID '{info.get('ssid')}'",
                    'prev_state': 'not_seen',
                    'new_state': 'rogue_ap',
                    'severity': severity,
                    'confidence': 'high' if is_approved_ssid else 'medium',
                    'investigation_step': step,
                }
                alerts.append(alert)
                self.rogue_alerts.append(alert)
                self.log(f"⚠️ Rogue AP detected: {bssid} ({info.get('ssid')})", "SECURITY")
    except Exception as e:
        self.log(f"Rogue SSID detection error: {e}", "WARNING")
    return alerts

def detect_nat_boundary(self):
    """Detect new NAT boundaries via TTL changes"""
    alerts = []
    try:
        gw = self.get_gateway()
        if gw and gw != 'Unknown':
            # Check known devices for TTL anomalies
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                ip = values[0]
                if ip == gw:
                    continue
                try:
                    result = subprocess.run(['ping', '-c', '1', '-t', '1', ip],
                                           capture_output=True, text=True, timeout=3)
                    if 'Time to live exceeded' in result.stdout:
                        # This could be a NAT boundary
                        alert = {
                            'timestamp': datetime.now().isoformat(),
                            'device_id': ip,
                            'location': 'Unknown',
                            'evidence': f"TTL=1 ping returned 'Time to live exceeded' from {ip}",
                            'prev_state': 'direct',
                            'new_state': 'nat_boundary',
                            'severity': 'medium',
                            'confidence': 'low',
                            'investigation_step': f"Device {ip} might be a router or behind NAT. Check its ports and MAC.",
                        }
                        alerts.append(alert)
                        self.rogue_alerts.append(alert)
                except:
                    pass
    except Exception as e:
        self.log(f"NAT detection error: {e}", "WARNING")
    return alerts

def track_device_session(self, ip, mac, hostname=''):
    """Record current network session for a device"""
    try:
        gw = self.get_gateway()
        subnet = self._get_device_subnet(ip)
        now = datetime.now()
        device_id = mac if mac and mac != 'Unknown' else ip

        if device_id not in self.device_sessions:
            self.device_sessions[device_id] = []

        sessions = self.device_sessions[device_id]
        if sessions and sessions[-1].get('disconnected') is None:
            # Update current session
            sessions[-1]['gateway'] = gw
            sessions[-1]['subnet'] = subnet
            sessions[-1]['dns_coverage'] = self.dns_monitoring
            sessions[-1]['policy_coverage'] = self.parental_settings.get('block_method') != 'none'
            sessions[-1]['managed'] = self._is_managed_network(subnet, gw)
        else:
            # New session
            sessions.append({
                'device_id': device_id,
                'mac': mac,
                'hostname': hostname,
                'gateway': gw,
                'ap': '',
                'ssid': '',
                'bssid': '',
                'subnet': subnet,
                'location': self.known_devices.get(ip, {}).get('location', 'Unknown'),
                'connected': now.isoformat(),
                'disconnected': None,
                'dns_coverage': self.dns_monitoring,
                'policy_coverage': self.parental_settings.get('block_method') != 'none',
                'managed': self._is_managed_network(subnet, gw),
            })
            # Keep max 100 sessions per device
            while len(sessions) > 100:
                sessions.pop(0)
    except Exception as e:
        self.log(f"Session tracking error: {e}", "WARNING")

def close_device_session(self, ip, mac=''):
    """Close the current session for a device"""
    device_id = mac if mac and mac != 'Unknown' else ip
    try:
        if device_id in self.device_sessions:
            sessions = self.device_sessions[device_id]
            if sessions and sessions[-1].get('disconnected') is None:
                sessions[-1]['disconnected'] = datetime.now().isoformat()
    except Exception as e:
        self.log(f"Session close error: {e}", "WARNING")

def _is_managed_network(self, subnet, gateway):
    """Check if a network is in the approved infrastructure"""
    for inf_id, inf_info in self.infrastructure.items():
        if inf_info.get('approved'):
            if inf_info.get('ip') == gateway:
                return True
            if subnet and inf_info.get('subnet') == subnet:
                return True
    return False

def detect_network_transition(self, ip, mac=''):
    """Detect when a child device changes networks"""
    alerts = []
    try:
        dev_info = self.known_devices.get(ip, {})
        profile_name = dev_info.get('profile', self.parental_settings.get('default_profile', 'child'))
        if profile_name not in ('child', 'teen'):
            return alerts  # Only monitor child/teen devices

        device_id = mac if mac and mac != 'Unknown' else ip
        sessions = self.device_sessions.get(device_id, [])
        if len(sessions) < 2:
            return alerts

        prev = sessions[-2]
        curr = sessions[-1]

        # Check for network transition
        if prev.get('gateway') and curr.get('gateway') and prev['gateway'] != curr['gateway']:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'device_id': device_id,
                'location': dev_info.get('location', 'Unknown'),
                'evidence': f"Device moved from gateway {prev['gateway']} to {curr['gateway']}",
                'prev_state': f"gateway:{prev.get('gateway')}",
                'new_state': f"gateway:{curr.get('gateway')}",
                'severity': 'high',
                'confidence': 'high',
                'investigation_step': f"Verify {ip} ({dev_info.get('device_name', '')}) is still under policy coverage.",
            }
            alerts.append(alert)
            self.rogue_alerts.append(alert)
            self.log(f"⚠️ Child device {ip} changed gateway: {prev['gateway']} -> {curr['gateway']}", "SECURITY")

        # Check DNS coverage loss
        if prev.get('dns_coverage') and not curr.get('dns_coverage'):
            alert = {
                'timestamp': datetime.now().isoformat(),
                'device_id': device_id,
                'location': dev_info.get('location', 'Unknown'),
                'evidence': f"DNS monitoring coverage lost for device {ip}",
                'prev_state': 'dns_covered',
                'new_state': 'dns_uncovered',
                'severity': 'high',
                'confidence': 'high',
                'investigation_step': f"Check if {ip} moved to unmanaged network or disabled monitoring.",
            }
            alerts.append(alert)
            self.rogue_alerts.append(alert)
            self.log(f"⚠️ DNS coverage lost for child device {ip}", "SECURITY")

        # Check managed -> unmanaged transition
        if prev.get('managed') and not curr.get('managed'):
            alert = {
                'timestamp': datetime.now().isoformat(),
                'device_id': device_id,
                'location': dev_info.get('location', 'Unknown'),
                'evidence': f"Device {ip} moved from managed to unmanaged network",
                'prev_state': 'managed_network',
                'new_state': 'unmanaged_network',
                'severity': 'critical',
                'confidence': 'high',
                'investigation_step': f"Device {ip} ({dev_info.get('device_name', '')}) may be on cellular or neighbor WiFi.",
            }
            alerts.append(alert)
            self.rogue_alerts.append(alert)
            self.log(f"⚠️ Child device {ip} left managed network", "SECURITY")
    except Exception as e:
        self.log(f"Transition detection error: {e}", "WARNING")
    return alerts

def verify_infrastructure(self):
    """Verify all approved infrastructure is still present and responsive"""
    changes = []
    try:
        for inf_id, inf_info in list(self.infrastructure.items()):
            ip = inf_info.get('ip', '')
            was_active = inf_info.get('active', False)
            if ip and ip != 'Unknown':
                # Ping the device
                try:
                    ping3.ping(ip, timeout=1)
                    is_active = True
                except:
                    is_active = False
            else:
                is_active = was_active  # Can't verify without IP

            inf_info['active'] = is_active
            if was_active and not is_active:
                changes.append(f"Infrastructure '{inf_info.get('name', inf_id)}' ({ip}) went offline")
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'device_id': inf_id,
                    'location': inf_info.get('location', 'Unknown'),
                    'evidence': f"Ping timeout for {ip}",
                    'prev_state': 'online',
                    'new_state': 'offline',
                    'severity': 'high',
                    'confidence': 'high',
                    'investigation_step': f"Check if {inf_info.get('name', ip)} is powered on and connected.",
                }
                self.rogue_alerts.append(alert)
                self.log(f"⚠️ Infrastructure offline: {inf_info.get('name', inf_id)}", "SECURITY")
            elif not was_active and is_active:
                changes.append(f"Infrastructure '{inf_info.get('name', inf_id)}' ({ip}) is back online")
                self.log(f"Infrastructure online: {inf_info.get('name', inf_id)}", "INFO")
    except Exception as e:
        self.log(f"Infrastructure verification error: {e}", "WARNING")
    self.topology_last_verified = datetime.now().isoformat()
    return changes

def update_topology(self):
    """Full topology refresh: discover, detect, verify"""
    try:
        # 1. Discover current state
        self.discover_topology()
        routers = self.discover_routers()
        dhcp = self.discover_dhcp_servers()

        # 2. Detect rogues
        rogue_dhcp = self.detect_rogue_dhcp()
        rogue_ssid = self.detect_rogue_ssid()
        nat_issues = self.detect_nat_boundary()

        # 3. Verify infrastructure
        infra_changes = self.verify_infrastructure()

        # 4. Update sessions for all online devices
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item)['values']
            ip = values[0]
            mac = values[2] if len(values) > 2 else ''
            hostname = values[1] if len(values) > 1 else ''
            self.track_device_session(ip, mac, hostname)

        return {
            'routers': len(routers),
            'dhcp_servers': len(dhcp),
            'rogue_dhcp': len(rogue_dhcp),
            'rogue_ssid': len(rogue_ssid),
            'nat_issues': len(nat_issues),
            'infra_changes': len(infra_changes),
        }
    except Exception as e:
        self.log(f"Topology update error: {e}", "WARNING")
        return {}

def periodic_infrastructure_check(self):
    """Periodic infrastructure monitoring (called from auto_refresh)"""
    try:
        if not self.infrastructure_monitoring:
            return
        self.update_topology()
        # Refresh UI if parental tab is visible
        try:
            if hasattr(self, 'parental_infra_tree'):
                self.refresh_infrastructure_display()
            if hasattr(self, 'parental_rogue_tree'):
                self.refresh_rogue_alerts_display()
            if hasattr(self, 'parental_transitions_tree'):
                self.refresh_child_transitions_display()
            if hasattr(self, 'parental_topology_tree'):
                self.refresh_topology_display()
            if hasattr(self, 'parental_timeline_text'):
                self.refresh_timeline_display()
        except:
            pass
    except Exception as e:
        self.log(f"Infrastructure check error: {e}", "WARNING")


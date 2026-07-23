"""
persistence module — extracted from main.py
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

def export_csv(self):
    """Export device data as CSV"""
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not filename:
            return

        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Hostname', 'MAC', 'Vendor', 'Ports', 'Status'])
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                writer.writerow(values)

        self.log(f"CSV exported to {filename}", "SUCCESS")
        messagebox.showinfo("Export Complete", f"CSV saved to:\n{filename}")
    except Exception as e:
        self.log(f"CSV export error: {e}", "ERROR")

def export_pdf(self):
    """Export report as PDF"""
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if not filename:
            return

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
        except ImportError:
            self.log("reportlab not installed. Install: pip install reportlab", "ERROR")
            messagebox.showinfo("Info", "reportlab not installed.\nInstall: pip install reportlab")
            return

        c = canvas.Canvas(filename, pagesize=letter)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, 750, "Network Report")
        c.setFont("Helvetica", 10)

        y = 700
        c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 20
        c.drawString(50, y, f"Devices: {len(self.device_tree.get_children())}")
        y -= 30

        for item in self.device_tree.get_children():
            values = self.device_tree.item(item)['values']
            if y < 50:
                c.showPage()
                y = 750
            c.drawString(50, y, f"IP: {values[0]} | Hostname: {values[1]} | Status: {values[5]}")
            y -= 20

        c.save()
        self.log(f"PDF exported to {filename}", "SUCCESS")
        messagebox.showinfo("Export Complete", f"PDF saved to:\n{filename}")
    except Exception as e:
        self.log(f"PDF export error: {e}", "ERROR")

def export_report(self):
    """Export report"""
    try:
        filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            report = f"🔬 Network Report\n{'=' * 70}\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += f"Total Devices: {len(self.device_tree.get_children())}\n\n"
            for item in self.device_tree.get_children():
                values = self.device_tree.item(item)['values']
                report += f"IP: {values[0]} | Hostname: {values[1]} | Status: {values[5]}\n"
            with open(filename, 'w') as f:
                f.write(report)
            self.log(f"Report exported", "SUCCESS")
            messagebox.showinfo("Export Complete", f"Saved to:\n{filename}")
    except Exception as e:
        self.log(f"Export error: {e}", "ERROR")

def backup_data(self):
    """Backup"""
    try:
        backup_dir = os.path.expanduser("~/network_analyzer_backup")
        os.makedirs(backup_dir, exist_ok=True, mode=0o755)
        # Check for root-owned backup directory and report instead of sudo
        try:
            if os.stat(backup_dir).st_uid == 0 and os.geteuid() != 0:
                self.log(f"Backup dir {backup_dir} is root-owned; run: sudo chown {os.getlogin()} '{backup_dir}'", "ERROR")
        except:
            pass
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"backup_{timestamp}.json")
        data = {
            'backup_time': datetime.now().isoformat(),
            'known_devices': self.known_devices,
            'alerts': self.alerts
        }
        with open(backup_file, 'w') as f:
            json.dump(data, f, indent=2)
        self.log(f"Backup saved to {backup_file}", "SUCCESS")
        messagebox.showinfo("Backup Complete", f"Saved to:\n{backup_file}")
    except Exception as e:
        self.log(f"Backup error: {e}", "ERROR")

def load_data(self):
    """Load data including parental control settings"""
    try:
        data_dir = getattr(self, 'data_dir', None)
        if not data_dir:
            data_dir = os.path.expanduser("~/network_analyzer_data")
        known_file = os.path.join(data_dir, "known_devices.json")
        if os.path.exists(known_file):
            with open(known_file, 'r') as f:
                data = json.load(f)
            # Handle both plain dict and enhanced format
            if isinstance(data, dict) and 'known_devices' in data:
                self.known_devices = data.get('known_devices', {})
                self.parental_settings.update(data.get('parental_settings', {}))
                self.parental_profiles.update(data.get('parental_profiles', {}))
                self.parental_blocked_count = data.get('parental_blocked_count', 0)
                self.content_blocklist = set(data.get('content_blocklist', []))
                self.content_allowlist = set(data.get('content_allowlist', []))
                self.parental_last_reset = data.get('parental_last_reset', datetime.now().isoformat())
                # Load infrastructure data
                loaded_infra = data.get('infrastructure', {})
                if loaded_infra:
                    self.infrastructure = loaded_infra
                loaded_alerts = data.get('rogue_alerts', [])
                if loaded_alerts:
                    self.rogue_alerts = deque(loaded_alerts, maxlen=5000)
                loaded_sessions = data.get('device_sessions', {})
                if loaded_sessions:
                    self.device_sessions = loaded_sessions
                loaded_wireless = data.get('wireless_scan_cache', {})
                if loaded_wireless:
                    self.wireless_scan_cache = loaded_wireless
            else:
                self.known_devices = data
            self.log(f"Loaded {len(self.known_devices)} known devices", "INFO")
    except Exception as e:
        self.log(f"Data load error: {e}", "WARNING")

def save_data(self):
    """Save data atomically with permission safety and rate-limited error logging.

    Writes to a temporary file, flushes, fsyncs, then atomically replaces
    the destination. Never truncates the existing file before a successful write.
    Preserves the last valid known_devices.json on failure.
    Suppresses duplicate permission errors to prevent log flooding.
    """
    from pathlib import Path as _Path

    data_dir_s = getattr(self, 'data_dir', None)
    if not data_dir_s:
        data_dir_s = str(_Path.home() / "network_analyzer_data")
    data_dir = _Path(data_dir_s)

    # Use getattr for _last_save_error in case __init__ hasn't set it yet
    last_err = getattr(self, '_last_save_error', None)

    # Build payload (must match load_data expectations)
    payload = {
        'known_devices': self.known_devices,
        'parental_settings': self.parental_settings,
        'parental_profiles': self.parental_profiles,
        'parental_blocked_count': self.parental_blocked_count,
        'content_blocklist': list(self.content_blocklist),
        'content_allowlist': list(self.content_allowlist),
        'parental_last_reset': self.parental_last_reset,
        'infrastructure': self.infrastructure,
        'rogue_alerts': list(self.rogue_alerts),
        'device_sessions': self.device_sessions,
        'wireless_scan_cache': self.wireless_scan_cache,
    }

    dest = data_dir / "known_devices.json"
    tmp = data_dir / "known_devices.json.tmp"

    try:
        # Step 1: Serialize to temporary file
        tmp_bytes = json.dumps(payload, indent=2, ensure_ascii=False).encode('utf-8')
        tmp.write_bytes(tmp_bytes)
        # Step 2: Flush and fsync the temporary file
        with tmp.open('ab') as f:
            f.flush()
            os.fsync(f.fileno())
        # Step 3: Atomic replace — only replaces on success
        tmp.replace(dest)
        self._last_save_error = None
    except PermissionError as e:
        uid = os.geteuid()
        user = os.getlogin()
        st = dest.stat() if dest.exists() else None
        owner_info = f" (uid {st.st_uid})" if st else ""
        err_key = f"perm:{dest}"
        if err_key != last_err:
            msg = (
                f"Permission denied saving {dest}. "
                f"Current user: {user} (uid {uid}). "
                f"Destination owner{owner_info}. "
                f"Repair with: sudo chown {user} '{dest}' && sudo chown {user} '{data_dir}'"
            )
            self.log(msg, "ERROR")
            self._last_save_error = err_key
    except Exception as e:
        err_key = f"save:{e}"
        if err_key != last_err:
            self.log(f"Data save error: {e}", "WARNING")
            self._last_save_error = err_key
    finally:
        # Clean up temp file if it still exists (failed serialization edge case)
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass

def ensure_data_directory(self):
    """Create data directory with proper permissions and fallbacks.

    Returns a pathlib.Path that is writable by the current user.
    Falls back through three locations on failure.
    """
    from pathlib import Path as _Path

    candidates = [
        _Path.home() / "network_analyzer_data",
        _Path.home() / "Documents" / "network_analyzer_data",
        _Path("/tmp") / "network_analyzer_data",
    ]
    errors = []
    uid = os.geteuid()
    user = os.getlogin()

    for data_dir in candidates:
        try:
            # Must not be a symlink (safety)
            if data_dir.is_symlink():
                errors.append(f"{data_dir} is a symlink — rejecting for safety")
                continue
            if data_dir.exists():
                if not data_dir.is_dir():
                    errors.append(f"{data_dir} exists but is not a directory")
                    continue
                st = data_dir.stat()
                owner = "root" if st.st_uid == 0 else str(st.st_uid)
                if st.st_uid == 0 and uid != 0:
                    msg = (
                        f"{data_dir} is owned by root (uid 0); "
                        f"current user is {user} (uid {uid}). "
                        f"Re-run once as 'sudo chown -R {user} {data_dir}' "
                        f"to repair, or use a different directory."
                    )
                    errors.append(msg)
                    continue
                # Test write access
                test = data_dir / ".write_test"
                try:
                    test.write_text("test", encoding="utf-8")
                    test.unlink()
                except PermissionError:
                    errors.append(f"{data_dir} exists but current user cannot write to it")
                    continue
            else:
                # Create with current uid
                data_dir.mkdir(mode=0o755, parents=True)
            # Check known_devices.json if it exists
            json_file = data_dir / "known_devices.json"
            if json_file.exists():
                try:
                    json_file.open('a').close()
                except PermissionError:
                    errors.append(
                        f"{json_file} exists but is not writable by current user. "
                        f"Run: sudo chown {user} {json_file}"
                    )
                    continue
            self.log(f"📁 Data directory: {data_dir}", "INFO")
            return str(data_dir)
        except PermissionError:
            errors.append(f"Permission denied creating {data_dir}")
            continue
        except Exception as e:
            errors.append(f"{data_dir}: {e}")
            continue

    # All candidates failed
    full_msg = "; ".join(errors)
    self.log(f"❌ Cannot create data directory: {full_msg}", "ERROR")
    # Last resort: /tmp with no further fallback
    tmp = _Path("/tmp") / "network_analyzer_data"
    tmp.mkdir(mode=0o755, exist_ok=True)
    self.log(f"⚠️ Using /tmp fallback: {tmp}", "WARNING")
    return str(tmp)


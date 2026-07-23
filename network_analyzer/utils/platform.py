"""
platform module — extracted from main.py
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

def _check_root(self, feature_name="this feature"):
    """Check root privileges on non-Windows, return True if OK or Windows"""
    if platform.system() == 'Windows':
        return True
    try:
        if os.geteuid() == 0:
            return True
        msg = (f"⚠️ {feature_name} requires root privileges.\n\n"
               f"Run: sudo python3 main.py\n\n"
               f"Without root, raw socket access is blocked by the system.")
        self._show_tool_message(msg)
        return False
    except AttributeError:
        return True

def _restart_with_sudo(self):
    """Restart the application with sudo privileges in a new terminal"""
    if platform.system() == 'Windows':
        messagebox.showinfo("Elevate Required",
                            "Run as Administrator to enable all features.\n\n"
                            "Right-click the terminal and select 'Run as administrator'.")
        return
    try:
        if os.geteuid() == 0:
            messagebox.showinfo("Already Elevated",
                                "Already running with root privileges.")
            return
    except AttributeError:
        return

    python = sys.executable
    script = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else os.path.abspath(__file__)
    reply = messagebox.askyesno("Elevate Privileges",
                                "Restart with sudo to enable:\n"
                                "• Full ARP network scans\n"
                                "• Packet capture\n"
                                "• ARP spoofing detection\n"
                                "• Port scan detection\n"
                                "• Traceroute\n\n"
                                "Restart now?\n\n"
                                "A Terminal window will open for password entry.")
    if not reply:
        return

    self.log("Restarting with sudo in new terminal...", "INFO")
    script_dir = os.path.dirname(script)
    args = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ''

    try:
        if platform.system() == 'Darwin':
            # Write a temporary shell script so quoting is trivial
            import tempfile
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False)
            tmp.write('#!/bin/bash\n')
            tmp.write(f'cd "{script_dir}"\n')
            tmp.write(f'sudo "{python}" "{script}" {args}\n')
            tmp.write(f'rm -- "$0"\n')
            tmp.close()
            os.chmod(tmp.name, 0o755)
            subprocess.Popen(['open', '-a', 'Terminal', tmp.name])
        else:
            # Linux: try common terminal emulators
            launch = f'cd "{script_dir}" && sudo "{python}" "{script}" {args}'
            terminals = [('x-terminal-emulator', '-e', 'bash', '-c'),
                         ('xterm', '-e', 'bash', '-c'),
                         ('gnome-terminal', '--', 'bash', '-c'),
                         ('konsole', '--hold', '-e', 'bash', '-c'),
                         ('xfce4-terminal', '-e', 'bash', '-c')]
            launched = False
            for term_cmd in terminals:
                try:
                    subprocess.Popen(list(term_cmd) + [launch])
                    launched = True
                    break
                except FileNotFoundError:
                    continue
            if not launched:
                messagebox.showerror("Terminal Not Found",
                                     "Could not find a terminal emulator.\n"
                                     "Please run manually:\n\n"
                                     f"sudo {python} {script}")
                return
    except Exception as e:
        self.log(f"Sudo restart error: {e}", "ERROR")
        messagebox.showerror("Error",
                             f"Failed to launch terminal: {e}\n\n"
                             f"Please run manually:\nsudo {python} {script}")


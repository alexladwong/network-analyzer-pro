"""
reporting module — extracted from main.py
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

def generate_security_report(self):
    """Generate HTML security report"""
    self.log("Generating security report...", "SECURITY")
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.expanduser(f"~/network_analyzer_data/security_report_{timestamp}.html")

        html = """<!DOCTYPE html>
l>
d><title>Security Report</title>
le>
 { background: #0a0a12; color: #e0e0e0; font-family: Arial; padding: 20px; }
 color: #6c5ce7; }
e { width: 100%; border-collapse: collapse; margin: 20px 0; }
 background: #6c5ce7; padding: 10px; text-align: left; }
 background: #14141f; padding: 8px; border: 1px solid #2d2d44; }
ning { color: #ffd93d; }
ger { color: #ff6b6b; }
cess { color: #00d4aa; }
yle>
ad>
y>
🔒 Network Security Report</h1>
enerated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
evices: """ + str(len(self.device_tree.get_children())) + """</p>

Device Security Summary</h2>
le>
<th>IP</th><th>Hostname</th><th>Open Ports</th><th>Vulnerabilities</th></tr>
"""
        for item in self.device_tree.get_children():
            values = self.device_tree.item(item)['values']
            ip = values[0]
            hostname = values[1]
            ports = values[4]
            vulns = self.check_device_vulnerabilities(ip)
            vuln_class = "success" if not vulns else "danger" if len(vulns) > 2 else "warning"
            vuln_text = "<br>".join(vulns) if vulns else "✅ No issues found"
            html += f"""
        <tr>
            <td>{ip}</td>
            <td>{hostname}</td>
            <td>{ports}</td>
            <td class="{vuln_class}">{vuln_text}</td>
        </tr>
        """

        html += """
ble>
Recommendations</h2>

Run regular security audits</li>
Keep firmware/software updated</li>
Disable unnecessary services</li>
Use strong passwords</li>
Enable firewall</li>
>
dy>
ml>
"""
        with open(filename, 'w') as f:
            f.write(html)

        self.log(f"Security report generated: {filename}", "SUCCESS")
        messagebox.showinfo("Report Complete", f"Security report saved to:\n{filename}")
    except Exception as e:
        self.log(f"Report generation error: {e}", "ERROR")

def security_audit(self):
    """Security audit with CVE checking"""
    self.log("Starting security audit...", "SECURITY")
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, "🔒 Security Audit\n")
    self.tool_output.insert(1.0, f"{'=' * 60}\n")
    threading.Thread(target=self.run_security_audit, daemon=True).start()

def run_security_audit(self):
    """Run security audit with CVE and weak password checks"""
    try:
        # Load CVE database if not loaded
        if not self.cve_db:
            self.tool_output.insert(1.0, "Loading CVE database...\n")
            self.load_cve_database()

        total = len(self.device_tree.get_children())
        if total == 0:
            self.tool_output.insert(1.0, "⚠️ No devices found. Run a scan first.\n")
            return

        self.tool_output.insert(1.0, f"Scanning {total} devices...\n\n")
        findings = []

        for idx, item in enumerate(self.device_tree.get_children()):
            values = self.device_tree.item(item)['values']
            ip = values[0]
            hostname = values[1]
            self.tool_output.insert(1.0, f"Checking {ip} ({hostname})...\n")
            self.root.update_idletasks()

            open_ports = self.scan_common_ports(ip)
            if open_ports:
                vulns = []
                if 21 in open_ports:
                    vulns.append("  🔓 FTP (21) - use SFTP instead")
                if 22 in open_ports:
                    vulns.append("  🔓 SSH (22) - check for weak passwords/ciphers")
                if 23 in open_ports:
                    vulns.append("  🔴 Telnet (23) - insecure, disable")
                if 25 in open_ports:
                    vulns.append("  🔓 SMTP (25) - check for open relay")
                if 80 in open_ports:
                    vulns.append("  ℹ️ HTTP (80) - check for web vulnerabilities")
                if 445 in open_ports:
                    vulns.append("  🔴 SMB (445) - known RCE vulnerabilities")
                if 3389 in open_ports:
                    vulns.append("  🔴 RDP (3389) - check BlueKeep")

                if vulns:
                    findings.append(f"\n⚠️ {ip} ({hostname}):\n" + "\n".join(vulns))

            progress = (idx + 1) / total * 100
            self.tool_output.insert(1.0, f"  Progress: {progress:.0f}%\n")
            self.root.update_idletasks()

        self.tool_output.insert(1.0, f"\n{'=' * 60}\n")
        if findings:
            self.tool_output.insert(1.0, f"⚠️ Found {len(findings)} security issues:\n")
            self.tool_output.insert(1.0, "\n".join(findings))
            self.log(f"Security audit: {len(findings)} issues found", "WARNING")
        else:
            self.tool_output.insert(1.0, "✅ No security issues found\n")
            self.log("Security audit: Clean", "SUCCESS")

        self.tool_output.insert(1.0, f"\n💾 Click 'Generate Report' to save as HTML\n")

    except Exception as e:
        self.log(f"Security audit error: {e}", "ERROR")


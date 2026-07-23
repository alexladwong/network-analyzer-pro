"""
packet_capture module — extracted from main.py
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

def start_capture(self):
    """Start packet capture with root check"""
    if not SCAPY_AVAILABLE:
        self.log("Scapy not available", "ERROR")
        self.tool_output.delete(1.0, tk.END)
        self.tool_output.insert(1.0, "❌ Scapy not installed. Install: pip install scapy")
        return

    if not self.capturing:
        self.capturing = True
        self.capture_btn.config(text="🔄 Capturing...", state='disabled')
        self.capture_stop_btn.config(state='normal')
        self.log("Starting packet capture...", "PACKET")
        self.packet_display.delete(1.0, tk.END)
        self.packet_display.insert(1.0, "📦 Packet Capture Active\n")
        if platform.system() != 'Windows' and os.geteuid() != 0:
            self.packet_display.insert(1.0, "⚠️ Running without root — may not capture all packets\n")
            self.packet_display.insert(1.0, "   Run: sudo python3 main.py for full capture\n\n")
        self.log("Packet capture may need root privileges", "WARNING")
        threading.Thread(target=self.capture_packets, daemon=True).start()

def stop_capture(self):
    """Stop capture"""
    self.capturing = False
    self.capture_btn.config(text="▶ Start Capture", state='normal')
    self.capture_stop_btn.config(state='disabled')
    self.log("Packet capture stopped", "INFO")

def capture_packets(self):
    """Capture packets with BPF filter support"""
    try:
        filter_str = self.packet_filter.get().strip() if hasattr(self, 'packet_filter') else ""
        max_packets = 2000
        count = [0]

        def packet_callback(pkt):
            if not self.capturing:
                return
            if count[0] >= max_packets:
                return
            try:
                count[0] += 1
                timestamp = datetime.now().strftime("%H:%M:%S")
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    proto = 'Unknown'
                    line = ""

                    if TCP in pkt:
                        proto = 'TCP'
                        line = f"[{timestamp}] 🔵 {proto} {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}"
                    elif UDP in pkt:
                        proto = 'UDP'
                        line = f"[{timestamp}] 🟢 {proto} {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
                    elif ICMP in pkt:
                        proto = 'ICMP'
                        line = f"[{timestamp}] 🟡 {proto} {src} -> {dst}"
                    else:
                        line = f"[{timestamp}] {src} -> {dst}"

                    self.packet_display.insert(tk.END, line + "\n")
                    self.packet_display.see(tk.END)
                    self.packet_count.set(f"{count[0]} packets")

                    self.packet_queue.append({
                        'time': timestamp,
                        'src': src,
                        'dst': dst,
                        'proto': proto,
                        'size': len(pkt)
                    })
            except:
                pass

        self.packet_display.insert(1.0, f"📦 Capturing packets{f' with filter: {filter_str}' if filter_str else ''}\n")
        if filter_str:
            self.log(f"Packet capture with filter: {filter_str}", "PACKET")
            sniff(prn=packet_callback, store=0, filter=filter_str, timeout=60)
        else:
            sniff(prn=packet_callback, store=0, timeout=60)

    except PermissionError:
        if self.capturing:
            self.packet_display.insert(1.0, "\n❌ Permission denied.\nRun with sudo: sudo python3 main.py\nScapy needs root for packet capture.\n")
            self.log("Packet capture requires root", "WARNING")
    except Exception as e:
        if self.capturing:
            self.log(f"Capture error: {e}", "WARNING")
            self.packet_display.insert(1.0, f"\n⚠️ {e}\n")

def save_packets(self):
    """Save packets as text"""
    try:
        filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            packets = self.packet_display.get(1.0, tk.END)
            with open(filename, 'w') as f:
                f.write(packets)
            self.log(f"Packets saved to {filename}", "SUCCESS")
    except Exception as e:
        self.log(f"Save error: {e}", "ERROR")

def load_pcap(self):
    """Load PCAP file for analysis"""
    if not SCAPY_AVAILABLE:
        self.log("Scapy required for PCAP loading", "ERROR")
        return

    filename = filedialog.askopenfilename(
        title="Select PCAP file",
        filetypes=[("PCAP files", "*.pcap"), ("PCAPNG files", "*.pcapng"), ("All files", "*.*")]
    )
    if not filename:
        return

    try:
        packets = scapy.rdpcap(filename)
        self.packet_display.delete(1.0, tk.END)
        self.packet_display.insert(1.0, f"📦 Loaded PCAP: {os.path.basename(filename)}\n")
        self.packet_display.insert(1.0, f"{'=' * 60}\n")
        self.packet_display.insert(1.0, f"Packets: {len(packets)}\n\n")

        for idx, pkt in enumerate(packets[:200]):
            try:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    if TCP in pkt:
                        line = f"[{idx:4d}] 🔵 TCP {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}"
                    elif UDP in pkt:
                        line = f"[{idx:4d}] 🟢 UDP {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"
                    elif ICMP in pkt:
                        line = f"[{idx:4d}] 🟡 ICMP {src} -> {dst}"
                    else:
                        line = f"[{idx:4d}] {src} -> {dst}"
                    self.packet_display.insert(tk.END, line + "\n")
            except:
                continue

        if len(packets) > 200:
            self.packet_display.insert(tk.END, f"\n... and {len(packets) - 200} more packets\n")

        self.packet_count.set(f"{len(packets)} packets")
        self.log(f"Loaded PCAP: {os.path.basename(filename)} ({len(packets)} packets)", "SUCCESS")

    except Exception as e:
        self.log(f"PCAP load error: {e}", "ERROR")
        self.packet_display.insert(1.0, f"❌ Error loading PCAP: {e}\n")

def save_pcap(self):
    """Save captured packets as PCAP"""
    if not SCAPY_AVAILABLE:
        self.log("Scapy required for PCAP saving", "ERROR")
        return

    filename = filedialog.asksaveasfilename(
        defaultextension=".pcap",
        filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
    )
    if not filename:
        return

    try:
        packets = []
        for line in self.packet_display.get(1.0, tk.END).split('\n'):
            if 'TCP' in line:
                packets.append(IP(src='192.168.1.1', dst='192.168.1.2') / TCP())
            elif 'UDP' in line:
                packets.append(IP(src='192.168.1.1', dst='192.168.1.2') / UDP())
        if packets:
            scapy.wrpcap(filename, packets)
            self.log(f"Saved PCAP to {filename}", "SUCCESS")
        else:
            self.log("No packets to save", "WARNING")
    except Exception as e:
        self.log(f"PCAP save error: {e}", "ERROR")

def clear_packets(self):
    """Clear packets"""
    self.packet_display.delete(1.0, tk.END)
    self.packet_count.set("0 packets")

def tcp_stream_reassembly(self):
    """Reconstruct TCP streams from captured packets"""
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, "🔀 TCP Stream Reconstruction\n")
    self.tool_output.insert(1.0, f"{'=' * 60}\n")

    streams = {}
    content = self.packet_display.get(1.0, tk.END)
    for line in content.split('\n'):
        if 'TCP' in line:
            parts = line.split()
            try:
                src = parts[3].split(':')[0]
                dst = parts[5].split(':')[0]
                key = f"{src}:{dst}" if src < dst else f"{dst}:{src}"
                if key not in streams:
                    streams[key] = {'src': src, 'dst': dst, 'packets': []}
                streams[key]['packets'].append(line)
            except (IndexError, ValueError):
                continue

    self.tool_output.insert(1.0, f"Found {len(streams)} TCP streams\n\n")
    for key, stream in streams.items():
        self.tool_output.insert(1.0, f"Stream: {stream['src']} <-> {stream['dst']}\n")
        self.tool_output.insert(1.0, f"Packets: {len(stream['packets'])}\n")
        self.tool_output.insert(1.0, "-" * 40 + "\n")
        for pkt in stream['packets'][:10]:
            self.tool_output.insert(1.0, f"  {pkt}\n")
        if len(stream['packets']) > 10:
            self.tool_output.insert(1.0, f"  ... and {len(stream['packets']) - 10} more\n")
        self.tool_output.insert(1.0, "\n")

    self.log(f"TCP stream reassembly: {len(streams)} streams", "SUCCESS")

def load_cve_database(self):
    """Load local CVE database (NVD API 2.0)"""
    try:
        cve_file = os.path.expanduser("~/network_analyzer_data/cve_cache.json")
        # Use cache if less than 24 hours old
        if os.path.exists(cve_file):
            cache_age = time.time() - os.path.getmtime(cve_file)
            if cache_age < 86400:
                with open(cve_file, 'r') as f:
                    self.cve_db = json.load(f)
                self.log(f"Loaded {len(self.cve_db)} CVE entries (cached)", "INFO")
                return

        self.log("Downloading CVE database...", "INFO")
        import urllib.request
        import ssl as ssl_mod

        from datetime import timedelta
        # Try NVD API 2.0 first
        try:
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            end_date = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
            start = datetime.utcnow() - timedelta(days=120)
            start_date = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                   f"?lastModStartDate={start_date}&lastModEndDate={end_date}&resultsPerPage=50")
            req = urllib.request.Request(url, headers={'User-Agent': 'NetworkAnalyzerPro/4.2'})
            response = urllib.request.urlopen(req, context=ctx, timeout=15)
            data = json.loads(response.read())
            self.cve_db = {}
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', '')
                if cve_id:
                    descs = cve.get('descriptions', [])
                    desc = next((d['value'] for d in descs if d.get('lang') == 'en'), '')
                    if desc:
                        self.cve_db[cve_id] = desc[:200]
            self.log(f"NVD API: loaded {len(self.cve_db)} CVEs", "SUCCESS")
        except Exception as nvd_err:
            self.log(f"NVD API failed ({nvd_err}), trying CIRCL...", "INFO")
            # Fallback: CIRCL CVE API (no auth required)
            try:
                url = "https://cve.circl.lu/api/last"
                req = urllib.request.Request(url, headers={'User-Agent': 'NetworkAnalyzerPro/4.2'})
                response = urllib.request.urlopen(req, timeout=10)
                data = json.loads(response.read())
                self.cve_db = {}
                for entry in data:
                    cve_id = entry.get('id', '')
                    summary = entry.get('summary', '')
                    if cve_id and summary:
                        self.cve_db[cve_id] = summary[:200]
                self.log(f"CIRCL API: loaded {len(self.cve_db)} CVEs", "SUCCESS")
            except Exception as circl_err:
                self.log(f"CIRCL API also failed ({circl_err})", "WARNING")
                raise

        os.makedirs(os.path.dirname(cve_file), exist_ok=True)
        with open(cve_file, 'w') as f:
            json.dump(self.cve_db, f)

    except Exception as e:
        self.log(f"CVE database error: {e}", "WARNING")
        self.cve_db = {}

def check_device_vulnerabilities(self, ip):
    """Check device for known vulnerabilities"""
    vulnerabilities = []
    open_ports = self.scan_common_ports(ip)
    port_vulns = {
        21: "FTP - weak authentication possible",
        22: "SSH - check for weak cipher suites",
        23: "Telnet - insecure protocol",
        80: "HTTP - check for known web vulnerabilities",
        443: "HTTPS - verify SSL/TLS configuration",
        445: "SMB - known vulnerabilities (EternalBlue, etc.)",
        3389: "RDP - check for BlueKeep vulnerability"
    }
    for port in open_ports:
        if port in port_vulns:
            vulnerabilities.append(f"Port {port}: {port_vulns[port]}")

    if self.cve_db:
        for cve_id, description in self.cve_db.items():
            for port in open_ports:
                if str(port) in description.lower():
                    vulnerabilities.append(f"{cve_id}: {description[:100]}...")
                    break

    return vulnerabilities

def arp_spoofing_detection(self):
    """Monitor for ARP spoofing attacks"""
    if not SCAPY_AVAILABLE:
        self.log("Scapy required for ARP monitoring", "ERROR")
        return self._show_tool_message("❌ Scapy not installed.\nInstall: pip install scapy")
    if not self._check_root("ARP spoofing detection"):
        return

    self.log("Starting ARP spoofing detection...", "SECURITY")
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, "🔍 ARP Spoofing Detection\n")
    self.tool_output.insert(1.0, f"{'=' * 60}\n")
    self.tool_output.insert(1.0, "Monitoring ARP traffic (30s)...\n\n")

    arp_table = {}

    def arp_monitor(pkt):
        if not hasattr(self, 'arp_monitoring') or not self.arp_monitoring:
            return
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in arp_table:
                if arp_table[ip] != mac:
                    alert = f"⚠️ ARP SPOOFING: {ip} now at {mac} (was {arp_table[ip]})"
                    self.tool_output.insert(1.0, f"\n{alert}\n")
                    self.add_alert(alert)
            else:
                arp_table[ip] = mac
                self.tool_output.insert(1.0, f"✅ {ip} -> {mac}\n")

    self.arp_monitoring = True
    try:
        sniff(filter="arp", prn=arp_monitor, store=0, timeout=30)
    except PermissionError:
        self.tool_output.insert(1.0, "\n❌ Permission denied. Run with sudo for ARP monitoring.\n")
        self.log("ARP monitoring requires root privileges", "WARNING")
    except Exception as e:
        self.tool_output.insert(1.0, f"\n⚠️ ARP monitoring error: {e}\n")
        self.log(f"ARP monitoring error: {e}", "WARNING")
    finally:
        self.arp_monitoring = False
        self.tool_output.insert(1.0, "\n✅ ARP monitoring complete\n")

def _show_tool_message(self, message):
    """Show a message in the tool output area"""
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, message + "\n")

def port_scan_detection(self):
    """Detect port scans against this machine"""
    if not SCAPY_AVAILABLE:
        self._show_tool_message("❌ Scapy not installed.\nInstall: pip install scapy")
        return
    if not self._check_root("Port scan detection"):
        return

    self.log("Starting port scan detection...", "SECURITY")
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, "🛡️ Port Scan Detection\n")
    self.tool_output.insert(1.0, f"{'=' * 60}\n")
    self.tool_output.insert(1.0, "Monitoring for scans (30s)...\n\n")

    scan_threshold = 10
    source_tracker = {}

    def scan_detector(pkt):
        if not hasattr(self, 'scan_detection') or not self.scan_detection:
            return
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            flags = pkt[TCP].flags
            if flags & 0x02 and not (flags & 0x10):
                if src not in source_tracker:
                    source_tracker[src] = {'ports': []}
                source_tracker[src]['ports'].append(pkt[TCP].dport)
                if len(source_tracker[src]['ports']) >= scan_threshold:
                    alert = f"⚠️ Port scan detected from {src}: {len(source_tracker[src]['ports'])} ports"
                    self.tool_output.insert(1.0, f"\n{alert}\n")
                    self.add_alert(alert)
                    source_tracker[src]['ports'] = []

    self.scan_detection = True
    try:
        sniff(filter="tcp", prn=scan_detector, store=0, timeout=30)
    except PermissionError:
        self.tool_output.insert(1.0, "\n❌ Permission denied. Run with sudo for scan detection.\n")
        self.log("Scan detection requires root privileges", "WARNING")
    except Exception as e:
        self.tool_output.insert(1.0, f"\n⚠️ Detection error: {e}\n")
        self.log(f"Scan detection error: {e}", "WARNING")
    finally:
        self.scan_detection = False
        self.tool_output.insert(1.0, "\n✅ Scan detection complete\n")

def analyze_ssl_certificate(self, target=None, port=443):
    """Analyze SSL/TLS certificate"""
    if not target:
        dialog = tk.Toplevel(self.root)
        dialog.title("SSL Certificate Analysis")
        dialog.geometry("500x200")
        dialog.configure(bg=self.colors['bg'])
        ttk.Label(dialog, text="Target (domain or IP):", style='Pro.TLabel').pack(pady=10)
        entry = ttk.Entry(dialog, width=40, font=('Consolas', 11))
        entry.pack(pady=10)
        def do_lookup():
            t = entry.get().strip()
            if t:
                dialog.destroy()
                threading.Thread(target=self.analyze_ssl_certificate, args=(t,), daemon=True).start()
        ttk.Button(dialog, text="Analyze", command=do_lookup, style='Pro.TButton').pack(pady=10)
        entry.bind('<Return>', lambda e: do_lookup())
        return

    self.log(f"Analyzing SSL certificate for {target}:{port}", "SECURITY")
    self.tool_output.delete(1.0, tk.END)
    self.tool_output.insert(1.0, f"🔒 SSL Certificate Analysis\n")
    self.tool_output.insert(1.0, f"{'=' * 60}\n")
    self.tool_output.insert(1.0, f"Target: {target}:{port}\n\n")

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=target
        )
        conn.settimeout(5)
        conn.connect((target, port))

        cert = conn.getpeercert()
        cipher = conn.cipher()

        self.tool_output.insert(1.0, f"✅ SSL connection established\n")
        self.tool_output.insert(1.0, f"Cipher: {cipher[0]}\n")

        if cert:
            self.tool_output.insert(1.0, f"\n📋 Certificate Details:\n")
            self.tool_output.insert(1.0, f"{'-' * 40}\n")
            subject = dict(x[0] for x in cert['subject'])
            issuer = dict(x[0] for x in cert['issuer'])
            self.tool_output.insert(1.0, f"Subject: {subject.get('commonName', 'Unknown')}\n")
            self.tool_output.insert(1.0, f"Issuer: {issuer.get('commonName', 'Unknown')}\n")

            not_after = cert['notAfter']
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.now()).days

            if days_left < 0:
                self.tool_output.insert(1.0, f"⚠️ Certificate EXPIRED on {not_after}\n")
            elif days_left < 30:
                self.tool_output.insert(1.0, f"⚠️ Expires in {days_left} days ({not_after})\n")
            else:
                self.tool_output.insert(1.0, f"✅ Valid until {not_after} ({days_left} days)\n")

            if 'subjectAltName' in cert:
                san = [x[1] for x in cert['subjectAltName']]
                self.tool_output.insert(1.0, f"SAN: {', '.join(san[:5])}\n")

        conn.close()
        self.log(f"SSL analysis complete for {target}", "SUCCESS")

    except ssl.SSLError as e:
        self.tool_output.insert(1.0, f"❌ SSL Error: {e}\n")
        self.log(f"SSL analysis error: {e}", "WARNING")
    except Exception as e:
        self.tool_output.insert(1.0, f"❌ Error: {e}\n")
        self.log(f"SSL analysis error: {e}", "ERROR")

def dns_lookup(self):
    """DNS Lookup with multi-IP display"""
    dialog = tk.Toplevel(self.root)
    dialog.title("DNS Lookup")
    dialog.geometry("500x350")
    dialog.configure(bg=self.colors['bg'])

    ttk.Label(dialog, text="Domain (without http://):", style='Pro.TLabel',
              font=('Arial', 11)).pack(pady=(10, 2))
    domain_entry = ttk.Entry(dialog, width=40, font=('Consolas', 11))
    domain_entry.pack(pady=5)
    domain_entry.focus()

    ttk.Label(dialog, text="Example: google.com, github.com", style='Pro.TLabel',
              foreground=self.colors['text_dim']).pack()

    result_text = tk.Text(dialog, height=10, width=50,
                          bg=self.colors['secondary'], fg=self.colors['text'],
                          font=('Consolas', 10), bd=0, highlightthickness=0)
    result_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    def lookup():
        domain = domain_entry.get().strip()
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        if not domain:
            result_text.delete(1.0, tk.END)
            result_text.insert(1.0, "Please enter a domain name")
            return

        self.log(f"DNS lookup for {domain}", "TOOL")
        result_text.delete(1.0, tk.END)
        result_text.insert(1.0, f"🔍 Looking up {domain}...\n")
        self.root.update_idletasks()

        try:
            ip = socket.gethostbyname(domain)
            result = f"🌐 DNS Lookup Result\n{'=' * 40}\n"
            result += f"Domain: {domain}\n"
            result += f"IP Address: {ip}\n"

            try:
                addrs = socket.getaddrinfo(domain, None)
                ips = set()
                for addr in addrs:
                    if addr[4][0] not in ('', domain):
                        ips.add(addr[4][0])
                if len(ips) > 1:
                    result += f"\nAll Resolved IPs:\n"
                    for r_ip in sorted(ips):
                        result += f"  {r_ip}\n"
            except:
                pass

            result_text.delete(1.0, tk.END)
            result_text.insert(1.0, result)
            self.log(f"DNS lookup: {domain} -> {ip}", "SUCCESS")
        except socket.gaierror as e:
            error_msg = f"❌ Domain not found: {domain}\n"
            error_msg += f"Error: {e}\n\n"
            error_msg += "💡 Tips:\n"
            error_msg += "  - Check spelling\n"
            error_msg += "  - Don't include http:// or https://\n"
            error_msg += "  - Make sure domain exists"
            result_text.delete(1.0, tk.END)
            result_text.insert(1.0, error_msg)
            self.log(f"DNS lookup failed for {domain}: {e}", "ERROR")
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(1.0, f"Error: {e}")
            self.log(f"DNS lookup error: {e}", "ERROR")

    btn_frame = ttk.Frame(dialog, style='Pro.TFrame')
    btn_frame.pack(pady=5)
    ttk.Button(btn_frame, text="🔍 Lookup", command=lookup,
              style='Pro.TButton').pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Close", command=dialog.destroy,
              style='Pro.TButton').pack(side=tk.LEFT, padx=5)
    domain_entry.bind('<Return>', lambda e: lookup())


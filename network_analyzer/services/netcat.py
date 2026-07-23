"""
netcat module — extracted from main.py
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

def netcat_start(self):
    """Start netcat session with protocol selection"""
    with self.netcat_lock:
        if self.netcat_active:
            self.terminal_display.insert(1.0, "⚠️ Session already active\n")
            return

        target = self.netcat_target.get().strip()
        port_str = self.netcat_port.get().strip()
        protocol = self.netcat_protocol.get()

        if not target:
            self.log("Please enter a target IP", "WARNING")
            return

        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            self.log("Invalid port number", "ERROR")
            return

        self.terminal_display.delete(1.0, tk.END)
        self.terminal_display.insert(1.0, f"🔌 Netcat Session ({protocol.upper()})\n{'=' * 60}\n")

        use_ssl = self.netcat_ssl_enabled.get() and protocol == 'tcp'

        mode = self.netcat_mode.get()
        if mode == "connect":
            self.terminal_display.insert(1.0, f"Connecting to {target}:{port}...\n")
            if use_ssl:
                self.terminal_display.insert(1.0, "🔒 SSL/TLS enabled\n")
            self.log(f"Connecting to {target}:{port} via {protocol.upper()}", "NETCAT")
            self.netcat_btn.config(text="🔄 Connecting...", state='disabled')
            self.netcat_stop_btn.config(state='normal')
            self.netcat_input.config(state='disabled')

            self.netcat_active = True
            self.netcat_running = True

            if use_ssl:
                threading.Thread(target=self.netcat_do_connect_ssl, args=(target, port), daemon=True).start()
            elif protocol == 'udp':
                threading.Thread(target=self.netcat_do_connect_udp, args=(target, port), daemon=True).start()
            else:
                threading.Thread(target=self.netcat_do_connect, args=(target, port), daemon=True).start()
        else:
            self.terminal_display.insert(1.0, f"Listening on port {port}...\n")
            if use_ssl:
                self.terminal_display.insert(1.0, "🔒 SSL/TLS enabled\n")
            self.log(f"Listening on port {port} via {protocol.upper()}", "NETCAT")
            self.netcat_btn.config(text="🔄 Listening...", state='disabled')
            self.netcat_stop_btn.config(state='normal')
            self.netcat_input.config(state='disabled')

            self.netcat_active = True
            self.netcat_running = True

            if protocol == 'udp':
                threading.Thread(target=self.netcat_do_listen_udp, args=(port,), daemon=True).start()
            else:
                threading.Thread(target=self.netcat_do_listen_multi, args=(port,), daemon=True).start()

def netcat_do_connect(self, target, port):
    """Connect to remote - PROPER IMPLEMENTATION"""
    try:
        self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.netcat_sock.settimeout(5)
        self.netcat_sock.connect((target, port))

        self.terminal_display.insert(1.0, f"✅ Connected to {target}:{port}\n")
        self.terminal_display.insert(1.0, f"{'=' * 60}\n")
        self.terminal_display.insert(1.0, "Type messages and press Enter to send\n\n")
        self.log(f"Connected to {target}:{port}", "SUCCESS")

        self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
        self.root.after(0, lambda: self.netcat_input.config(state='normal'))

        threading.Thread(target=self.netcat_do_receive, daemon=True).start()

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        self.terminal_display.insert(1.0, f"❌ Connection failed: {e}\n")
        self.log(f"Connection failed to {target}:{port}: {e}", "ERROR")
        if self.netcat_reconnect.get():
            threading.Thread(target=self.netcat_auto_reconnect, args=(target, port), daemon=True).start()
        else:
            self.netcat_stop()

def netcat_do_connect_ssl(self, target, port):
    """SSL/TLS encrypted connection"""
    try:
        self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.netcat_sock.settimeout(5)
        self.netcat_sock.connect((target, port))

        context = ssl.create_default_context()
        if self.netcat_ssl_insecure.get():
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self.netcat_sock = context.wrap_socket(self.netcat_sock, server_hostname=target)

        self.terminal_display.insert(1.0, f"✅ SSL connection to {target}:{port}\n")
        try:
            self.terminal_display.insert(1.0, f"🔒 Cipher: {self.netcat_sock.cipher()[0]}\n")
        except:
            pass
        self.terminal_display.insert(1.0, f"{'=' * 60}\n")
        self.terminal_display.insert(1.0, "Type messages and press Enter to send\n\n")
        self.log(f"SSL connected to {target}:{port}", "SUCCESS")

        self.root.after(0, lambda: self.netcat_btn.config(text="🔌 🔒 Active", state='normal'))
        self.root.after(0, lambda: self.netcat_input.config(state='normal'))

        threading.Thread(target=self.netcat_do_receive, daemon=True).start()

    except ssl.SSLError as e:
        self.terminal_display.insert(1.0, f"❌ SSL error: {e}\n")
        self.log(f"SSL error: {e}", "ERROR")
        self.netcat_stop()
    except Exception as e:
        self.terminal_display.insert(1.0, f"❌ Connection error: {e}\n")
        self.log(f"Connection error: {e}", "ERROR")
        self.netcat_stop()

def netcat_do_connect_udp(self, target, port):
    """UDP connect mode (connectionless with target fixed)"""
    try:
        self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.netcat_sock.settimeout(1)
        self.netcat_udp_target = (target, port)

        self.terminal_display.insert(1.0, f"✅ UDP session ready to {target}:{port}\n")
        self.terminal_display.insert(1.0, f"{'=' * 60}\n")
        self.terminal_display.insert(1.0, "UDP is connectionless. Messages may be lost.\n\n")
        self.log(f"UDP session ready to {target}:{port}", "SUCCESS")

        self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
        self.root.after(0, lambda: self.netcat_input.config(state='normal'))

        threading.Thread(target=self.netcat_do_receive_udp, daemon=True).start()

    except Exception as e:
        self.terminal_display.insert(1.0, f"❌ UDP setup failed: {e}\n")
        self.log(f"UDP setup failed: {e}", "ERROR")
        self.netcat_stop()

def netcat_do_listen_udp(self, port):
    """UDP listen mode"""
    try:
        self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.netcat_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.netcat_sock.bind(('0.0.0.0', port))
        self.netcat_sock.settimeout(1)

        self.terminal_display.insert(1.0, f"✅ UDP listening on port {port}\n")
        self.terminal_display.insert(1.0, f"{'=' * 60}\n")
        self.log(f"UDP listening on port {port}", "SUCCESS")

        self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
        self.root.after(0, lambda: self.netcat_input.config(state='normal'))

        self.netcat_udp_target = None
        threading.Thread(target=self.netcat_do_receive_udp, daemon=True).start()

    except Exception as e:
        self.terminal_display.insert(1.0, f"❌ UDP listen failed: {e}\n")
        self.log(f"UDP listen failed: {e}", "ERROR")
        self.netcat_stop()

def netcat_do_receive_udp(self):
    """Receive UDP datagrams"""
    try:
        while self.netcat_running and self.netcat_sock:
            try:
                data, addr = self.netcat_sock.recvfrom(65535)
                if data:
                    self.netcat_udp_target = addr
                    if self.netcat_verbose.get():
                        self.show_hexdump(data)
                    else:
                        try:
                            text = data.decode('utf-8', errors='ignore')
                            self.terminal_display.insert(tk.END, f"\n[RECV] {addr[0]}:{addr[1]} -> {text}\n")
                        except:
                            self.terminal_display.insert(tk.END, f"\n[RECV] {addr[0]}:{addr[1]} -> {len(data)} bytes\n")
                    self.terminal_display.see(tk.END)
            except socket.timeout:
                continue
            except Exception as e:
                if self.netcat_running:
                    self.log(f"UDP receive error: {e}", "WARNING")
                break
    except:
        pass
    finally:
        if self.netcat_running:
            self.netcat_stop()

def netcat_do_listen_multi(self, port):
    """Listen with multiple connection support"""
    try:
        self.netcat_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.netcat_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.netcat_server.bind(('0.0.0.0', port))
        self.netcat_server.listen(5)
        self.netcat_server.settimeout(1)

        self.terminal_display.insert(1.0, f"✅ Listening on port {port} (queue: 5)\n")
        self.terminal_display.insert(1.0, "Waiting for connections...\n")
        self.log(f"Listening on port {port} (multi-connection)", "NETCAT")

        self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))

        self.netcat_connections = []
        self.netcat_current_conn = -1

        while self.netcat_running:
            try:
                client, addr = self.netcat_server.accept()
                self.terminal_display.insert(1.0, f"✅ Connection {len(self.netcat_connections) + 1} from {addr[0]}:{addr[1]}\n")
                self.log(f"Connection from {addr[0]}:{addr[1]}", "SUCCESS")

                self.netcat_connections.append(client)
                self.netcat_current_conn = len(self.netcat_connections) - 1

                if len(self.netcat_connections) == 1:
                    self.netcat_sock = client
                    self.root.after(0, lambda: self.netcat_input.config(state='normal'))

                threading.Thread(target=self.netcat_do_receive_multi, args=(client, len(self.netcat_connections) - 1), daemon=True).start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.netcat_running:
                    self.log(f"Accept error: {e}", "WARNING")
                break

        if self.netcat_server:
            self.netcat_server.close()
            self.netcat_server = None

    except Exception as e:
        if self.netcat_running:
            self.terminal_display.insert(1.0, f"❌ Listen failed: {e}\n")
            self.log(f"Listen failed: {e}", "ERROR")
            self.netcat_stop()

def netcat_do_receive_multi(self, client, conn_id):
    """Receive data from a specific connection"""
    try:
        client.settimeout(1)
        while self.netcat_running:
            try:
                data = client.recv(4096)
                if data:
                    if self.netcat_verbose.get():
                        self.show_hexdump(data)
                    else:
                        try:
                            text = data.decode('utf-8', errors='ignore')
                            self.terminal_display.insert(tk.END, f"\n[CONN {conn_id} RECV] {text}\n")
                        except:
                            self.terminal_display.insert(tk.END, f"\n[CONN {conn_id} RECV] {len(data)} bytes (binary)\n")
                    self.terminal_display.see(tk.END)
                else:
                    self.terminal_display.insert(1.0, f"\n❌ Connection {conn_id} closed by peer\n")
                    self.log(f"Connection {conn_id} closed by peer", "WARNING")
                    break
            except socket.timeout:
                continue
            except Exception as e:
                if self.netcat_running:
                    self.terminal_display.insert(1.0, f"\n❌ Connection {conn_id} receive error: {e}\n")
                break
    except:
        pass
    finally:
        try:
            client.close()
        except:
            pass
        if conn_id < len(self.netcat_connections):
            self.netcat_connections[conn_id] = None

def netcat_do_receive(self):
    """Receive data with file transfer detection"""
    receiving_file = False
    file_data = bytearray()
    file_name = ""
    file_size = 0
    file_received = 0

    try:
        self.netcat_sock.settimeout(1)
        while self.netcat_running and self.netcat_sock:
            try:
                data = self.netcat_sock.recv(8192)
                if data:
                    if not receiving_file:
                        try:
                            text = data.decode('utf-8', errors='ignore')
                            if text.startswith('FILE:'):
                                parts = text.strip().split(':')
                                if len(parts) >= 3:
                                    file_name = parts[1]
                                    file_size = int(parts[2])
                                    receiving_file = True
                                    file_received = 0
                                    file_data = bytearray()
                                    self.terminal_display.insert(1.0, f"\n📁 Receiving file: {file_name} ({file_size:,} bytes)\n")
                                    self.terminal_display.insert(1.0, "Progress: ")
                                    data = data[data.find(b'\n') + 1:]
                                else:
                                    if self.netcat_verbose.get():
                                        self.show_hexdump(data)
                                    else:
                                        self.terminal_display.insert(tk.END, f"\n[RECV] {text}\n")
                                    continue
                            else:
                                if self.netcat_verbose.get():
                                    self.show_hexdump(data.encode('utf-8'))
                                else:
                                    self.terminal_display.insert(tk.END, f"\n[RECV] {text}\n")
                                continue
                        except:
                            if self.netcat_verbose.get():
                                self.show_hexdump(data)
                            else:
                                self.terminal_display.insert(tk.END, f"\n[RECV] {len(data)} bytes (binary)\n")
                            continue

                    if receiving_file:
                        file_data.extend(data)
                        file_received += len(data)
                        progress = int((file_received / file_size) * 100)
                        self.terminal_display.insert(tk.END, f"{progress}% ")
                        self.terminal_display.see(tk.END)

                        if file_received >= file_size:
                            save_path = filedialog.asksaveasfilename(
                                initialfile=file_name,
                                defaultextension=".*",
                                filetypes=[("All files", "*.*")]
                            )
                            if save_path:
                                with open(save_path, 'wb') as f:
                                    f.write(file_data)
                                self.terminal_display.insert(1.0, f"\n✅ File received: {save_path}\n")
                                self.log(f"File received: {file_name} ({file_size:,} bytes)", "SUCCESS")
                            else:
                                self.terminal_display.insert(1.0, f"\n⚠️ File save cancelled\n")
                            receiving_file = False
                            file_data = bytearray()
                else:
                    self.terminal_display.insert(1.0, "\n❌ Connection closed by peer\n")
                    self.log("Connection closed by peer", "WARNING")
                    break
            except socket.timeout:
                continue
            except Exception as e:
                if self.netcat_running:
                    self.terminal_display.insert(1.0, f"\n❌ Receive error: {e}\n")
                break
    except:
        pass
    finally:
        if self.netcat_running:
            self.netcat_stop()

def netcat_send(self, event=None):
    """Send data with protocol awareness"""
    if not self.netcat_active or not self.netcat_sock:
        self.log("Not connected", "WARNING")
        return

    data = self.netcat_input.get()
    if not data:
        return

    try:
        if self.netcat_protocol.get() == 'udp':
            self.netcat_send_udp(data)
            return

        self.netcat_sock.send(data.encode('utf-8'))
        self.terminal_display.insert(tk.END, f"\n[SENT] {data}\n")
        self.terminal_display.see(tk.END)
        self.netcat_input.delete(0, tk.END)
    except Exception as e:
        self.log(f"Send error: {e}", "ERROR")
        self.terminal_display.insert(1.0, f"\n❌ Send error: {e}\n")
        self.netcat_stop()

def netcat_send_udp(self, data):
    """Send UDP datagram"""
    try:
        if self.netcat_mode.get() == "connect":
            if hasattr(self, 'netcat_udp_target') and self.netcat_udp_target:
                self.netcat_sock.sendto(data.encode('utf-8'), self.netcat_udp_target)
            else:
                self.log("No UDP target set", "WARNING")
                return
        else:
            target = self.netcat_target.get().strip()
            port = int(self.netcat_port.get().strip())
            self.netcat_sock.sendto(data.encode('utf-8'), (target, port))

        self.terminal_display.insert(tk.END, f"\n[SENT] {data}\n")
        self.terminal_display.see(tk.END)
        self.netcat_input.delete(0, tk.END)
    except Exception as e:
        self.log(f"UDP send error: {e}", "ERROR")

def netcat_send_file(self):
    """Send file over netcat connection"""
    if not self.netcat_active or not self.netcat_sock:
        self.log("No active connection", "WARNING")
        return

    filename = filedialog.askopenfilename(title="Select file to send")
    if not filename:
        return

    try:
        file_size = os.path.getsize(filename)
        self.terminal_display.insert(1.0, f"\n📁 Sending file: {os.path.basename(filename)} ({file_size:,} bytes)\n")
        self.terminal_display.insert(1.0, "Progress: ")

        header = f"FILE:{os.path.basename(filename)}:{file_size}\n"
        self.netcat_sock.send(header.encode('utf-8'))

        sent = 0
        chunk_size = 8192
        with open(filename, 'rb') as f:
            while sent < file_size and self.netcat_running:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                self.netcat_sock.send(chunk)
                sent += len(chunk)
                progress = int((sent / file_size) * 100)
                self.terminal_display.insert(tk.END, f"{progress}% ")
                self.terminal_display.see(tk.END)

        self.terminal_display.insert(1.0, f"\n✅ File sent successfully ({sent:,} bytes)\n")
        self.log(f"File sent: {os.path.basename(filename)} ({sent:,} bytes)", "SUCCESS")

    except Exception as e:
        self.log(f"File send error: {e}", "ERROR")
        self.terminal_display.insert(1.0, f"\n❌ File send failed: {e}\n")

def netcat_receive_file(self):
    """Prompt file receive mode"""
    self.terminal_display.insert(1.0, "\n📁 Ready to receive file. Send a FILE: header from the remote side.\n")
    self.log("File receive mode activated", "NETCAT")

def netcat_auto_reconnect(self, target, port, max_retries=5, base_delay=2):
    """Auto-reconnect with exponential backoff"""
    for retry in range(max_retries):
        if not self.netcat_running:
            return False

        wait = base_delay * (2 ** retry)
        self.terminal_display.insert(1.0, f"⚠️ Reconnecting in {wait}s (attempt {retry + 1}/{max_retries})...\n")
        self.log(f"Reconnect attempt {retry + 1}/{max_retries}", "NETCAT")
        time.sleep(wait)

        if not self.netcat_running:
            return False

        try:
            self.netcat_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.netcat_sock.settimeout(5)
            self.netcat_sock.connect((target, port))
            self.terminal_display.insert(1.0, f"✅ Reconnected to {target}:{port}\n")
            self.log(f"Reconnected to {target}:{port}", "SUCCESS")

            self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Active", state='normal'))
            self.root.after(0, lambda: self.netcat_input.config(state='normal'))
            threading.Thread(target=self.netcat_do_receive, daemon=True).start()
            return True
        except:
            continue

    self.terminal_display.insert(1.0, f"❌ Auto-reconnect failed after {max_retries} attempts\n")
    self.log("Auto-reconnect failed", "ERROR")
    self.netcat_stop()
    return False

def show_hexdump(self, data, max_bytes=1024):
    """Display hexdump of binary data"""
    if not data:
        return

    display_data = data[:max_bytes]
    hex_lines = []

    for i in range(0, len(display_data), 16):
        chunk = display_data[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(48)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_lines.append(f"  {i:04x}: {hex_part}  {ascii_part}")

    self.terminal_display.insert(tk.END, f"\n[HEXDUMP] {len(data)} bytes:\n")
    self.terminal_display.insert(tk.END, '\n'.join(hex_lines) + '\n')

    if len(data) > max_bytes:
        self.terminal_display.insert(tk.END, f"... and {len(data) - max_bytes} more bytes\n")

def netcat_stop(self):
    """Stop netcat - PROPER CLEANUP"""
    with self.netcat_lock:
        if not self.netcat_active and not self.netcat_running:
            return

        self.netcat_running = False
        self.netcat_active = False

        # Close client socket
        if self.netcat_sock:
            try:
                self.netcat_sock.close()
            except:
                pass
            self.netcat_sock = None

        # Close server socket
        if self.netcat_server:
            try:
                self.netcat_server.close()
            except:
                pass
            self.netcat_server = None

        # Close multi-connections
        if hasattr(self, 'netcat_connections'):
            for conn in self.netcat_connections:
                try:
                    if conn:
                        conn.close()
                except:
                    pass
            self.netcat_connections = []

        # Update UI
        self.terminal_display.insert(1.0, "\n🔌 Connection closed\n")
        self.log("Netcat closed", "INFO")

        self.root.after(0, lambda: self.netcat_btn.config(text="🔌 Start", state='normal'))
        self.root.after(0, lambda: self.netcat_stop_btn.config(state='disabled'))
        self.root.after(0, lambda: self.netcat_input.config(state='disabled'))


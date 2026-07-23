"""
theme module — extracted from main.py
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

def setup_styles(self):
    """Configure modern dark theme styles"""
    style = ttk.Style()
    style.theme_use('clam')
    c = self.colors

    # Base frames
    style.configure('Pro.TFrame', background=c['bg'])
    style.configure('Card.TFrame', background=c['secondary'], relief='flat')
    style.configure('Header.TFrame', background=c['bg'])

    # Labels
    style.configure('Pro.TLabel', background=c['bg'], foreground=c['text'])
    style.configure('Card.TLabel', background=c['secondary'], foreground=c['text'])
    style.configure('Heading.TLabel', background=c['bg'], foreground=c['highlight'],
                    font=('Arial', 13, 'bold'))
    style.configure('Title.TLabel', background=c['bg'], foreground=c['text'],
                    font=('Arial', 24, 'bold'))
    style.configure('Status.TLabel', background=c['secondary'],
                    foreground=c['text_dim'], padding=8, font=('Consolas', 9))
    style.configure('Terminal.TFrame', background='#000000')
    style.configure('Terminal.TLabel', background='#000000',
                    foreground=c['terminal'], font=('Courier', 11))

    # Buttons with hover effects
    style.configure('Pro.TButton', background=c['accent'],
                    foreground='white', borderwidth=0, padding=(14, 8),
                    font=('Arial', 10))
    style.map('Pro.TButton',
              background=[('active', c['highlight']), ('pressed', '#5a4bd1')],
              foreground=[('disabled', '#555566')])

    style.configure('Small.TButton', background=c['accent2'],
                    foreground='white', borderwidth=0, padding=(8, 4),
                    font=('Arial', 9))
    style.map('Small.TButton',
              background=[('active', c['highlight']), ('pressed', '#5a4bd1')],
              foreground=[('disabled', '#555566')])

    # Notebook/tabs
    style.configure('Pro.TNotebook', background=c['bg'], borderwidth=0)
    style.configure('Pro.TNotebook.Tab', background=c['secondary'],
                    foreground=c['text_dim'], padding=[20, 9],
                    font=('Arial', 10))
    style.map('Pro.TNotebook.Tab',
              background=[('selected', c['accent']), ('active', '#252540')],
              foreground=[('selected', c['text'])])

    # Treeview
    style.configure('Pro.Treeview', background=c['secondary'],
                    foreground='white', fieldbackground=c['secondary'],
                    rowheight=36, font=('Consolas', 10))
    style.map('Pro.Treeview',
              background=[('selected', c['highlight'])],
              foreground=[('selected', 'white')])

    style.configure('Pro.Treeview.Heading', background=c['accent'],
                    foreground='white', font=('Arial', 11, 'bold'),
                    borderwidth=0)
    style.map('Pro.Treeview.Heading',
              background=[('active', c['highlight'])])

    # LabelFrame
    style.configure('Pro.TLabelframe', background=c['bg'],
                    foreground=c['text'], relief='flat', borderwidth=0)
    style.configure('Pro.TLabelframe.Label', background=c['bg'],
                    foreground=c['highlight'], font=('Arial', 12, 'bold'))

    # Progressbar
    style.configure('Pro.Horizontal.TProgressbar', background=c['highlight'],
                    troughcolor=c['secondary'], bordercolor=c['bg'],
                    lightcolor=c['highlight'], darkcolor=c['highlight'],
                    thickness=12)

    # Scrollbar
    style.configure('Pro.Vertical.TScrollbar', background=c['accent2'],
                    troughcolor=c['bg'], bordercolor=c['bg'],
                    arrowcolor='white')
    style.map('Pro.Vertical.TScrollbar',
              background=[('active', c['highlight'])])

    # Entry
    style.configure('Pro.TEntry', fieldbackground=c['secondary'],
                    foreground='white', bordercolor=c['accent2'],
                    lightcolor=c['accent2'], darkcolor=c['accent2'],
                    padding=6)
    style.map('Pro.TEntry',
              fieldbackground=[('focus', c['accent'])])

    # Radiobutton for scan modes
    style.configure('Pro.TRadiobutton', background=c['bg'],
                    foreground=c['text'], font=('Arial', 10),
                    indicatorbackground=c['secondary'],
                    indicatorforeground=c['highlight'])
    style.map('Pro.TRadiobutton',
              background=[('active', c['accent'])],
              foreground=[('selected', c['text']), ('active', 'white')],
              indicatorbackground=[('selected', c['highlight']), ('active', c['accent2'])])


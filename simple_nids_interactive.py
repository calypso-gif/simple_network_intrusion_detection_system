#!/usr/bin/env python3
"""
simple_nids_interactive.py

Interactive terminal-to-GUI upgrade of a small Network Intrusion Detection System.

Detects:
    - TCP port scans: many DIFFERENT destination ports from one source IP
    - SYN-flood-like behavior: many SYN packets from one source IP

Features:
    - Tkinter dashboard
    - Start / Stop monitoring
    - Interface selection and automatic local-IP detection
    - Live packet/SYN/alert statistics
    - Live activity graph (no matplotlib required)
    - Editable detection thresholds
    - Alert cooldown
    - Trusted-IP whitelist
    - Alert type/IP filtering
    - Alert table with timestamps
    - Automatic CSV logging
    - Manual CSV export
    - Clear alerts/statistics
    - Safe DEMO MODE (simulates detection without sending attack traffic)

Run on Linux with sufficient packet-capture permissions, for example:
    sudo python3 simple_nids_interactive.py

Requirements:
    pip install scapy
    Tkinter is normally included with Python on Linux desktops.
"""

import csv
import os
import queue
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from scapy.all import AsyncSniffer, IP, TCP, conf, get_if_addr, get_if_list


# ---------------------------------------------------------------------------
# Default settings
# ---------------------------------------------------------------------------
DEFAULT_PORT_SCAN_PORT_LIMIT = 15
DEFAULT_PORT_SCAN_TIME_WINDOW = 5
DEFAULT_DOS_SYN_LIMIT = 100
DEFAULT_DOS_TIME_WINDOW = 3
DEFAULT_ALERT_COOLDOWN = 10
DEFAULT_LOG_FILE = "nids_alerts.csv"
DEFAULT_WHITELIST_FILE = "nids_whitelist.txt"
GRAPH_SECONDS = 30


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def detect_default_interface():
    """Try to find the normal outbound interface used by the host."""
    try:
        # Scapy route: (interface, source_ip, gateway)
        route = conf.route.route("8.8.8.8")
        if route and route[0]:
            return str(route[0])
    except Exception:
        pass

    try:
        iface = str(conf.iface)
        if iface:
            return iface
    except Exception:
        pass

    interfaces = get_if_list()
    return interfaces[0] if interfaces else ""


def get_ipv4_for_interface(iface):
    try:
        ip = get_if_addr(iface)
        if ip and ip != "0.0.0.0":
            return ip
    except Exception:
        pass
    return ""


def list_interfaces():
    """Return [(display_name, iface, ip), ...] for usable interfaces."""
    result = []
    for iface in get_if_list():
        try:
            ip = get_ipv4_for_interface(iface)
        except Exception:
            ip = ""
        label = f"{iface}"
        if ip:
            label += f" ({ip})"
        if ip == "127.0.0.1":
            label += " [loopback]"
        result.append((label, iface, ip))
    return result


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------
class DetectionEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.port_scan_port_limit = DEFAULT_PORT_SCAN_PORT_LIMIT
        self.port_scan_time_window = DEFAULT_PORT_SCAN_TIME_WINDOW
        self.dos_syn_limit = DEFAULT_DOS_SYN_LIMIT
        self.dos_time_window = DEFAULT_DOS_TIME_WINDOW
        self.alert_cooldown = DEFAULT_ALERT_COOLDOWN

        # src_ip -> deque[(timestamp, destination_port)]
        self.syn_log = defaultdict(deque)
        self.last_alert_time = {}

        self.alerts = []
        self.whitelist = set()
        self.pending_events = queue.Queue()

        # Statistics
        self.total_tcp_packets = 0
        self.total_syn_packets = 0
        self.unique_source_ips = set()
        self.port_scan_alerts = 0
        self.dos_alerts = 0
        self.started_at = None

        # One entry per second: (timestamp, tcp_count, syn_count)
        self.activity = deque(maxlen=GRAPH_SECONDS + 5)
        self._last_activity_second = None
        self._current_second_tcp = 0
        self._current_second_syn = 0

        self._load_whitelist()
        self._ensure_log_file()

    # -------------------------- settings --------------------------
    def set_thresholds(self, port_limit, port_window, dos_limit, dos_window, cooldown):
        with self.lock:
            self.port_scan_port_limit = int(port_limit)
            self.port_scan_time_window = float(port_window)
            self.dos_syn_limit = int(dos_limit)
            self.dos_time_window = float(dos_window)
            self.alert_cooldown = float(cooldown)

    # -------------------------- whitelist --------------------------
    def _load_whitelist(self):
        try:
            if os.path.exists(DEFAULT_WHITELIST_FILE):
                with open(DEFAULT_WHITELIST_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith("#"):
                            self.whitelist.add(ip)
        except OSError:
            pass

    def _save_whitelist(self):
        try:
            with open(DEFAULT_WHITELIST_FILE, "w", encoding="utf-8") as f:
                for ip in sorted(self.whitelist):
                    f.write(ip + "\n")
        except OSError:
            pass

    def add_whitelist(self, ip):
        ip = ip.strip()
        if not ip:
            return False
        with self.lock:
            self.whitelist.add(ip)
            self._save_whitelist()
        return True

    def remove_whitelist(self, ip):
        with self.lock:
            if ip in self.whitelist:
                self.whitelist.remove(ip)
                self._save_whitelist()
                return True
        return False

    # -------------------------- logging --------------------------
    def _ensure_log_file(self):
        if os.path.exists(DEFAULT_LOG_FILE):
            return
        try:
            with open(DEFAULT_LOG_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "source_ip", "alert_type", "details", "mode"])
        except OSError:
            pass

    def _write_alert_to_log(self, alert):
        try:
            with open(DEFAULT_LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    alert["timestamp"],
                    alert["source_ip"],
                    alert["alert_type"],
                    alert["details"],
                    alert["mode"],
                ])
        except OSError:
            # Logging failure should never stop packet detection.
            pass

    # -------------------------- activity graph --------------------------
    def _touch_activity(self, timestamp, is_syn=False):
        second = int(timestamp)
        if self._last_activity_second is None:
            self._last_activity_second = second

        if second != self._last_activity_second:
            self.activity.append((self._last_activity_second,
                                  self._current_second_tcp,
                                  self._current_second_syn))
            self._current_second_tcp = 0
            self._current_second_syn = 0
            self._last_activity_second = second

        self._current_second_tcp += 1
        if is_syn:
            self._current_second_syn += 1

    # -------------------------- alert creation --------------------------
    def _create_alert(self, src_ip, alert_type, details, mode="LIVE"):
        # Whitelisted sources never generate alerts.
        if src_ip in self.whitelist:
            return False

        current = time.monotonic()
        key = (src_ip, alert_type)
        previous = self.last_alert_time.get(key, 0)
        if current - previous < self.alert_cooldown:
            return False

        self.last_alert_time[key] = current
        alert = {
            "timestamp": now_text(),
            "epoch": time.time(),
            "source_ip": src_ip,
            "alert_type": alert_type,
            "details": details,
            "mode": mode,
        }

        self.alerts.append(alert)
        if alert_type == "PORT SCAN":
            self.port_scan_alerts += 1
        elif alert_type == "DOS (SYN FLOOD)":
            self.dos_alerts += 1

        self._write_alert_to_log(alert)
        self.pending_events.put({"kind": "alert", "alert": alert})
        return True

    # -------------------------- packet processing --------------------------
    def process_packet(self, pkt, my_ip, mode="LIVE"):
        """Process a real Scapy packet. This method is thread-safe."""
        if IP not in pkt or TCP not in pkt:
            return

        timestamp = time.monotonic()
        with self.lock:
            self.total_tcp_packets += 1
            self.unique_source_ips.add(pkt[IP].src)
            self._touch_activity(timestamp, is_syn=False)

        if pkt[IP].dst != my_ip:
            return

        try:
            flags = int(pkt[TCP].flags)
        except (TypeError, ValueError):
            return
        # SYN set (0x02), ACK not set (0x10).
        is_syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
        if not is_syn_only:
            return

        with self.lock:
            self.total_syn_packets += 1
            # The same timestamp is fine; this is only for the live graph.
            self._touch_activity(timestamp, is_syn=True)
            src_ip = pkt[IP].src
            dst_port = int(pkt[TCP].dport)
            self._process_syn(src_ip, dst_port, timestamp, mode)

    def process_syn_event(self, src_ip, dst_port, mode="DEMO"):
        """Feed a synthetic SYN event to the same detector used by real packets."""
        timestamp = time.monotonic()
        with self.lock:
            self.total_tcp_packets += 1
            self.total_syn_packets += 1
            self.unique_source_ips.add(src_ip)
            self._touch_activity(timestamp, is_syn=True)
            self._process_syn(src_ip, int(dst_port), timestamp, mode)

    def _process_syn(self, src_ip, dst_port, timestamp, mode):
        entries = self.syn_log[src_ip]
        entries.append((timestamp, dst_port))

        max_window = max(self.port_scan_time_window, self.dos_time_window)
        cutoff = timestamp - max_window
        while entries and entries[0][0] < cutoff:
            entries.popleft()

        # Trusted IPs are still allowed to update bounded history, but they never alert.
        if src_ip in self.whitelist:
            return

        port_cutoff = timestamp - self.port_scan_time_window
        ports_in_window = {
            port for t, port in entries if t >= port_cutoff
        }

        if len(ports_in_window) >= self.port_scan_port_limit:
            self._create_alert(
                src_ip,
                "PORT SCAN",
                f"{len(ports_in_window)} different ports probed in "
                f"{self.port_scan_time_window:g}s",
                mode,
            )

        dos_cutoff = timestamp - self.dos_time_window
        syn_count = sum(1 for t, _ in entries if t >= dos_cutoff)
        if syn_count >= self.dos_syn_limit:
            self._create_alert(
                src_ip,
                "DOS (SYN FLOOD)",
                f"{syn_count} connection attempts in "
                f"{self.dos_time_window:g}s",
                mode,
            )

    # -------------------------- state access --------------------------
    def pop_events(self):
        events = []
        while True:
            try:
                events.append(self.pending_events.get_nowait())
            except queue.Empty:
                break
        return events

    def reset_data(self):
        with self.lock:
            self.syn_log.clear()
            self.last_alert_time.clear()
            self.alerts.clear()
            self.total_tcp_packets = 0
            self.total_syn_packets = 0
            self.unique_source_ips.clear()
            self.port_scan_alerts = 0
            self.dos_alerts = 0
            self.activity.clear()
            self._last_activity_second = None
            self._current_second_tcp = 0
            self._current_second_syn = 0
            while True:
                try:
                    self.pending_events.get_nowait()
                except queue.Empty:
                    break

    def snapshot(self):
        with self.lock:
            return {
                "total_tcp": self.total_tcp_packets,
                "total_syn": self.total_syn_packets,
                "unique_ips": len(self.unique_source_ips),
                "port_alerts": self.port_scan_alerts,
                "dos_alerts": self.dos_alerts,
                "alerts": list(self.alerts),
                "whitelist": sorted(self.whitelist),
                "activity": list(self.activity),
                "current_activity": (
                    self._last_activity_second,
                    self._current_second_tcp,
                    self._current_second_syn,
                ),
            }


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class NIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Network IDS — Interactive Dashboard")
        self.root.geometry("1240x800")
        self.root.minsize(1050, 700)

        self.engine = DetectionEngine()
        self.sniffer = None
        self.monitoring = False
        self.demo_running = False
        self.demo_thread = None
        self.rendered_alert_ids = set()

        self.interfaces = []
        self.interface_display_to_data = {}

        self.interface_var = tk.StringVar()
        self.ip_var = tk.StringVar(value="Not selected")
        self.status_var = tk.StringVar(value="STOPPED")
        self.mode_var = tk.StringVar(value="READY")
        self.alert_filter_var = tk.StringVar(value="ALL")
        self.search_ip_var = tk.StringVar()

        self.port_limit_var = tk.StringVar(value=str(DEFAULT_PORT_SCAN_PORT_LIMIT))
        self.port_window_var = tk.StringVar(value=str(DEFAULT_PORT_SCAN_TIME_WINDOW))
        self.dos_limit_var = tk.StringVar(value=str(DEFAULT_DOS_SYN_LIMIT))
        self.dos_window_var = tk.StringVar(value=str(DEFAULT_DOS_TIME_WINDOW))
        self.cooldown_var = tk.StringVar(value=str(DEFAULT_ALERT_COOLDOWN))

        self.stat_vars = {
            "tcp": tk.StringVar(value="0"),
            "syn": tk.StringVar(value="0"),
            "ips": tk.StringVar(value="0"),
            "scans": tk.StringVar(value="0"),
            "dos": tk.StringVar(value="0"),
            "alerts": tk.StringVar(value="0"),
        }

        self._setup_style()
        self._build_ui()
        self._refresh_interfaces()
        self._load_whitelist_into_listbox()
        self._schedule_ui_update()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -------------------------- UI setup --------------------------
    def _setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", font=("Segoe UI", 9, "bold"))
        style.configure("CardValue.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=28)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=14)
        main.pack(fill="both", expand=True)

        header = ttk.Frame(main)
        header.pack(fill="x", pady=(0, 10))

        ttk.Label(header, text="SIMPLE NETWORK IDS", style="Title.TLabel").pack(side="left")
        ttk.Label(
            header,
            text="  Port Scan + SYN Flood Detection",
            style="Subtitle.TLabel",
        ).pack(side="left", padx=6, pady=(10, 0))

        status_box = ttk.Frame(header)
        status_box.pack(side="right")
        ttk.Label(status_box, text="STATUS:").pack(side="left")
        self.status_label = ttk.Label(status_box, textvariable=self.status_var, style="Status.TLabel")
        self.status_label.pack(side="left", padx=(6, 0))

        # Network controls
        network = ttk.LabelFrame(main, text="Network / Monitoring", padding=10)
        network.pack(fill="x", pady=(0, 10))

        ttk.Label(network, text="Interface:").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.interface_combo = ttk.Combobox(network, textvariable=self.interface_var, state="readonly", width=38)
        self.interface_combo.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.interface_combo.bind("<<ComboboxSelected>>", self._on_interface_change)

        ttk.Button(network, text="Refresh", command=self._refresh_interfaces).grid(row=0, column=2, padx=4)
        ttk.Label(network, text="Local IPv4:").grid(row=0, column=3, sticky="e", padx=(18, 6))
        ttk.Label(network, textvariable=self.ip_var, font=("Segoe UI", 10, "bold")).grid(row=0, column=4, sticky="w")

        self.start_btn = ttk.Button(network, text="START MONITORING", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=5, padx=(20, 4))
        self.stop_btn = ttk.Button(network, text="STOP", command=self.stop_monitoring, state="disabled")
        self.stop_btn.grid(row=0, column=6, padx=4)
        self.demo_btn = ttk.Button(network, text="DEMO MODE", command=self.start_demo)
        self.demo_btn.grid(row=0, column=7, padx=4)

        network.columnconfigure(1, weight=1)

        # Stats cards
        stats = ttk.Frame(main)
        stats.pack(fill="x", pady=(0, 10))
        cards = [
            ("TCP PACKETS", "tcp"),
            ("SYN PACKETS", "syn"),
            ("UNIQUE SOURCE IPs", "ips"),
            ("PORT SCAN ALERTS", "scans"),
            ("DOS ALERTS", "dos"),
            ("TOTAL ALERTS", "alerts"),
        ]
        for i, (title, key) in enumerate(cards):
            card = ttk.Frame(stats, relief="solid", borderwidth=1, padding=(10, 7))
            card.grid(row=0, column=i, sticky="nsew", padx=3)
            ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=self.stat_vars[key], style="CardValue.TLabel").pack(anchor="w", pady=(3, 0))
            stats.columnconfigure(i, weight=1)

        # Middle area: thresholds + whitelist
        middle = ttk.Frame(main)
        middle.pack(fill="x", pady=(0, 10))

        threshold_box = ttk.LabelFrame(middle, text="Detection Thresholds", padding=10)
        threshold_box.pack(side="left", fill="x", expand=True, padx=(0, 5))

        fields = [
            ("Port scan ports", self.port_limit_var),
            ("Port scan window (s)", self.port_window_var),
            ("DoS SYN limit", self.dos_limit_var),
            ("DoS window (s)", self.dos_window_var),
            ("Alert cooldown (s)", self.cooldown_var),
        ]
        for col, (label, var) in enumerate(fields):
            box = ttk.Frame(threshold_box)
            box.grid(row=0, column=col, padx=6, sticky="w")
            ttk.Label(box, text=label).pack(anchor="w")
            ttk.Entry(box, textvariable=var, width=12).pack(anchor="w", pady=(4, 0))

        ttk.Button(threshold_box, text="Apply Settings", command=self.apply_settings).grid(
            row=0, column=len(fields), padx=(10, 0), pady=(14, 0)
        )

        whitelist_box = ttk.LabelFrame(middle, text="Trusted IP Whitelist", padding=10)
        whitelist_box.pack(side="left", fill="both", padx=(5, 0))

        list_frame = ttk.Frame(whitelist_box)
        list_frame.pack(side="left", fill="both", expand=True)
        self.whitelist_list = tk.Listbox(list_frame, height=4, width=24, exportselection=False)
        self.whitelist_list.pack(side="left", fill="both", expand=True)
        wl_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.whitelist_list.yview)
        wl_scroll.pack(side="right", fill="y")
        self.whitelist_list.config(yscrollcommand=wl_scroll.set)

        wl_controls = ttk.Frame(whitelist_box)
        wl_controls.pack(side="left", padx=(8, 0), fill="y")
        self.whitelist_entry = ttk.Entry(wl_controls, width=18)
        self.whitelist_entry.pack(pady=(0, 5))
        ttk.Button(wl_controls, text="Add IP", command=self.add_whitelist).pack(fill="x", pady=2)
        ttk.Button(wl_controls, text="Remove", command=self.remove_whitelist).pack(fill="x", pady=2)

        # Bottom area
        bottom = ttk.Frame(main)
        bottom.pack(fill="both", expand=True)

        graph_box = ttk.LabelFrame(bottom, text="Live Activity — last 30 seconds", padding=8)
        graph_box.pack(side="left", fill="both", expand=True, padx=(0, 5))
        self.graph = tk.Canvas(graph_box, height=270, background="#111827", highlightthickness=0)
        self.graph.pack(fill="both", expand=True)

        alerts_box = ttk.LabelFrame(bottom, text="Alerts", padding=8)
        alerts_box.pack(side="left", fill="both", expand=True, padx=(5, 0))

        filter_row = ttk.Frame(alerts_box)
        filter_row.pack(fill="x", pady=(0, 6))
        ttk.Label(filter_row, text="Type:").pack(side="left")
        self.filter_combo = ttk.Combobox(
            filter_row,
            textvariable=self.alert_filter_var,
            values=["ALL", "PORT SCAN", "DOS (SYN FLOOD)"],
            state="readonly",
            width=18,
        )
        self.filter_combo.pack(side="left", padx=5)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_alert_table())

        ttk.Label(filter_row, text="Source IP:").pack(side="left", padx=(10, 4))
        self.search_ip_entry = ttk.Entry(filter_row, textvariable=self.search_ip_var, width=18)
        self.search_ip_entry.pack(side="left")
        self.search_ip_entry.bind("<KeyRelease>", lambda _e: self._refresh_alert_table())

        ttk.Button(filter_row, text="Clear", command=self.clear_alerts_and_stats).pack(side="right", padx=2)
        ttk.Button(filter_row, text="Export CSV", command=self.export_csv).pack(side="right", padx=2)

        tree_frame = ttk.Frame(alerts_box)
        tree_frame.pack(fill="both", expand=True)
        columns = ("time", "source", "type", "details", "mode")
        self.alert_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        self.alert_tree.heading("time", text="Time")
        self.alert_tree.heading("source", text="Source IP")
        self.alert_tree.heading("type", text="Alert")
        self.alert_tree.heading("details", text="Details")
        self.alert_tree.heading("mode", text="Mode")
        self.alert_tree.column("time", width=125, anchor="center")
        self.alert_tree.column("source", width=115, anchor="center")
        self.alert_tree.column("type", width=135, anchor="center")
        self.alert_tree.column("details", width=250)
        self.alert_tree.column("mode", width=65, anchor="center")
        self.alert_tree.pack(side="left", fill="both", expand=True)

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.alert_tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.alert_tree.config(yscrollcommand=tree_scroll.set)

        footer = ttk.Label(main, textvariable=self.mode_var, anchor="w")
        footer.pack(fill="x", pady=(8, 0))

    # -------------------------- interface handling --------------------------
    def _refresh_interfaces(self):
        try:
            self.interfaces = list_interfaces()
        except Exception as exc:
            messagebox.showerror("Interface Error", f"Could not list interfaces.\n\n{exc}")
            return

        self.interface_display_to_data = {
            display: (iface, ip) for display, iface, ip in self.interfaces
        }
        values = [display for display, _, _ in self.interfaces]
        self.interface_combo["values"] = values

        default_iface = detect_default_interface()
        chosen = None
        for display, iface, ip in self.interfaces:
            if iface == default_iface:
                chosen = display
                break
        if chosen is None and values:
            chosen = values[0]

        if chosen:
            self.interface_var.set(chosen)
            self._on_interface_change()
        else:
            self.interface_var.set("")
            self.ip_var.set("Not available")

    def _on_interface_change(self, _event=None):
        if self.monitoring or self.demo_running:
            messagebox.showinfo("Monitoring active", "Stop monitoring/demo mode before changing interfaces.")
            return
        data = self.interface_display_to_data.get(self.interface_var.get())
        if data:
            iface, ip = data
            if not ip:
                ip = get_ipv4_for_interface(iface)
            self.ip_var.set(ip or "No IPv4 detected")

    # -------------------------- settings --------------------------
    def apply_settings(self):
        try:
            port_limit = int(self.port_limit_var.get())
            port_window = float(self.port_window_var.get())
            dos_limit = int(self.dos_limit_var.get())
            dos_window = float(self.dos_window_var.get())
            cooldown = float(self.cooldown_var.get())

            if port_limit < 1 or port_window <= 0 or dos_limit < 1 or dos_window <= 0 or cooldown < 0:
                raise ValueError("All limits must be positive; cooldown cannot be negative.")

            self.engine.set_thresholds(
                port_limit, port_window, dos_limit, dos_window, cooldown
            )
            self.mode_var.set("Settings applied successfully.")
        except ValueError as exc:
            messagebox.showerror("Invalid Settings", str(exc))

    # -------------------------- monitoring --------------------------
    def selected_interface(self):
        data = self.interface_display_to_data.get(self.interface_var.get())
        if not data:
            raise ValueError("Please select a network interface.")
        iface, ip = data
        ip = ip or get_ipv4_for_interface(iface)
        return iface, ip

    def start_monitoring(self):
        if self.monitoring or self.demo_running:
            return

        try:
            self.apply_settings_silent()
            iface, my_ip = self.selected_interface()
            if not my_ip:
                raise ValueError("The selected interface does not have an IPv4 address.")
        except ValueError as exc:
            messagebox.showerror("Cannot Start", str(exc))
            return

        self.ip_var.set(my_ip)
        try:
            self.sniffer = AsyncSniffer(
                iface=iface,
                filter="tcp",
                prn=lambda pkt: self.engine.process_packet(pkt, my_ip, mode="LIVE"),
                store=False,
            )
            self.sniffer.start()
        except Exception as exc:
            self.sniffer = None
            messagebox.showerror(
                "Packet Capture Error",
                "Could not start packet capture.\n\n"
                f"Interface: {iface}\n"
                f"Reason: {exc}\n\n"
                "On Linux, try running the program with sudo."
            )
            return

        self.monitoring = True
        self.status_var.set("MONITORING")
        self.mode_var.set(f"LIVE MODE — monitoring {iface} → {my_ip}")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.demo_btn.config(state="disabled")
        self.interface_combo.config(state="disabled")

    def apply_settings_silent(self):
        try:
            values = [
                int(self.port_limit_var.get()),
                float(self.port_window_var.get()),
                int(self.dos_limit_var.get()),
                float(self.dos_window_var.get()),
                float(self.cooldown_var.get()),
            ]
            if values[0] < 1 or values[1] <= 0 or values[2] < 1 or values[3] <= 0 or values[4] < 0:
                raise ValueError
        except ValueError:
            raise ValueError("Please enter valid positive threshold values.")
        self.engine.set_thresholds(*values)

    def stop_monitoring(self):
        # Stop real packet capture.
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.sniffer = None
        self.monitoring = False

        # Stop the local demo generator too.
        if self.demo_running:
            self.demo_running = False
            self.status_var.set("STOPPED")
            self.mode_var.set("Demo stopped.")
        else:
            self.status_var.set("STOPPED")
            self.mode_var.set("Monitoring stopped.")

        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.demo_btn.config(state="normal")
        self.interface_combo.config(state="readonly")

    # -------------------------- demo mode --------------------------
    def start_demo(self):
        if self.monitoring or self.demo_running:
            return

        try:
            self.apply_settings_silent()
        except ValueError as exc:
            messagebox.showerror("Invalid Settings", str(exc))
            return

        self.demo_running = True
        self.status_var.set("DEMO")
        self.mode_var.set("DEMO MODE — generating synthetic events locally; no attack packets are sent.")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.demo_btn.config(state="disabled")
        self.interface_combo.config(state="disabled")

        self.demo_thread = threading.Thread(target=self._demo_worker, daemon=True)
        self.demo_thread.start()

    def _demo_worker(self):
        try:
            # Port-scan scenario: many different ports from one synthetic source.
            scan_ip = "10.10.10.99"
            base_port = 20
            for offset in range(max(self.engine.port_scan_port_limit + 2, 18)):
                if not self.demo_running:
                    return
                self.engine.process_syn_event(scan_ip, base_port + offset, mode="DEMO")
                time.sleep(0.08)

            time.sleep(1.0)

            # SYN-flood-like scenario: many SYNs to the same port from another source.
            dos_ip = "10.10.20.77"
            count = max(self.engine.dos_syn_limit + 10, 110)
            for _ in range(count):
                if not self.demo_running:
                    return
                self.engine.process_syn_event(dos_ip, 80, mode="DEMO")
                time.sleep(0.01)
        finally:
            self.root.after(0, self._finish_demo)

    def _finish_demo(self):
        if not self.demo_running:
            return
        self.demo_running = False
        self.status_var.set("STOPPED")
        self.mode_var.set("Demo complete. No real attack traffic was generated.")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.demo_btn.config(state="normal")
        self.interface_combo.config(state="readonly")

    # -------------------------- whitelist UI --------------------------
    def _load_whitelist_into_listbox(self):
        self.whitelist_list.delete(0, tk.END)
        for ip in self.engine.snapshot()["whitelist"]:
            self.whitelist_list.insert(tk.END, ip)

    def add_whitelist(self):
        ip = self.whitelist_entry.get().strip()
        if not ip:
            messagebox.showwarning("Whitelist", "Enter an IP address first.")
            return
        self.engine.add_whitelist(ip)
        self.whitelist_entry.delete(0, tk.END)
        self._load_whitelist_into_listbox()
        self.mode_var.set(f"Trusted IP added: {ip}")

    def remove_whitelist(self):
        selection = self.whitelist_list.curselection()
        if not selection:
            messagebox.showinfo("Whitelist", "Select an IP to remove.")
            return
        ip = self.whitelist_list.get(selection[0])
        self.engine.remove_whitelist(ip)
        self._load_whitelist_into_listbox()
        self.mode_var.set(f"Trusted IP removed: {ip}")

    # -------------------------- alerts / export --------------------------
    def _filtered_alerts(self, alerts):
        alert_type = self.alert_filter_var.get()
        source_filter = self.search_ip_var.get().strip().lower()

        filtered = []
        for alert in reversed(alerts):
            if alert_type != "ALL" and alert["alert_type"] != alert_type:
                continue
            if source_filter and source_filter not in alert["source_ip"].lower():
                continue
            filtered.append(alert)
        return filtered

    def _refresh_alert_table(self):
        snapshot = self.engine.snapshot()
        alerts = self._filtered_alerts(snapshot["alerts"])

        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)

        for alert in alerts:
            self.alert_tree.insert(
                "",
                "end",
                values=(
                    alert["timestamp"].split(" ", 1)[-1],
                    alert["source_ip"],
                    alert["alert_type"],
                    alert["details"],
                    alert["mode"],
                ),
            )

    def clear_alerts_and_stats(self):
        answer = messagebox.askyesno(
            "Clear Data",
            "Clear the current alerts and live statistics?\n\n"
            "This does not delete the CSV log or whitelist.",
        )
        if not answer:
            return
        self.engine.reset_data()
        self.rendered_alert_ids.clear()
        self._refresh_alert_table()
        self.mode_var.set("Alerts and live statistics cleared.")

    def export_csv(self):
        snapshot = self.engine.snapshot()
        if not snapshot["alerts"]:
            messagebox.showinfo("Export CSV", "There are no alerts to export yet.")
            return

        path = filedialog.asksaveasfilename(
            title="Export IDS Alerts",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="nids_alerts_export.csv",
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "source_ip", "alert_type", "details", "mode"])
                for alert in snapshot["alerts"]:
                    writer.writerow([
                        alert["timestamp"],
                        alert["source_ip"],
                        alert["alert_type"],
                        alert["details"],
                        alert["mode"],
                    ])
            messagebox.showinfo("Export CSV", f"Exported {len(snapshot['alerts'])} alerts.\n\n{path}")
        except OSError as exc:
            messagebox.showerror("Export Error", str(exc))

    # -------------------------- live UI update --------------------------
    def _schedule_ui_update(self):
        self._update_dashboard()
        self.root.after(250, self._schedule_ui_update)

    def _update_dashboard(self):
        snapshot = self.engine.snapshot()
        self.stat_vars["tcp"].set(f"{snapshot['total_tcp']:,}")
        self.stat_vars["syn"].set(f"{snapshot['total_syn']:,}")
        self.stat_vars["ips"].set(f"{snapshot['unique_ips']:,}")
        self.stat_vars["scans"].set(f"{snapshot['port_alerts']:,}")
        self.stat_vars["dos"].set(f"{snapshot['dos_alerts']:,}")
        self.stat_vars["alerts"].set(f"{len(snapshot['alerts']):,}")

        # Refresh the alert list when new alerts arrive or when filters change.
        new_ids = set(id(alert) for alert in snapshot["alerts"])
        if new_ids != self.rendered_alert_ids:
            self.rendered_alert_ids = new_ids
            self._refresh_alert_table()

        self._draw_graph(snapshot)

    def _draw_graph(self, snapshot):
        canvas = self.graph
        canvas.delete("all")
        width = max(canvas.winfo_width(), 300)
        height = max(canvas.winfo_height(), 180)

        # Title / legend
        canvas.create_text(12, 12, anchor="nw", fill="#e5e7eb", text="TCP traffic per second")
        canvas.create_text(12, 34, anchor="nw", fill="#f59e0b", text="SYN traffic per second")

        activity = snapshot["activity"][:]
        sec, current_tcp, current_syn = snapshot["current_activity"]
        if sec is not None:
            activity.append((sec, current_tcp, current_syn))

        cutoff = int(time.monotonic()) - GRAPH_SECONDS + 1
        activity = [item for item in activity if item[0] >= cutoff]

        if not activity:
            canvas.create_text(
                width / 2,
                height / 2,
                fill="#9ca3af",
                text="Waiting for traffic...",
                font=("Segoe UI", 12),
            )
            return

        max_value = max(max(tcp, syn) for _, tcp, syn in activity)
        max_value = max(max_value, 1)

        left = 45
        right = width - 20
        top = 60
        bottom = height - 28
        graph_h = max(bottom - top, 50)
        slots = GRAPH_SECONDS
        slot_w = max((right - left) / slots, 3)

        # Horizontal grid lines
        for frac in (0, 0.25, 0.5, 0.75, 1):
            y = bottom - frac * graph_h
            value = int(max_value * frac)
            canvas.create_line(left, y, right, y, fill="#374151")
            canvas.create_text(left - 6, y, anchor="e", fill="#9ca3af", text=str(value), font=("Segoe UI", 8))

        by_second = {sec_val: (tcp, syn) for sec_val, tcp, syn in activity}
        start = cutoff
        for i in range(slots):
            sec_value = start + i
            tcp, syn = by_second.get(sec_value, (0, 0))

            x0 = left + i * slot_w + 1
            x1 = left + (i + 1) * slot_w - 1
            if x1 <= x0:
                continue

            tcp_h = (tcp / max_value) * graph_h
            syn_h = (syn / max_value) * graph_h

            canvas.create_rectangle(x0, bottom - tcp_h, x1, bottom, fill="#60a5fa", outline="")
            if syn > 0:
                syn_w = max((x1 - x0) * 0.45, 1)
                canvas.create_rectangle(x0, bottom - syn_h, x0 + syn_w, bottom, fill="#f59e0b", outline="")

        canvas.create_text(left, height - 10, anchor="w", fill="#9ca3af", text=f"-{GRAPH_SECONDS}s")
        canvas.create_text(right, height - 10, anchor="e", fill="#9ca3af", text="now")

    # -------------------------- shutdown --------------------------
    def on_close(self):
        if self.monitoring:
            self.stop_monitoring()
        if self.demo_running:
            self.demo_running = False
        self.root.destroy()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    root = tk.Tk()
    app = NIDSApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

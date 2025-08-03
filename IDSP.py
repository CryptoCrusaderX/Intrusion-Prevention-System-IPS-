import os
import sys
import threading
import datetime
import subprocess
import socket
from queue import Queue
from scapy.all import sniff, IP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import customtkinter as ctk
from tkinter import filedialog, Canvas, END


class MacOSFirewall:
    def __init__(self):
        self.blocked_ips = set()
        self.anchor_file = "/etc/pf.anchors/com.idps.block"
        self.conf_line = 'anchor "com.idps.block"'
        self._check_pf_config()

    def _check_pf_config(self):
        # Check if pf.conf is properly configured with our custom anchor
        with open("/etc/pf.conf", "r") as f:
            conf = f.read()
        if self.conf_line not in conf:
            print(
                f"[!] ERROR: Add `{self.conf_line}` line in /etc/pf.conf and reload pf."
            )
            sys.exit(1)

    def add_block(self, ip):
        # Block an IP using pfctl if it's not already blocked
        if ip not in self.blocked_ips:
            try:
                subprocess.run(["pfctl", "-t", "blocked", "-T", "add", ip], check=True)
                self.blocked_ips.add(ip)
                return True
            except subprocess.CalledProcessError:
                return False
        return True  # Already blocked

    def remove_all_blocks(self):
        # Remove all IPs we blocked during the session
        if self.blocked_ips:
            for ip in list(self.blocked_ips):
                try:
                    subprocess.run(
                        ["pfctl", "-t", "blocked", "-T", "delete", ip], check=True
                    )
                except subprocess.CalledProcessError:
                    pass
            self.blocked_ips.clear()


class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, queue):
        self.queue = queue

    def on_any_event(self, event):
        # Whenever a file is created, modified, or deleted, push an alert to the queue
        if not event.is_directory:
            event_type = event.event_type.title()
            self.queue.put(
                ("File", f"{event_type} event detected on: {event.src_path}")
            )


def packet_sniffer(queue, stop_event, suspicious_ips, iface="en0"):
    """Capture packets and report network activity in real-time."""

    def process_packet(pkt):
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            # For now, just treat everything as normal traffic
            queue.put(("NetworkNormal", f"Normal packet: src={src_ip}, dst={dst_ip}"))

    sniff(
        iface=iface,
        prn=process_packet,
        store=False,
        stop_filter=lambda x: stop_event.is_set(),
        promisc=True,
    )


class IDPSApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SurkhsyaNet- Intrusion Prevention System")
        self.geometry("880x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Core components and state tracking
        self.alert_queue = Queue()
        self.file_observer = None
        self.sniffer_thread = None
        self.stop_event = threading.Event()
        self.firewall = MacOSFirewall()

        # Track suspicious IPs and alerts
        self.suspicious_ips = set()
        self.file_alert_messages = set()  # Only unique file alerts
        self.normal_packets = 0
        self.file_alerts = 0
        self.monitoring = False

        # Build UI and prepare monitoring
        self._setup_ui()
        self._setup_file_monitor("./lab")
        self.after(200, self._process_alerts)  # Short delay for smooth UI updates

    def _setup_ui(self):
        # Create tabbed interface: Dashboard, Alerts, Settings
        self.tabview = ctk.CTkTabview(self, width=860, height=560)
        self.tabview.pack(padx=10, pady=10)
        self.tabview.add("Dashboard")
        self.tabview.add("Alerts")
        self.tabview.add("Settings")

        # Dashboard Tab
        dash = self.tabview.tab("Dashboard")
        self.network_label = ctk.CTkLabel(
            dash,
            text="Network Alerts: 0",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#1f77b4",
        )
        self.network_label.pack(pady=(20, 5))

        self.file_label = ctk.CTkLabel(
            dash,
            text="File Alerts: 0",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#ff7f0e",
        )
        self.file_label.pack(pady=(5, 20))

        # Simple canvas to visualize traffic with circular indicators
        self.canvas = Canvas(
            dash, width=250, height=250, bg="#2b2b2b", highlightthickness=0
        )
        self.canvas.pack()

        # Show normal packet count
        self.normal_label = ctk.CTkLabel(
            dash,
            text="Normal Packets: 0",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="green",
        )
        self.normal_label.pack(pady=10)

        # Start/Stop buttons
        btn_frame = ctk.CTkFrame(dash)
        btn_frame.pack(pady=15)
        self.start_btn = ctk.CTkButton(
            btn_frame, text="Start Monitoring", command=self.start_monitoring, width=130
        )
        self.start_btn.grid(row=0, column=0, padx=20)
        self.stop_btn = ctk.CTkButton(
            btn_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            width=130,
            state="disabled",
        )
        self.stop_btn.grid(row=0, column=1, padx=20)

        # Alerts Tab
        alerts = self.tabview.tab("Alerts")
        self.network_frame = ctk.CTkFrame(alerts)
        self.network_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.file_frame = ctk.CTkFrame(alerts)
        self.file_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(
            self.network_frame,
            text="Network Traffic (Live)",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#1f77b4",
        ).pack()
        ctk.CTkLabel(
            self.file_frame,
            text="File Alerts",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#ff7f0e",
        ).pack()

        self.network_box = ctk.CTkTextbox(self.network_frame, width=420, height=500)
        self.network_box.pack(pady=5)
        self.file_box = ctk.CTkTextbox(self.file_frame, width=420, height=500)
        self.file_box.pack(pady=5)

        # Settings Tab
        settings = self.tabview.tab("Settings")
        ctk.CTkLabel(settings, text="Add Suspicious IP or Domain:").pack(pady=10)
        self.ip_entry = ctk.CTkEntry(settings, width=300)
        self.ip_entry.pack(pady=5)
        ctk.CTkButton(
            settings, text="Add & Block", command=self._add_ip_or_domain
        ).pack(pady=10)
        self.blocked_label = ctk.CTkLabel(
            settings, text="Blocked IPs: None", wraplength=400
        )
        self.blocked_label.pack(pady=5)
        ctk.CTkButton(
            settings, text="Clear All Blocks", command=self._clear_blocks
        ).pack(pady=10)
        ctk.CTkButton(
            settings, text="Select Folder to Monitor", command=self._browse_folder
        ).pack(pady=10)

        # Initial drawing of rings
        self._draw_rings()

    def _draw_rings(self):
        # Update circular indicators showing ratio of packets to file alerts
        self.canvas.delete("all")
        self.canvas.create_oval(30, 30, 220, 220, outline="#444", width=15)
        self.canvas.create_oval(55, 55, 195, 195, outline="#444", width=15)

        total = max(1, self.normal_packets + self.file_alerts)

        # Outer ring shows network packets (green)
        net_angle = (self.normal_packets / total) * 360
        self.canvas.create_arc(
            30,
            30,
            220,
            220,
            start=90,
            extent=-net_angle,
            outline="green",
            width=15,
            style="arc",
        )

        # Inner ring shows file alerts (orange)
        file_angle = (self.file_alerts / total) * 360
        self.canvas.create_arc(
            55,
            55,
            195,
            195,
            start=90,
            extent=-file_angle,
            outline="#ff7f0e",
            width=15,
            style="arc",
        )

    def _setup_file_monitor(self, folder):
        # Monitor a folder for file changes and alert on events
        if not os.path.exists(folder):
            os.makedirs(folder)
        handler = FileMonitorHandler(self.alert_queue)
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
        self.file_observer = Observer()
        self.file_observer.schedule(handler, folder, recursive=True)
        if self.monitoring:
            self.file_observer.start()

    def _start_sniffer_thread(self):
        # Start background thread for packet sniffing if not already running
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return
        self.stop_event.clear()
        self.sniffer_thread = threading.Thread(
            target=packet_sniffer,
            args=(self.alert_queue, self.stop_event, self.suspicious_ips, "en0"),
            daemon=True,
        )
        self.sniffer_thread.start()

    def _process_alerts(self):
        # Fetch any queued alerts and update the UI
        updated = False

        while not self.alert_queue.empty():
            atype, msg = self.alert_queue.get()
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            full_msg = f"[{timestamp}] {msg}\n"

            if atype == "NetworkNormal":
                self.normal_packets += 1
                updated = True
                self.network_box.insert(END, full_msg)
                self.network_box.tag_add(
                    f"normal{self.normal_packets}", f"end-{len(full_msg)}c", "end-1c"
                )
                self.network_box.tag_config(
                    f"normal{self.normal_packets}", foreground="green"
                )
                self.network_box.see(END)

            elif atype == "File":
                # Avoid duplicate file alerts
                if msg not in self.file_alert_messages:
                    self.file_alert_messages.add(msg)
                    self.file_alerts = len(self.file_alert_messages)
                    updated = True
                    self.file_box.insert(END, full_msg)
                    self.file_box.tag_add(
                        f"file{self.file_alerts}", f"end-{len(full_msg)}c", "end-1c"
                    )
                    self.file_box.tag_config(
                        f"file{self.file_alerts}", foreground="#ff7f0e"
                    )
                    self.file_box.see(END)

        # Update counters and redraw visualization if something changed
        if updated:
            self.network_label.configure(
                text=f"Network Alerts: {len(self.suspicious_ips)}"
            )
            self.file_label.configure(text=f"File Alerts: {self.file_alerts}")
            self.normal_label.configure(text=f"Normal Packets: {self.normal_packets}")
            self._draw_rings()

        self.after(200, self._process_alerts)

    def start_monitoring(self):
        # Reset state and begin monitoring
        if self.monitoring:
            return
        self.monitoring = True

        self.file_alert_messages.clear()
        self.file_alerts = 0
        self.normal_packets = 0

        self.network_box.delete("1.0", END)
        self.file_box.delete("1.0", END)
        self.network_label.configure(text="Network Alerts: 0")
        self.file_label.configure(text="File Alerts: 0")
        self.normal_label.configure(text="Normal Packets: 0")
        self._draw_rings()

        if self.file_observer:
            self.file_observer.start()

        self._start_sniffer_thread()
        self._append_system_alert("Monitoring started", color="#2ca02c")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def stop_monitoring(self):
        # Gracefully stop monitoring and threads
        if not self.monitoring:
            return
        self.monitoring = False
        self.stop_event.set()

        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()

        self._append_system_alert("Monitoring stopped", color="#d62728")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _add_ip_or_domain(self):
        # Take user input (IP/domain), resolve to IPs, and block them
        entry = self.ip_entry.get().strip()
        if not entry:
            return

        resolved_ips = set()
        try:
            infos = socket.getaddrinfo(entry, None)
            for info in infos:
                ip = info[4][0]
                if ":" not in ip:  # Skip IPv6 for simplicity
                    resolved_ips.add(ip)
        except socket.gaierror:
            resolved_ips.add(entry)

        for ip in resolved_ips:
            success = self.firewall.add_block(ip)
            if success:
                self.suspicious_ips.add(ip)
                self._append_system_alert(f"Blocked IP added: {ip}", color="#1f77b4")
            else:
                self._append_system_alert(f"Failed to block IP: {ip}", color="#d62728")

        self.blocked_label.configure(
            text=f"Blocked IPs: {', '.join(self.suspicious_ips) if self.suspicious_ips else 'None'}"
        )
        self.ip_entry.delete(0, "end")

    def _clear_blocks(self):
        # Clear all currently blocked IPs
        self.firewall.remove_all_blocks()
        self.suspicious_ips.clear()
        self.blocked_label.configure(text="Blocked IPs: None")
        self._append_system_alert("All blocked IPs cleared", color="#d62728")

    def _browse_folder(self):
        # Allow user to select a folder to monitor
        folder = filedialog.askdirectory()
        if folder:
            self._setup_file_monitor(folder)
            self._append_system_alert(
                f"Monitoring folder set to: {folder}", color="#1f77b4"
            )

    def _append_system_alert(self, msg, color="#000000"):
        # Display a system-level message in the network alert box
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        full_msg = f"[{timestamp}] [System] {msg}\n"
        self.network_box.insert(END, full_msg)
        self.network_box.tag_add(
            f"sys{self.normal_packets}", f"end-{len(full_msg)}c", "end-1c"
        )
        self.network_box.tag_config(f"sys{self.normal_packets}", foreground=color)
        self.network_box.see(END)

    def on_closing(self):
        # Cleanup before closing the app
        self.stop_monitoring()
        self.firewall.remove_all_blocks()
        self.destroy()


if __name__ == "__main__":
    # Must be run as root to allow pfctl operations
    if os.geteuid() != 0:
        print("[!] Please run this program as root (sudo).")
        sys.exit(1)
    app = IDPSApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()

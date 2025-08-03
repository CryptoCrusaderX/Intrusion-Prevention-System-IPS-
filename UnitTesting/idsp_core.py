import os
import sys
import subprocess
import socket
from queue import Queue
from scapy.all import sniff, IP
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading


class MacOSFirewall:
    def __init__(self):
        self.blocked_ips = set()
        self.anchor_file = "/etc/pf.anchors/com.idps.block"
        self.conf_line = 'anchor "com.idps.block"'
        self._check_pf_config()

    def _check_pf_config(self):
        """Ensure pf.conf contains the required anchor for blocking."""
        if not os.path.exists("/etc/pf.conf"):
            print("[!] ERROR: /etc/pf.conf not found. Run on macOS.")
            sys.exit(1)

        with open("/etc/pf.conf", "r") as f:
            conf = f.read()
        if self.conf_line not in conf:
            print(
                f"[!] ERROR: Add `{self.conf_line}` line in /etc/pf.conf and reload pf."
            )
            sys.exit(1)

    def add_block(self, ip):
        """Block a given IP address using pfctl."""
        if ip not in self.blocked_ips:
            try:
                subprocess.run(["pfctl", "-t", "blocked", "-T", "add", ip], check=True)
                self.blocked_ips.add(ip)
                return True
            except subprocess.CalledProcessError:
                return False
        return True  # already blocked

    def remove_all_blocks(self):
        """Remove all blocked IPs."""
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
    """Detects file system events and pushes alerts to a queue."""

    def __init__(self, queue):
        self.queue = queue

    def on_any_event(self, event):
        if not event.is_directory:
            event_type = event.event_type.title()
            self.queue.put(
                ("File", f"{event_type} event detected on: {event.src_path}")
            )


def packet_sniffer(queue, stop_event, suspicious_ips, iface="en0"):
    """Capture packets and report normal traffic."""

    def process_packet(pkt):
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            queue.put(("NetworkNormal", f"Normal packet: src={src_ip}, dst={dst_ip}"))

    sniff(
        iface=iface,
        prn=process_packet,
        store=False,
        stop_filter=lambda x: stop_event.is_set(),
        promisc=True,
    )


def start_sniffer_thread(queue, stop_event, suspicious_ips, iface="en0"):
    """Utility for running sniffer in a background thread for tests."""
    thread = threading.Thread(
        target=packet_sniffer,
        args=(queue, stop_event, suspicious_ips, iface),
        daemon=True,
    )
    thread.start()
    return thread

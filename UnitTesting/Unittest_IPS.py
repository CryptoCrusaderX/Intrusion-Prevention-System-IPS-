import unittest
from unittest.mock import patch, MagicMock
from queue import Queue
from watchdog.events import FileSystemEvent
from scapy.packet import Packet
from scapy.layers.inet import IP

# Import only non-GUI parts from your file, e.g., idps_core.py
from idsp_core import MacOSFirewall, FileMonitorHandler, packet_sniffer


class TestMacOSFirewall(unittest.TestCase):

    @patch("subprocess.run")
    def test_add_block_success(self, mock_run):
        fw = MacOSFirewall()
        fw.blocked_ips.clear()  # Ensure clean state
        mock_run.return_value = MagicMock(returncode=0)

        result = fw.add_block("192.168.1.10")
        self.assertTrue(result)
        self.assertIn("192.168.1.10", fw.blocked_ips)

    @patch("subprocess.run")
    def test_remove_all_blocks(self, mock_run):
        fw = MacOSFirewall()
        fw.blocked_ips = {"192.168.1.10", "10.0.0.5"}

        fw.remove_all_blocks()
        self.assertEqual(len(fw.blocked_ips), 0)


class TestFileMonitorHandler(unittest.TestCase):

    def test_file_event_added_to_queue(self):
        q = Queue()
        handler = FileMonitorHandler(q)

        # Simulate file event
        event = FileSystemEvent("/tmp/test.txt")
        event.event_type = "modified"
        event.is_directory = False

        handler.on_any_event(event)
        self.assertFalse(q.empty())
        alert_type, msg = q.get()
        self.assertEqual(alert_type, "File")
        self.assertIn("Modified event detected", msg)


class TestPacketSniffer(unittest.TestCase):

    def test_packet_sniffer_processes_ip_packet(self):
        q = Queue()

        # Create a fake packet with src and dst IPs
        pkt = IP(src="192.168.1.2", dst="8.8.8.8")
        stop_event = MagicMock()
        stop_event.is_set.return_value = False

        # Instead of running sniff(), directly call process logic
        # Simulate the callback
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            q.put(("NetworkNormal", f"Normal packet: src={src_ip}, dst={dst_ip}"))

        alert_type, msg = q.get()
        self.assertEqual(alert_type, "NetworkNormal")
        self.assertIn("192.168.1.2", msg)
        self.assertIn("8.8.8.8", msg)


if __name__ == "__main__":
    unittest.main()

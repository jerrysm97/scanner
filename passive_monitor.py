#!/usr/bin/env python3
"""
Sentinel Passive Monitor v1.0 — All-Device DNS Footprint Engine
================================================================
Listens to ALL DNS queries on the network without ARP spoofing.
Builds a per-device digital footprint in footprint_db.json.

Usage: sudo python3 passive_monitor.py [-i en0]
"""

import os
import sys
import time
import json
import signal
import logging
import argparse
import threading
from collections import defaultdict

from scapy.all import DNS, DNSQR, IP, sniff, conf

logging.basicConfig(level=logging.INFO, format='%(asctime)s [PASSIVE] %(message)s')

FOOTPRINT_DB = "footprint_db.json"
STATS_FILE = "traffic_stats.json"

# Domains to ignore (noise)
IGNORE_DOMAINS = {
    'local', 'arpa', 'localhost', '_dns-sd', 'lan',
    'in-addr.arpa', 'ip6.arpa', '_tcp.local', '_udp.local'
}

# Internal/gateway IPs to ignore as sources
IGNORE_IPS = set()


class PassiveMonitor:
    def __init__(self, interface=None, gateway_ip=None, own_ip=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.own_ip = own_ip
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.db = self._load_db()
        self.packet_count = 0
        self.dns_count = 0

        # Track per-IP byte counters for this session
        self.byte_counters = defaultdict(lambda: {"upload": 0, "download": 0})

    def _load_db(self):
        if os.path.exists(FOOTPRINT_DB):
            try:
                with open(FOOTPRINT_DB, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_db(self):
        try:
            tmp = FOOTPRINT_DB + ".tmp"
            with open(tmp, 'w') as f:
                json.dump(self.db, f, indent=2)
            os.rename(tmp, FOOTPRINT_DB)
        except Exception as e:
            logging.error(f"DB save error: {e}")

    def _ensure_device(self, ip):
        if ip not in self.db:
            self.db[ip] = {
                "domains": {},
                "sessions": [],
                "total_bytes": 0,
                "total_domains": 0,
                "images_captured": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "status": "active"
            }

    def _is_noise(self, domain):
        """Filter out mDNS, ARPA, and other noise."""
        if not domain:
            return True
        parts = domain.split('.')
        if len(parts) < 2:
            return True
        tld = parts[-1].lower()
        if tld in IGNORE_DOMAINS:
            return True
        if domain.startswith('_'):
            return True
        if any(ignore in domain.lower() for ignore in ['_tcp', '_udp', 'in-addr', 'ip6']):
            return True
        return False

    def _is_private_ip(self, ip):
        """Check if IP is a private/LAN IP we want to track."""
        return (ip.startswith('192.168.') or
                ip.startswith('10.') or
                ip.startswith('172.16.') or
                ip.startswith('172.17.') or
                ip.startswith('172.18.') or
                ip.startswith('172.19.') or
                ip.startswith('172.2') or
                ip.startswith('172.3'))

    def handle_packet(self, pkt):
        self.packet_count += 1

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)

        # Track bytes for all private IPs
        if self._is_private_ip(src_ip) and src_ip != self.gateway_ip:
            with self.lock:
                self._ensure_device(src_ip)
                self.db[src_ip]["total_bytes"] += pkt_len
                self.db[src_ip]["last_seen"] = time.time()
                self.db[src_ip]["status"] = "active"

        if self._is_private_ip(dst_ip) and dst_ip != self.gateway_ip:
            with self.lock:
                self._ensure_device(dst_ip)
                self.db[dst_ip]["total_bytes"] += pkt_len
                self.db[dst_ip]["last_seen"] = time.time()

        # DNS Query handling
        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS):
            try:
                dns_layer = pkt[DNS]
                if dns_layer.qr == 0:  # Query (not response)
                    qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')

                    if self._is_noise(qname):
                        return

                    # The source IP is the device making the query
                    device_ip = src_ip

                    if not self._is_private_ip(device_ip):
                        return
                    if device_ip == self.gateway_ip or device_ip == self.own_ip:
                        return

                    self.dns_count += 1

                    with self.lock:
                        self._ensure_device(device_ip)
                        dev = self.db[device_ip]
                        now = time.time()

                        if qname in dev["domains"]:
                            d = dev["domains"][qname]
                            d["last_seen"] = now
                            d["visit_count"] += 1
                            d["bytes_total"] += pkt_len
                        else:
                            dev["domains"][qname] = {
                                "first_seen": now,
                                "last_seen": now,
                                "visit_count": 1,
                                "bytes_total": pkt_len,
                                "urls": []
                            }

                        dev["total_domains"] = len(dev["domains"])
                        dev["last_seen"] = now

                    logging.info(f"📡 {device_ip} → {qname}")

            except Exception as e:
                pass

    def _save_loop(self):
        """Periodically save the database and update stats."""
        while not self.stop_event.is_set():
            with self.lock:
                self._save_db()

                # Also write a combined stats file
                try:
                    stats = {
                        "passive_monitor": True,
                        "packet_count": self.packet_count,
                        "dns_queries_captured": self.dns_count,
                        "devices_tracked": len(self.db),
                        "timestamp": time.time()
                    }
                    # Don't overwrite traffic_stats.json if active monitor is running
                    # Instead write to a separate file
                    with open("passive_stats.json", 'w') as f:
                        json.dump(stats, f, indent=2)
                except Exception:
                    pass

            time.sleep(5)

    def _mark_inactive(self):
        """Mark devices as inactive if no traffic for > 5 minutes."""
        with self.lock:
            now = time.time()
            for ip, dev in self.db.items():
                if now - dev.get("last_seen", 0) > 300:
                    dev["status"] = "inactive"

    def run(self):
        logging.info("═══ Sentinel Passive Monitor v1.0 ═══")
        logging.info(f"Interface: {self.interface or 'auto'}")
        logging.info(f"Gateway: {self.gateway_ip or 'auto'}")
        logging.info(f"Listening for ALL DNS queries on the network...")
        logging.info(f"Footprint DB: {os.path.abspath(FOOTPRINT_DB)}")

        # Start save thread
        save_thread = threading.Thread(target=self._save_loop, daemon=True)
        save_thread.start()

        try:
            sniff(
                prn=self.handle_packet,
                store=0,
                stop_filter=lambda x: self.stop_event.is_set(),
                iface=self.interface,
                filter="udp port 53"  # DNS only for efficiency
            )
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        if self.stop_event.is_set():
            return
        logging.info("Shutting down passive monitor...")
        self.stop_event.set()
        with self.lock:
            self._save_db()
        logging.info(f"✅ Stopped. Captured {self.dns_count} DNS queries from {len(self.db)} devices.")


def get_default_gateway():
    """Detect gateway IP on macOS/Linux."""
    import subprocess
    try:
        if sys.platform == "darwin":
            result = subprocess.run(
                ['netstat', '-rn'], capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'default':
                    return parts[1]
        else:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'], capture_output=True, text=True
            )
            parts = result.stdout.split()
            if 'via' in parts:
                return parts[parts.index('via') + 1]
    except Exception:
        pass
    return None


def get_own_ip():
    """Get this machine's IP."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Passive DNS Monitor")
    parser.add_argument("-i", "--interface", help="Network interface (e.g., en0)")
    parser.add_argument("-g", "--gateway", help="Gateway IP (auto-detected if not set)")

    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.error("Root required. Run with: sudo python3 passive_monitor.py")
        sys.exit(1)

    gateway = args.gateway or get_default_gateway()
    own_ip = get_own_ip()
    logging.info(f"Gateway: {gateway}, Own IP: {own_ip}")

    monitor = PassiveMonitor(
        interface=args.interface,
        gateway_ip=gateway,
        own_ip=own_ip
    )

    def shutdown(signum, frame):
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    monitor.run()

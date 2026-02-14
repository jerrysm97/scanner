#!/usr/bin/env python3
"""
Sentinel Agent v2.0 — Professional Network Scanner Engine
=========================================================
Active ARP scanning via Scapy, multithreaded port scanning,
risk classification, and credential auditing.

Usage:
    python3 agent.py                  # Discovery scan (all devices)
    python3 agent.py <IP>             # Deep scan (ports + hostname)
    python3 agent.py audit <IP>       # Credential audit
"""

import sys
import os
import json
import socket
import logging
import concurrent.futures
import platform
import subprocess
import re
import urllib.request
import base64
import urllib.error

# ── Scapy Setup ──────────────────────────────────────────────────────────────
# Suppress ALL scapy output so only clean JSON hits stdout
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import ARP, Ether, srp, conf
conf.verb = 0  # Silence scapy globally


# ═══════════════════════════════════════════════════════════════════════════════
#  1. SUBNET DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def get_local_subnet():
    """
    Auto-detect the local network subnet (e.g. '192.168.1.0/24').
    Uses a UDP socket trick that works without root on macOS/Linux/Windows.
    Falls back to 192.168.1.0/24 if everything fails.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # Doesn't actually send data — just selects the right interface
            s.connect(("10.254.254.254", 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s.close()

        if local_ip.startswith("127."):
            # Try platform-specific fallback
            local_ip = _fallback_local_ip()

        if local_ip.startswith("127.") or local_ip == "0.0.0.0":
            return "192.168.1.0/24"

        # Build /24 subnet
        octets = local_ip.rsplit(".", 1)
        return f"{octets[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _fallback_local_ip():
    """Platform-specific fallback to find the local IP."""
    try:
        os_type = platform.system()
        if os_type == "Darwin":
            out = subprocess.check_output(
                ["ipconfig", "getifaddr", "en0"], stderr=subprocess.DEVNULL
            ).decode().strip()
            if out:
                return out
        elif os_type == "Linux":
            out = subprocess.check_output(
                ["hostname", "-I"], stderr=subprocess.DEVNULL
            ).decode().strip().split()[0]
            if out:
                return out
    except Exception:
        pass
    return "127.0.0.1"


# ═══════════════════════════════════════════════════════════════════════════════
#  2. NETWORK DISCOVERY (Active ARP Scan)
# ═══════════════════════════════════════════════════════════════════════════════

def scan_network():
    """
    Active ARP broadcast scan via Scapy.
    Discovers ALL devices on the local subnet — not just those in the cache.
    Falls back to passive 'arp -a' if not running as root.
    """
    target_range = get_local_subnet()
    scan_mode = "active"

    try:
        # ── Active Scan (requires root/admin) ────────────────────────────
        arp_request = ARP(pdst=target_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered, _ = srp(packet, timeout=3, verbose=0)

        devices = []
        seen_macs = set()
        for sent, received in answered:
            mac = received.hwsrc.lower()
            if mac not in seen_macs:
                seen_macs.add(mac)
                devices.append({
                    "ip": received.psrc,
                    "mac": mac,
                    "status": "online",
                    "scan_mode": "active"
                })
        return devices, scan_mode

    except PermissionError:
        scan_mode = "passive"
        _log_stderr("⚠️  Active scanning requires root privileges. Falling back to passive scan.")
        _log_stderr("    Run with: sudo python3 agent.py")
        return _passive_arp_scan(), scan_mode

    except Exception as e:
        scan_mode = "passive"
        _log_stderr(f"⚠️  Active scan failed ({type(e).__name__}: {e}). Trying passive scan...")
        return _passive_arp_scan(), scan_mode


def _passive_arp_scan():
    """Fallback: parse the OS ARP cache with 'arp -a'."""
    try:
        raw = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL).decode("utf-8")
        devices = []
        os_type = platform.system()

        for line in raw.splitlines():
            ip, mac = None, None

            if os_type == "Darwin":
                m = re.search(r"\(([\d.]+)\)\s+at\s+([\w:]+)\s+on", line)
                if m:
                    ip, mac = m.group(1), m.group(2)
            else:
                m = re.search(r"\(([\d.]+)\)\s+at\s+([\w:]+)", line)
                if not m:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1].strip("()")
                        mac = parts[3]
                else:
                    ip, mac = m.group(1), m.group(2)

            if ip and mac and "incomplete" not in mac.lower():
                devices.append({
                    "ip": ip,
                    "mac": mac.lower(),
                    "status": "online",
                    "scan_mode": "passive"
                })
        return devices
    except Exception as e:
        _log_stderr(f"❌ Passive scan also failed: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
#  3. DEEP SCAN — Multithreaded Port Scanner
# ═══════════════════════════════════════════════════════════════════════════════

# Top 20 security-relevant ports
TOP_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    502,   # Modbus (ICS/SCADA)
    554,   # RTSP (cameras)
    993,   # IMAPS
    995,   # POP3S
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
    8080,  # HTTP Proxy
]

# Ports that raise security concern
CRITICAL_PORTS = {23, 502, 554, 5900}   # Telnet, Modbus, RTSP, VNC
HIGH_RISK_PORTS = {21, 22, 3389, 445}   # FTP, SSH, RDP, SMB


def _check_port(ip, port):
    """Probe a single TCP port. Returns (port, banner) or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Try to grab a banner
            banner = ""
            try:
                sock.send(b"\r\n")
                banner = sock.recv(128).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            sock.close()
            return {"port": port, "banner": banner}
        sock.close()
    except Exception:
        pass
    return None


def _classify_risk(open_ports):
    """Classify the overall risk level based on open ports."""
    port_numbers = {p["port"] for p in open_ports}

    if port_numbers & CRITICAL_PORTS:
        return "CRITICAL"
    if port_numbers & HIGH_RISK_PORTS:
        return "HIGH"
    if port_numbers & {80, 8080, 443}:
        return "MEDIUM"
    return "LOW"


def deep_scan(target_ip):
    """
    Professional port scan: 20 threads, top 20 ports, banner grabbing,
    risk classification.
    """
    # 1. Hostname resolution
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
    except socket.herror:
        hostname = "Unknown"

    # 2. Parallel port scan with 20 threads
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_check_port, target_ip, port): port
            for port in TOP_PORTS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda p: p["port"])

    # 3. Risk classification
    risk_level = _classify_risk(open_ports)

    return {
        "ip": target_ip,
        "hostname": hostname,
        "open_ports": open_ports,
        "port_count": len(open_ports),
        "risk_level": risk_level
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  4. CREDENTIAL AUDIT
# ═══════════════════════════════════════════════════════════════════════════════

# Common default credential pairs to check
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("user", "user"),
]


def audit_credentials(target_ip):
    """Check a device for common default HTTP Basic Auth credentials."""
    url = f"http://{target_ip}"
    results = []

    for username, password in DEFAULT_CREDENTIALS:
        cred_b64 = base64.b64encode(f"{username}:{password}".encode()).decode("utf-8")
        headers = {"Authorization": f"Basic {cred_b64}"}

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=2) as response:
                if response.getcode() == 200:
                    results.append({
                        "credential": f"{username}:{password}",
                        "status": "VULNERABLE"
                    })
        except urllib.error.HTTPError as e:
            if e.code == 401:
                results.append({
                    "credential": f"{username}:{password}",
                    "status": "REJECTED"
                })
        except Exception:
            pass  # Connection refused / timeout — no HTTP server

    if not results:
        return {
            "ip": target_ip,
            "status": "SECURE",
            "risk": "LOW",
            "message": "No HTTP Basic Auth endpoint detected.",
            "details": []
        }

    vulnerable = [r for r in results if r["status"] == "VULNERABLE"]
    if vulnerable:
        return {
            "ip": target_ip,
            "status": "VULNERABLE",
            "risk": "CRITICAL",
            "message": f"{len(vulnerable)} default credential(s) accepted!",
            "details": results
        }

    return {
        "ip": target_ip,
        "status": "SECURE",
        "risk": "LOW",
        "message": "All default credentials rejected.",
        "details": results
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  5. UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def _log_stderr(msg):
    """Print diagnostic messages to stderr so stdout stays clean JSON."""
    print(msg, file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════════════════
#  6. CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "audit":
            if len(sys.argv) > 2:
                print(json.dumps(audit_credentials(sys.argv[2])))
            else:
                print(json.dumps({"error": "Usage: python3 agent.py audit <IP>"}))

        else:
            # Deep scan a specific IP
            # Validate IP format
            ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
            if ip_pattern.match(command):
                print(json.dumps(deep_scan(command)))
            else:
                print(json.dumps({"error": f"Invalid IP address: {command}"}))

    else:
        # Discovery scan
        devices, mode = scan_network()
        output = {
            "status": "success",
            "scan_mode": mode,
            "subnet": get_local_subnet(),
            "count": len(devices),
            "devices": devices
        }
        print(json.dumps(output))
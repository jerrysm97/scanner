#!/usr/bin/env python3
"""
Sentinel Agent v3.0 — Market-Ready Network Scanner Engine
==========================================================
Cross-platform ARP scanning (Windows/macOS/Linux), multithreaded
port scanning, risk classification, and credential auditing.

NO ROOT / ADMIN REQUIRED — uses native 'arp -a' command.

Usage:
    python3 agent.py                  # Discovery scan (all devices)
    python3 agent.py <IP>             # Deep scan (ports + hostname)
    python3 agent.py audit <IP>       # Credential audit
"""

import sys
import os
import json
import socket
import concurrent.futures
import platform
import subprocess
import re
import urllib.request
import base64
import urllib.error


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
            s.connect(("10.254.254.254", 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s.close()

        if local_ip.startswith("127."):
            local_ip = _fallback_local_ip()

        if local_ip.startswith("127.") or local_ip == "0.0.0.0":
            return "192.168.1.0/24"

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
        elif os_type == "Windows":
            out = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL
            ).decode()
            match = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", out)
            if match:
                return match.group(1)
    except Exception:
        pass
    return "127.0.0.1"


# ═══════════════════════════════════════════════════════════════════════════════
#  2. NETWORK DISCOVERY (Cross-Platform ARP Scan — NO ROOT NEEDED)
# ═══════════════════════════════════════════════════════════════════════════════

def scan_network():
    """
    Cross-platform ARP cache scan using 'arp -a'.
    Detects the OS and uses the correct regex pattern for each.

    Windows:  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic
    macOS:    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0
    Linux:    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
    """
    os_type = platform.system()
    _log_stderr(f"🖥️  Detected OS: {os_type}")

    try:
        if os_type == "Windows":
            raw = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=10
            ).decode("utf-8", errors="ignore")
        else:
            raw = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=10
            ).decode("utf-8", errors="ignore")
    except subprocess.TimeoutExpired:
        _log_stderr("❌ ARP command timed out.")
        return [], "timeout"
    except FileNotFoundError:
        _log_stderr("❌ 'arp' command not found on this system.")
        return [], "error"
    except Exception as e:
        _log_stderr(f"❌ ARP scan failed: {e}")
        return [], "error"

    devices = []
    seen_macs = set()

    for line in raw.splitlines():
        ip, mac = None, None

        if os_type == "Windows":
            # Windows format: "  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"
            m = re.search(
                r"((?:\d{1,3}\.){3}\d{1,3})\s+"
                r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-"
                r"[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})",
                line
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").lower()

        elif os_type == "Darwin":
            # macOS format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
            m = re.search(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                r"([0-9a-fA-F:]+)\s+on",
                line
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()

        else:
            # Linux format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            m = re.search(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                r"([0-9a-fA-F:]+)",
                line
            )
            if not m:
                # Fallback: try space-delimited fields
                parts = line.split()
                if len(parts) >= 4:
                    candidate_ip = parts[1].strip("()")
                    candidate_mac = parts[3]
                    if re.match(r"\d+\.\d+\.\d+\.\d+", candidate_ip) and ":" in candidate_mac:
                        ip = candidate_ip
                        mac = candidate_mac.lower()
            else:
                ip = m.group(1)
                mac = m.group(2).lower()

        # Skip incomplete or broadcast entries
        if ip and mac and "incomplete" not in mac and "ff:ff:ff:ff:ff:ff" not in mac:
            if mac not in seen_macs:
                seen_macs.add(mac)
                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "status": "online",
                    "scan_mode": "passive"
                })

    _log_stderr(f"📡 Found {len(devices)} device(s) on the network.")
    return devices, "passive"


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
    """Probe a single TCP port with 0.5s timeout. Returns (port, banner) or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
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
    risk classification. Uses 0.5s timeout per port.
    """
    # 1. Hostname resolution
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = "Unknown"

    # 2. Parallel port scan with 20 threads
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_check_port, target_ip, port): port
            for port in TOP_PORTS
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=5)
                if result:
                    open_ports.append(result)
            except Exception:
                pass

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
    """
    Check a device for common default HTTP Basic Auth credentials.
    Uses urllib to attempt login to http://<ip> with each credential pair.
    Returns VULNERABLE (200 OK) or SECURE (401 Unauthorized / connection refused).
    """
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
            # Other HTTP errors = skip
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
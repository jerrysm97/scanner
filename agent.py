#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
  Sentinel Agent v4.0 — Industrial-Grade Network Scanner (OOP)
═══════════════════════════════════════════════════════════════════════════════

  Cross-platform ARP scanning (Windows/macOS/Linux), multithreaded port
  scanning, risk classification, and HTTP Basic Auth credential auditing.

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
import urllib.error
import base64
from datetime import datetime


class NetworkScanner:
    """
    Industrial-grade network scanner with cross-platform ARP parsing,
    multithreaded port scanning, and HTTP credential auditing.
    """

    # Top 20 security-critical ports
    TOP_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 502, 554, 993, 995, 3306, 3389, 5900, 8080,
    ]

    CRITICAL_PORTS = {23, 502, 554, 5900}
    HIGH_RISK_PORTS = {21, 22, 3389, 445}

    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("root", "root"),
        ("root", ""),
        ("user", "user"),
    ]

    def __init__(self):
        self.os_type = platform.system()
        self._log(f"🖥️  OS Detected: {self.os_type}")

    # ═══════════════════════════════════════════════════════════════════════════
    #  LOGGING
    # ═══════════════════════════════════════════════════════════════════════════

    @staticmethod
    def _log(msg: str):
        """Print diagnostics to stderr so stdout stays clean JSON."""
        print(msg, file=sys.stderr)

    # ═══════════════════════════════════════════════════════════════════════════
    #  SUBNET DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def get_local_ip(self) -> str:
        """Auto-detect local IP address using a UDP socket trick."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            try:
                s.connect(("10.254.254.254", 1))
                ip = s.getsockname()[0]
            except Exception:
                ip = "127.0.0.1"
            finally:
                s.close()

            if ip.startswith("127."):
                ip = self._fallback_ip()
            return ip
        except Exception:
            return "127.0.0.1"

    def _fallback_ip(self) -> str:
        """Platform-specific IP fallback."""
        try:
            if self.os_type == "Darwin":
                return subprocess.check_output(
                    ["ipconfig", "getifaddr", "en0"], stderr=subprocess.DEVNULL
                ).decode().strip()
            elif self.os_type == "Linux":
                return subprocess.check_output(
                    ["hostname", "-I"], stderr=subprocess.DEVNULL
                ).decode().strip().split()[0]
            elif self.os_type == "Windows":
                out = subprocess.check_output(
                    ["ipconfig"], stderr=subprocess.DEVNULL
                ).decode()
                m = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", out)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return "127.0.0.1"

    def get_subnet(self) -> str:
        """Return the /24 subnet string."""
        ip = self.get_local_ip()
        return f"{ip.rsplit('.', 1)[0]}.0/24"

    # ═══════════════════════════════════════════════════════════════════════════
    #  NETWORK DISCOVERY (Cross-Platform ARP — NO ROOT)
    # ═══════════════════════════════════════════════════════════════════════════

    def scan(self) -> dict:
        """
        Cross-platform ARP cache scan using 'arp -a'.

        Regex patterns per OS:
          Windows:  192.168.1.1   aa-bb-cc-dd-ee-ff   dynamic
          macOS:    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0
          Linux:    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
        """
        self._log("📡 Starting network scan...")

        try:
            raw = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=15
            ).decode("utf-8", errors="ignore")
        except subprocess.TimeoutExpired:
            self._log("❌ ARP command timed out.")
            return self._scan_result([], "timeout")
        except FileNotFoundError:
            self._log("❌ 'arp' command not found.")
            return self._scan_result([], "error")
        except Exception as e:
            self._log(f"❌ ARP scan failed: {e}")
            return self._scan_result([], "error")

        devices = []
        seen_macs = set()

        for line in raw.splitlines():
            parsed = self._parse_arp_line(line)
            if parsed:
                ip, mac = parsed
                if mac not in seen_macs:
                    seen_macs.add(mac)
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "status": "online",
                        "scan_mode": "passive",
                        "last_seen": datetime.now().isoformat(),
                    })

        self._log(f"✅ Found {len(devices)} device(s).")
        return self._scan_result(devices, "passive")

    def _parse_arp_line(self, line: str):
        """
        Parse a single ARP output line based on the current OS.
        Returns (ip, mac) tuple or None.
        """
        ip, mac = None, None

        if self.os_type == "Windows":
            # Windows: "  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"
            m = re.search(
                r"((?:\d{1,3}\.){3}\d{1,3})\s+"
                r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-"
                r"[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})",
                line
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").lower()

        elif self.os_type == "Darwin":
            # macOS: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
            m = re.search(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                r"([0-9a-fA-F:]+)\s+on",
                line
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()

        else:
            # Linux: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            m = re.search(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                r"([0-9a-fA-F:]+)",
                line
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).lower()

        # Filter out incomplete and broadcast entries
        if ip and mac:
            if "incomplete" in mac or "ff:ff:ff:ff:ff:ff" in mac:
                return None
            return (ip, mac)

        return None

    def _scan_result(self, devices: list, mode: str) -> dict:
        """Build standardized scan result."""
        return {
            "status": "success",
            "scan_mode": mode,
            "subnet": self.get_subnet(),
            "count": len(devices),
            "devices": devices,
            "timestamp": datetime.now().isoformat(),
        }

    # ═══════════════════════════════════════════════════════════════════════════
    #  DEEP SCAN — Multithreaded Port Scanner
    # ═══════════════════════════════════════════════════════════════════════════

    def deep_scan(self, target_ip: str) -> dict:
        """
        Scan top 20 ports with 20 threads, banner grabbing, hostname
        resolution, and risk classification. 0.5s timeout per port.
        """
        self._log(f"🔍 Deep scanning {target_ip}...")

        # Hostname
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = "Unknown"

        # Parallel port scan
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            futures = {
                pool.submit(self._probe_port, target_ip, port): port
                for port in self.TOP_PORTS
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=5)
                    if result:
                        open_ports.append(result)
                except Exception:
                    pass

        open_ports.sort(key=lambda p: p["port"])
        risk = self._classify_risk(open_ports)

        return {
            "ip": target_ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "risk_level": risk,
            "timestamp": datetime.now().isoformat(),
        }

    def _probe_port(self, ip: str, port: int):
        """Probe a single TCP port. Returns dict or None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
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

    def _classify_risk(self, open_ports: list) -> str:
        """Classify risk based on open ports."""
        ports = {p["port"] for p in open_ports}
        if ports & self.CRITICAL_PORTS:
            return "CRITICAL"
        if ports & self.HIGH_RISK_PORTS:
            return "HIGH"
        if ports & {80, 8080, 443}:
            return "MEDIUM"
        return "LOW"

    # ═══════════════════════════════════════════════════════════════════════════
    #  CREDENTIAL AUDIT — HTTP Basic Auth Check
    # ═══════════════════════════════════════════════════════════════════════════

    def audit_credentials(self, target_ip: str) -> dict:
        """
        Check for default HTTP Basic Auth credentials on port 80.
        Uses urllib with Authorization headers to test each pair.
        Returns VULNERABLE (200) or SECURE (401 / connection refused).
        """
        self._log(f"🔐 Auditing credentials on {target_ip}...")

        url = f"http://{target_ip}"
        results = []

        for username, password in self.DEFAULT_CREDENTIALS:
            cred_str = f"{username}:{password}"
            cred_b64 = base64.b64encode(cred_str.encode()).decode("utf-8")
            headers = {"Authorization": f"Basic {cred_b64}"}

            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.getcode() == 200:
                        results.append({
                            "credential": cred_str,
                            "status": "VULNERABLE",
                        })
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    results.append({
                        "credential": cred_str,
                        "status": "REJECTED",
                    })
            except Exception:
                pass  # Connection refused / timeout

        vulnerable = [r for r in results if r["status"] == "VULNERABLE"]

        if vulnerable:
            return {
                "ip": target_ip,
                "status": "VULNERABLE",
                "risk": "CRITICAL",
                "message": f"{len(vulnerable)} default credential(s) accepted!",
                "details": results,
            }

        if not results:
            return {
                "ip": target_ip,
                "status": "SECURE",
                "risk": "LOW",
                "message": "No HTTP Basic Auth endpoint detected.",
                "details": [],
            }

        return {
            "ip": target_ip,
            "status": "SECURE",
            "risk": "LOW",
            "message": "All default credentials rejected.",
            "details": results,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    scanner = NetworkScanner()

    if len(sys.argv) == 1:
        # Discovery scan
        print(json.dumps(scanner.scan()))

    elif sys.argv[1] == "audit" and len(sys.argv) > 2:
        # Credential audit
        print(json.dumps(scanner.audit_credentials(sys.argv[2])))

    elif re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", sys.argv[1]):
        # Deep scan
        print(json.dumps(scanner.deep_scan(sys.argv[1])))

    else:
        print(json.dumps({"error": f"Unknown command: {sys.argv[1]}"}))
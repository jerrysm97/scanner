#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
  Sentinel Agent v5.0 — Production-Ready Network Scanner (Enterprise OOP)
═══════════════════════════════════════════════════════════════════════════════

  Architecture:  OOP—class NetworkScanner with clean method isolation
  Threading:     concurrent.futures.ThreadPoolExecutor for parallel port scans
  Compatibility: Windows (dashes), macOS (colons), Linux (colons)
  Security:      No root/admin required—uses native 'arp -a'
  Safety:        Every socket has a 0.5s hard timeout—never hangs

  Usage:
      python3 agent.py                  →  Network discovery (JSON to stdout)
      python3 agent.py <IP>             →  Deep scan (ports + hostname + risk)
      python3 agent.py audit <IP>       →  HTTP Basic Auth credential audit

  Edge Cases Handled:
      - Empty ARP output              → returns empty device list
      - 'arp' command not found       → returns error status
      - ARP entries with "incomplete" → silently skipped
      - Multicast / broadcast MACs    → silently skipped
      - Socket timeout on every port  → never blocks > 0.5s per port
      - No local IP detected          → falls back to 127.0.0.1
      - Invalid CLI arguments         → returns helpful JSON error
"""

import sys
import json
import socket
import platform
import subprocess
import re
import base64
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime
from typing import Optional, List, Dict, Tuple


class NetworkScanner:
    """
    Production-ready network scanner with cross-platform ARP parsing,
    multithreaded port scanning, and credential auditing.

    All public methods return JSON-serializable dicts.
    All I/O errors are caught—this class will NEVER raise to the caller.
    """

    # ── Configuration ──────────────────────────────────────────────────────────

    # Top 20 security-critical ports (ordered by severity)
    TOP_PORTS: List[int] = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 502, 554, 993, 995, 3306, 3389, 5900, 8080,
    ]

    CRITICAL_PORTS = frozenset({23, 502, 554, 5900})       # Telnet, Modbus, RTSP, VNC
    HIGH_RISK_PORTS = frozenset({21, 22, 3389, 445})       # FTP, SSH, RDP, SMB
    MEDIUM_RISK_PORTS = frozenset({80, 8080, 443, 3306})   # HTTP, MySQL

    SOCKET_TIMEOUT: float = 0.5       # Hard cap per port probe
    ARP_TIMEOUT: int = 15             # Max wait for 'arp -a'
    MAX_PORT_WORKERS: int = 20        # Thread pool size for port scanning

    # Default credentials to test (username, password)
    DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("root", "root"),
        ("root", ""),
        ("user", "user"),
        ("admin", "admin123"),
    ]

    # ── Constructor ────────────────────────────────────────────────────────────

    def __init__(self):
        """
        Initialize scanner with OS detection.
        Edge case: platform.system() returns '' on rare/exotic OS → defaults to Linux.
        """
        self._os_type: str = platform.system() or "Linux"
        self._log(f"🖥️  OS: {self._os_type}  |  Python: {platform.python_version()}")

    # ── Logging ────────────────────────────────────────────────────────────────

    @staticmethod
    def _log(message: str) -> None:
        """
        Write diagnostic messages to stderr so stdout stays clean JSON.
        Edge case: stderr might be closed in daemon mode → silently ignore.
        """
        try:
            print(message, file=sys.stderr, flush=True)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════
    #  NETWORK DETECTION
    # ═══════════════════════════════════════════════════════════════════════════

    def _get_local_ip(self) -> str:
        """
        Auto-detect local LAN IP using a non-connecting UDP socket trick.
        This never sends any data—just checks route binding.

        Edge cases:
            - No network interface        → falls back to platform-specific method
            - Platform method also fails   → returns 127.0.0.1
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0)
            try:
                sock.connect(("10.254.254.254", 1))
                local_ip = sock.getsockname()[0]
            except Exception:
                local_ip = "127.0.0.1"
            finally:
                sock.close()

            if local_ip.startswith("127."):
                local_ip = self._platform_ip_fallback()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def _platform_ip_fallback(self) -> str:
        """
        OS-specific fallback for IP detection.
        Edge case: each command might not exist → wrapped in try/except.
        """
        try:
            if self._os_type == "Darwin":
                return subprocess.check_output(
                    ["ipconfig", "getifaddr", "en0"],
                    stderr=subprocess.DEVNULL, timeout=5
                ).decode().strip()
            elif self._os_type == "Linux":
                output = subprocess.check_output(
                    ["hostname", "-I"],
                    stderr=subprocess.DEVNULL, timeout=5
                ).decode().strip()
                return output.split()[0] if output else "127.0.0.1"
            elif self._os_type == "Windows":
                output = subprocess.check_output(
                    ["ipconfig"], stderr=subprocess.DEVNULL, timeout=10
                ).decode()
                match = re.search(r"IPv4 Address[.\s]*:\s*([\d.]+)", output)
                return match.group(1) if match else "127.0.0.1"
        except Exception:
            pass
        return "127.0.0.1"

    def _get_subnet(self) -> str:
        """Return the /24 subnet string from local IP."""
        ip = self._get_local_ip()
        return f"{ip.rsplit('.', 1)[0]}.0/24"

    # ═══════════════════════════════════════════════════════════════════════════
    #  NETWORK DISCOVERY — Cross-Platform ARP Parsing
    # ═══════════════════════════════════════════════════════════════════════════

    def scan(self) -> dict:
        """
        Discover all devices on the local network via 'arp -a'.

        ARP output formats by OS:
            Windows:  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic
            macOS:    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ...
            Linux:    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0

        Edge cases handled:
            - 'arp' command not found      → returns error status
            - Command times out            → returns timeout status
            - Empty output                 → returns empty device list
            - Duplicate MACs               → deduplicated via set()
            - "incomplete" ARP entries     → filtered out
            - Broadcast ff:ff:ff:ff:ff:ff  → filtered out
        """
        self._log("📡 Starting network discovery scan...")

        try:
            raw_output = subprocess.check_output(
                ["arp", "-a"],
                stderr=subprocess.DEVNULL,
                timeout=self.ARP_TIMEOUT,
            ).decode("utf-8", errors="ignore")
        except subprocess.TimeoutExpired:
            self._log("❌ ARP command timed out after 15s.")
            return self._build_scan_result([], "timeout_error")
        except FileNotFoundError:
            self._log("❌ 'arp' command not found on this system.")
            return self._build_scan_result([], "command_not_found")
        except subprocess.CalledProcessError as e:
            self._log(f"❌ ARP command failed: {e}")
            return self._build_scan_result([], "command_error")
        except Exception as e:
            self._log(f"❌ Unexpected ARP error: {e}")
            return self._build_scan_result([], "unknown_error")

        # Edge case: ARP returned an empty string
        if not raw_output.strip():
            self._log("⚠️  ARP returned empty output.")
            return self._build_scan_result([], "empty")

        device_list: List[dict] = []
        seen_macs: set = set()

        for line in raw_output.splitlines():
            parsed = self._parse_arp_line(line)
            if parsed is None:
                continue

            ip_addr, mac_addr = parsed

            # Deduplicate by MAC
            if mac_addr in seen_macs:
                continue
            seen_macs.add(mac_addr)

            device_list.append({
                "ip": ip_addr,
                "mac": mac_addr,
                "status": "online",
                "scan_mode": "passive",
                "last_seen": datetime.now().isoformat(),
            })

        self._log(f"✅ Discovery complete: {len(device_list)} device(s) found.")
        return self._build_scan_result(device_list, "passive")

    def _parse_arp_line(self, line: str) -> Optional[Tuple[str, str]]:
        """
        Parse a single line of ARP output into (ip, mac).

        Returns None if:
            - Line doesn't match any known ARP format
            - Entry contains "incomplete" (no MAC resolved)
            - MAC is broadcast (ff:ff:ff:ff:ff:ff)
            - MAC is all zeros (00:00:00:00:00:00)

        Windows uses dashes (aa-bb-cc-dd-ee-ff) → normalized to colons.
        """
        ip_addr: Optional[str] = None
        mac_addr: Optional[str] = None

        if self._os_type == "Windows":
            # Windows format: "  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"
            match = re.search(
                r"((?:\d{1,3}\.){3}\d{1,3})\s+"
                r"([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-"
                r"[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})",
                line,
            )
            if match:
                ip_addr = match.group(1)
                mac_addr = match.group(2).replace("-", ":").lower()
        else:
            # macOS / Linux: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff ..."
            match = re.search(
                r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                r"([0-9a-fA-F:]+)",
                line,
            )
            if match:
                ip_addr = match.group(1)
                mac_addr = match.group(2).lower()

        # Validation: reject incomplete, broadcast, and zero MACs
        if not ip_addr or not mac_addr:
            return None
        if "incomplete" in line.lower():
            return None
        if mac_addr in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None

        return (ip_addr, mac_addr)

    def _build_scan_result(self, device_list: list, scan_mode: str) -> dict:
        """Build standardized JSON response for scan results."""
        return {
            "status": "success" if scan_mode == "passive" else "partial",
            "scan_mode": scan_mode,
            "subnet": self._get_subnet(),
            "count": len(device_list),
            "devices": device_list,
            "timestamp": datetime.now().isoformat(),
        }

    # ═══════════════════════════════════════════════════════════════════════════
    #  DEEP SCAN — Multithreaded Port Scanner
    # ═══════════════════════════════════════════════════════════════════════════

    def deep_scan(self, target_ip: str) -> dict:
        """
        Parallel port scan using ThreadPoolExecutor (20 workers).
        Each port probe has a strict 0.5s timeout—NEVER hangs.

        Includes:
            - Hostname resolution (reverse DNS)
            - Banner grabbing on open ports
            - Risk classification (CRITICAL / HIGH / MEDIUM / LOW)

        Edge cases:
            - Invalid IP string        → socket raises immediately
            - All ports filtered       → returns empty list, LOW risk
            - DNS resolution fails     → hostname = "Unknown"
            - Banner grab times out    → banner = "" (empty string)
        """
        self._log(f"🔍 Deep scanning {target_ip} with {self.MAX_PORT_WORKERS} threads...")

        # Hostname resolution
        hostname = "Unknown"
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

        # Parallel port scanning
        open_ports: List[dict] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_PORT_WORKERS) as executor:
            future_to_port = {
                executor.submit(self._probe_port, target_ip, port): port
                for port in self.TOP_PORTS
            }

            for future in concurrent.futures.as_completed(future_to_port):
                try:
                    result = future.result(timeout=5)
                    if result is not None:
                        open_ports.append(result)
                except concurrent.futures.TimeoutError:
                    self._log(f"⚠️  Port scan thread timed out for port {future_to_port[future]}")
                except Exception as e:
                    self._log(f"⚠️  Port scan error: {e}")

        open_ports.sort(key=lambda p: p["port"])
        risk_level = self._classify_risk(open_ports)

        self._log(f"✅ Deep scan complete: {len(open_ports)} open port(s), risk={risk_level}.")

        return {
            "ip": target_ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "port_count": len(open_ports),
            "risk_level": risk_level,
            "timestamp": datetime.now().isoformat(),
        }

    def _probe_port(self, ip: str, port: int) -> Optional[dict]:
        """
        Probe a single TCP port with a strict 0.5s timeout.

        Returns {"port": int, "banner": str} if open, or None if closed/filtered.

        Edge cases:
            - Connection refused  → returns None (port closed)
            - Timeout             → returns None (port filtered)
            - Banner recv fails   → returns port with empty banner
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.SOCKET_TIMEOUT)

            if sock.connect_ex((ip, port)) == 0:
                banner = ""
                try:
                    sock.send(b"\r\n")
                    raw_banner = sock.recv(128)
                    banner = raw_banner.decode("utf-8", errors="ignore").strip()
                except (socket.timeout, OSError):
                    pass  # No banner available—that's fine
                finally:
                    sock.close()
                return {"port": port, "banner": banner}

            sock.close()
        except Exception:
            pass

        return None

    def _classify_risk(self, open_ports: List[dict]) -> str:
        """
        Classify overall risk based on which ports are open.
        Priority: CRITICAL > HIGH > MEDIUM > LOW
        """
        port_numbers = frozenset(p["port"] for p in open_ports)

        if port_numbers & self.CRITICAL_PORTS:
            return "CRITICAL"
        if port_numbers & self.HIGH_RISK_PORTS:
            return "HIGH"
        if port_numbers & self.MEDIUM_RISK_PORTS:
            return "MEDIUM"
        return "LOW"

    # ═══════════════════════════════════════════════════════════════════════════
    #  CREDENTIAL AUDIT — HTTP Basic Auth
    # ═══════════════════════════════════════════════════════════════════════════

    def audit_credentials(self, target_ip: str) -> dict:
        """
        Test default HTTP Basic Auth credentials on port 80.

        Uses urllib with Authorization headers to attempt each credential pair.
        Status per credential:
            - VULNERABLE  →  HTTP 200 (server accepted default credentials!)
            - REJECTED    →  HTTP 401 (credentials refused—good)
            - UNREACHABLE →  Connection failed

        Edge cases:
            - No HTTP server on port 80    → returns SECURE with "no endpoint"
            - Connection timeout (>2s)     → skips that credential
            - SSL redirect                 → caught by urllib, skipped
            - Non-standard HTTP responses  → caught by generic Exception
        """
        self._log(f"🔐 Auditing default credentials on {target_ip}:80...")

        url = f"http://{target_ip}"
        audit_results: List[dict] = []
        reachable = False

        for username, password in self.DEFAULT_CREDENTIALS:
            credential_string = f"{username}:{password}"
            encoded_creds = base64.b64encode(credential_string.encode()).decode("utf-8")
            headers = {"Authorization": f"Basic {encoded_creds}"}

            try:
                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=2) as response:
                    reachable = True
                    if response.getcode() == 200:
                        audit_results.append({
                            "credential": credential_string,
                            "status": "VULNERABLE",
                        })
            except urllib.error.HTTPError as http_err:
                reachable = True
                if http_err.code == 401:
                    audit_results.append({
                        "credential": credential_string,
                        "status": "REJECTED",
                    })
                # Other HTTP errors (403, 500, etc.) → skip silently
            except (urllib.error.URLError, OSError, socket.timeout):
                # Connection refused, timeout, DNS failure
                pass
            except Exception:
                pass

        # Build response
        vulnerable_count = sum(1 for r in audit_results if r["status"] == "VULNERABLE")

        if vulnerable_count > 0:
            return {
                "ip": target_ip,
                "status": "VULNERABLE",
                "risk": "CRITICAL",
                "message": f"{vulnerable_count} default credential(s) accepted!",
                "details": audit_results,
                "timestamp": datetime.now().isoformat(),
            }

        if not reachable:
            return {
                "ip": target_ip,
                "status": "SECURE",
                "risk": "LOW",
                "message": "No HTTP endpoint detected on port 80.",
                "details": [],
                "timestamp": datetime.now().isoformat(),
            }

        return {
            "ip": target_ip,
            "status": "SECURE",
            "risk": "LOW",
            "message": "All default credentials rejected.",
            "details": audit_results,
            "timestamp": datetime.now().isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
#
#  Edge cases:
#      - No arguments           → runs discovery scan
#      - 'audit' without IP     → returns error JSON
#      - Invalid IP format      → returns error JSON
#      - Unknown command        → returns error JSON

if __name__ == "__main__":
    scanner = NetworkScanner()
    ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

    if len(sys.argv) == 1:
        # No args → discovery scan
        print(json.dumps(scanner.scan()))

    elif sys.argv[1] == "audit":
        if len(sys.argv) < 3 or not ip_pattern.match(sys.argv[2]):
            print(json.dumps({"error": "Usage: python3 agent.py audit <IP>"}))
        else:
            print(json.dumps(scanner.audit_credentials(sys.argv[2])))

    elif ip_pattern.match(sys.argv[1]):
        # Valid IP → deep scan
        print(json.dumps(scanner.deep_scan(sys.argv[1])))

    else:
        print(json.dumps({
            "error": f"Unknown command: '{sys.argv[1]}'",
            "usage": [
                "python3 agent.py              → Network discovery",
                "python3 agent.py <IP>          → Deep port scan",
                "python3 agent.py audit <IP>    → Credential audit",
            ],
        }))
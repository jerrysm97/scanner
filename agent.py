#!/usr/bin/env python3
import sys
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
from scapy.all import ARP, Ether, srp

# Suppress Scapy warnings to keep JSON output clean
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_local_ip_range():
    """Auto-detects local IP and subnet (e.g., 192.168.1.0/24)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to connect, just needs to pick an interface
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return f"{ip.rsplit('.', 1)[0]}.0/24"
    except:
        return "192.168.1.0/24" # Fallback

def scan_network():
    """ 
    GAP FIX: Active ARP Scan 
    Sends 'Who is here?' packets to the whole network.
    Falls back to passive scan if non-root.
    """
    target_ip = get_local_ip_range()
    
    try:
        # 1. Try Active ARP Request
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "status": "online"
            })
        return devices

    except Exception as active_err:
        # Fallback to passive ARP scan if active fails (e.g. no root)
        try:
            os_type = platform.system()
            args = ["arp", "-a"]
            raw_output = subprocess.check_output(args).decode("utf-8")
            
            devices = []
            for line in raw_output.split('\n'):
                ip = None
                mac = None
                
                if os_type == "Darwin": # macOS
                    match = re.search(r'\((.*?)\) at (.*?) on', line)
                    if match:
                        ip, mac = match.group(1), match.group(2)
                else: # Linux / Windows
                    match = re.search(r'\((.*?)\) at (.*?) \[', line)
                    if not match:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[1].strip('()')
                            mac = parts[3]
                    else:
                        ip, mac = match.group(1), match.group(2)

                if ip and mac and "incomplete" not in mac:
                    devices.append({"ip": ip, "mac": mac, "status": "online (passive)"})
            return devices
        except Exception as passive_err:
            return {"error": f"Active scan failed ({str(active_err)}) and Passive scan failed ({str(passive_err)})"}

def check_port(ip, port):
    """Helper for multithreading port scan"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except:
        pass
    return None

def deep_scan(target_ip):
    """
    GAP FIX: Multithreaded Port Scanner
    Scans common ports in parallel for speed.
    """
    # 1. Get Hostname
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
    except socket.herror:
        hostname = "Unknown Hostname"
    
    # 2. Parallel Port Scan
    # Added common industrial and management ports
    common_ports = [21, 22, 23, 53, 80, 135, 139, 443, 445, 502, 554, 3389, 8080]
    open_ports = []
    
    # Scan using 15 threads for high speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_port = {executor.submit(check_port, target_ip, p): p for p in common_ports}
        for future in concurrent.futures.as_completed(future_to_port):
            p = future.result()
            if p:
                open_ports.append(p)
        
    return {
        "ip": target_ip,
        "hostname": hostname,
        "open_ports": sorted(open_ports),
        "risk_level": "HIGH" if (22 in open_ports or 23 in open_ports or 554 in open_ports) else "LOW"
    }

def audit_credentials(target_ip):
    """ Vulnerability Scanner: Checks for weak 'admin:admin' credentials """
    url = f"http://{target_ip}"
    credentials = base64.b64encode(b"admin:admin").decode("utf-8")
    headers = {"Authorization": f"Basic {credentials}"}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=1) as response:
            if response.getcode() == 200:
                return {"status": "VULNERABLE", "risk": "CRITICAL", "message": "Default credentials (admin:admin) accepted!"}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"status": "SECURE", "risk": "LOW", "message": "Device is password protected."}
    except Exception as e:
        return {"status": "SECURE", "risk": "LOW", "message": f"Connection failed/Auth not requested: {str(e)}"}
    
    return {"status": "SECURE", "risk": "LOW", "message": "No login form found."}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "audit":
            # Usage: python3 agent.py audit <IP>
            if len(sys.argv) > 2:
                print(json.dumps(audit_credentials(sys.argv[2])))
            else:
                 print(json.dumps({"error": "Missing IP"}))
        else:
            # Usage: python3 agent.py <IP> (Deep Scan)
            print(json.dumps(deep_scan(cmd)))
    else:
        # Usage: python3 agent.py (Discovery)
        found_devices = scan_network()
        if isinstance(found_devices, dict) and "error" in found_devices:
             results = {"status": "error", "message": found_devices["error"], "devices": []}
        else:
            results = {"status": "success", "count": len(found_devices), "devices": found_devices}
        print(json.dumps(results))
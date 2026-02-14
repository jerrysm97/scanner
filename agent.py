#!/usr/bin/env python3
import subprocess
import re
import json
import sys
import socket
import platform
import urllib.request
import base64
import urllib.error

from scapy.all import ARP, Ether, srp

def scan_network(target_ip="192.168.1.0/24"):
    """
    Active ARP Scan using Scapy.
    Falls back to passive 'arp -a' if active scan fails (e.g. no root).
    """
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
        # Fallback to passive ARP scan if active fails
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

def deep_scan(target_ip):
    """ Checks for common open ports and hostname """
    # 1. Get Hostname
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
    except socket.herror:
        hostname = "Unknown Hostname"
    
    # 2. Scan Common Ports
    open_ports = []
    # Ports: FTP, SSH, DNS, HTTP, HTTPS, Modbus, RTSP, Alt-HTTP
    common_ports = [21, 22, 53, 80, 443, 502, 554, 8080]
   
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3) # Fast timeout
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
        
    return {
        "ip": target_ip,
        "hostname": hostname,
        "open_ports": open_ports,
        "risk_level": "HIGH" if (22 in open_ports or 554 in open_ports) else "LOW"
    }

def audit_credentials(target_ip):
    """ 
    Vulnerability Scanner: Checks for weak 'admin:admin' credentials 
    Returns: {"status": "VULNERABLE"} or {"status": "SECURE"}
    """
    url = f"http://{target_ip}"
    # Create Basic Auth Header for "admin:admin"
    credentials = base64.b64encode(b"admin:admin").decode("utf-8")
    headers = {"Authorization": f"Basic {credentials}"}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        # Timeout is 1 second as requested
        with urllib.request.urlopen(req, timeout=1) as response:
            if response.getcode() == 200:
                return {"status": "VULNERABLE", "risk": "CRITICAL", "message": "Default credentials (admin:admin) accepted!"}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"status": "SECURE", "risk": "LOW", "message": "Device is password protected."}
    except Exception as e:
        # Connection failed or other error - consider it secure/unreachable for this specific test
        return {"status": "SECURE", "risk": "LOW", "message": f"Connection failed/Auth not requested: {str(e)}"}
    
    return {"status": "SECURE", "risk": "LOW", "message": "No login form or auth required."}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        first_arg = sys.argv[1]
        
        if first_arg == "audit":
            # Usage: python3 agent.py audit <IP>
            if len(sys.argv) > 2:
                target_ip = sys.argv[2]
                print(json.dumps(audit_credentials(target_ip)))
            else:
                 print(json.dumps({"error": "Missing IP for audit"}))
        else:
            # Usage: python3 agent.py <IP>  (Deep Scan)
            print(json.dumps(deep_scan(first_arg)))
    else:
        # Usage: python3 agent.py (Discovery)
        found_devices = scan_network()
        if isinstance(found_devices, dict) and "error" in found_devices:
             results = {
                "status": "error",
                "message": found_devices["error"],
                "count": 0,
                "devices": []
            }
        else:
            results = {
                "status": "success",
                "count": len(found_devices),
                "devices": found_devices
            }
        print(json.dumps(results))
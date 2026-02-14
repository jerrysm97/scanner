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

def scan_network():
    """ 
    Robust ARP scan that detects OS (Linux vs MacOS) 
    and parses 'arp -a' correctly for both.
    """
    devices = []
    try:
        # Detect OS
        os_type = platform.system()
        args = ["arp", "-a"]
        
        # Execute command
        raw_output = subprocess.check_output(args).decode("utf-8")
        
        for line in raw_output.split('\n'):
            ip = None
            mac = None
            
            if os_type == "Darwin": # macOS
                # Format: ? (192.168.1.1) at 00:11:22:33:44:55 on en0 ...
                match = re.search(r'\((.*?)\) at (.*?) on', line)
                if match:
                    ip, mac = match.group(1), match.group(2)
            else: # Linux / Windows (Assuming Linux-like output for generic container)
                # Format: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
                match = re.search(r'\((.*?)\) at (.*?) \[', line)
                if not match:
                    # Alternative Linux format: 192.168.1.1 at 00:11...
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1].strip('()')
                        mac = parts[3]
                else:
                    ip, mac = match.group(1), match.group(2)

            if ip and mac and "incomplete" not in mac:
                devices.append({"ip": ip, "mac": mac, "status": "online"})
                
        return devices
    except Exception as e:
        return {"error": str(e)}

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
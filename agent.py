#!/usr/bin/env python3
import subprocess
import re
import json
import sys
import socket

def scan_mac_native():
    """ Basic ARP scan to find devices """
    try:
        raw_output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
        devices = []
        for line in raw_output.split('\n'):
            match = re.search(r'\((.*?)\) at (.*?) on', line)
            if match:
                ip, mac = match.groups()
                if "incomplete" not in mac:
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
    """ Vulnerability Scanner: Checks for weak 'admin:admin' credentials """
    import urllib.request
    import base64

    url = f"http://{target_ip}"
    # Create Basic Auth Header for "admin:admin"
    credentials = base64.b64encode(b"admin:admin").decode("utf-8")
    headers = {"Authorization": f"Basic {credentials}"}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        # Timeout is crucial to avoid hanging
        with urllib.request.urlopen(req, timeout=2) as response:
            if response.getcode() == 200:
                return {"status": "SUCCESS", "risk": "CRITICAL", "message": "Weak Credentials (admin:admin) Found!"}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"status": "FAILED", "risk": "LOW", "message": "Device is password protected."}
    except Exception as e:
        return {"status": "ERROR", "risk": "LOW", "message": f"Connection failed: {str(e)}"}
    
    return {"status": "UNKNOWN", "risk": "LOW", "message": "No typical login form found."}

if __name__ == "__main__":
    # If an IP argument is provided
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        
        # Check for mode argument
        mode = sys.argv[2] if len(sys.argv) > 2 else "scan"
        
        if mode == "audit":
            print(json.dumps(audit_credentials(target_ip)))
        else:
            print(json.dumps(deep_scan(target_ip)))
    else:
        # Otherwise, do a normal discovery scan
        found_devices = scan_mac_native()
        results = {
            "status": "success",
            "count": len(found_devices),
            "devices": found_devices
        }
        print(json.dumps(results))
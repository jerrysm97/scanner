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
    # Ports: FTP, SSH, DNS, HTTP, HTTPS, RTSP(Camera), Alt-HTTP
    common_ports = [21, 22, 53, 80, 443, 554, 8080]
   
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

if __name__ == "__main__":
    # If an IP argument is provided, do a DEEP SCAN
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
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
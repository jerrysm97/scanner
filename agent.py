#!/usr/bin/env python3
import subprocess
import re
import json
import sys

def scan_mac_native():
    """
    Uses the macOS native 'arp' command to discover local devices.
    This avoids the need for external libraries or root privileges.
    """
    try:
        # Runs the built-in macOS ARP utility to see the current network table
        # Format: ? (192.168.1.1) at 00:11:22:33:44:55 on en0 ...
        raw_output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
        
        devices = []
        for line in raw_output.split('\n'):
            # Regex to capture the IP (inside parentheses) and the MAC address
            match = re.search(r'\((.*?)\) at (.*?) on', line)
            
            if match:
                ip_address = match.group(1)
                mac_address = match.group(2)
                
                # Exclude entries that are not fully resolved
                if "incomplete" not in mac_address:
                    devices.append({
                        "ip": ip_address,
                        "mac": mac_address,
                        "status": "online"
                    })
        return devices
    except Exception as e:
        # Return an error indicator if the scan fails
        return {"error": str(e)}

if __name__ == "__main__":
    # Perform the discovery scan
    found_devices = scan_mac_native()
    
    # Check if we returned an error during the scan
    if isinstance(found_devices, dict) and "error" in found_devices:
        results = {
            "status": "error",
            "message": found_devices["error"],
            "count": 0,
            "devices": []
        }
    else:
        # Create a clean, serializable Python dictionary
        results = {
            "status": "success",
            "count": len(found_devices),
            "devices": found_devices
        }
    
    # Print ONLY the JSON string.
    # This is crucial so your Node.js Bridge receives valid JSON data.
    print(json.dumps(results))
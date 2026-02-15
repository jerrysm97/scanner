#!/bin/bash
echo "🛡️  Sentinel v6.0 — Starting with Root Privileges..."
echo "🔑  Please enter your password if prompted."

# Kill any existing processes
sudo pkill -9 -f node 2>/dev/null
sudo pkill -9 -f traffic_monitor 2>/dev/null
sudo pkill -9 -f passive_monitor 2>/dev/null
sudo pkill -9 -f python3 2>/dev/null

# Start Server
cd "$(dirname "$0")"
sudo node Backend/server.js

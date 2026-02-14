#!/bin/bash
# ═══════════════════════════════════════════════════════
# Sentinel — Linux Setup Script
# ═══════════════════════════════════════════════════════
# Run: chmod +x setup_linux.sh && sudo ./setup_linux.sh

set -e

echo ""
echo "🛡️  SENTINEL — Linux Setup"
echo "═══════════════════════════════"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run with sudo: sudo ./setup_linux.sh"
    exit 1
fi

# 1. System packages
echo "📦 Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip nodejs npm nmap arp-scan net-tools curl > /dev/null 2>&1
echo "   ✅ System packages installed"

# 2. Python packages
echo "🐍 Installing Python packages..."
pip3 install scapy netifaces --break-system-packages 2>/dev/null || pip3 install scapy netifaces
echo "   ✅ Python packages installed"

# 3. Node packages
echo "📦 Installing Node.js packages..."
cd Backend
npm install --silent
cd ..
echo "   ✅ Node packages installed"

# 4. Enable IP forwarding
echo "🔧 Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "   ✅ IP forwarding enabled"

# 5. Check everything
echo ""
echo "🔍 Verification:"
echo "   Node.js:  $(node --version)"
echo "   Python3:  $(python3 --version)"
echo "   npm:      $(npm --version)"
python3 -c "import scapy; print('   Scapy:    ✅ OK')" 2>/dev/null || echo "   Scapy:    ❌ FAILED"
python3 -c "import netifaces; print('   Netifaces: ✅ OK')" 2>/dev/null || echo "   Netifaces: ❌ FAILED"

# 6. Detect interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "   Interface: $IFACE"

echo ""
echo "═══════════════════════════════"
echo "✅ SETUP COMPLETE!"
echo ""
echo "To start Sentinel:"
echo "   sudo node Backend/server.js"
echo ""
echo "Then open in browser:"
echo "   http://localhost:3000"
echo "═══════════════════════════════"
echo ""

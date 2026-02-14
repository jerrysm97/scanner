#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Sentinel Project — Full Setup Script
# ═══════════════════════════════════════════════════════════════════════════════
# Run this from the project root: bash commands.sh

set -e

echo "🛡️  Sentinel Project — Installing Dependencies"
echo "================================================"

# ── 1. Python Dependencies ────────────────────────────────────────────────────
echo ""
echo "📦 Installing Python packages..."
pip3 install scapy

# ── 2. Backend (Node.js) Dependencies ─────────────────────────────────────────
echo ""
echo "📦 Installing Backend Node.js packages..."
cd Backend
npm install express cors mac-lookup
cd ..

# ── 3. Mobile (React Native) Dependencies ────────────────────────────────────
echo ""
echo "📦 Installing Mobile React Native packages..."
cd SentinelMobile
npm install @react-native-async-storage/async-storage
cd ..

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "✅ All dependencies installed!"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  HOW TO RUN:"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  1. Start the Backend (from project root):"
echo "     cd Backend && sudo node server.js"
echo ""
echo "  2. Start the Mobile App (from SentinelMobile/):"
echo "     npx react-native run-android"
echo "     # or"
echo "     npx react-native run-ios"
echo ""
echo "  3. Test the Agent directly:"
echo "     sudo python3 agent.py              # Discovery scan"
echo "     sudo python3 agent.py 192.168.1.1  # Deep scan"
echo "     python3 agent.py audit 192.168.1.1 # Credential audit"
echo ""
echo "═══════════════════════════════════════════════════════════════"

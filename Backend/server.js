/**
 * Sentinel Backend v2.0 — Intelligence Bridge
 * =============================================
 * Express server that orchestrates the Python agent, enriches results
 * with MAC vendor names, classifies device types, and runs a honeypot.
 *
 * Run: sudo node server.js   (sudo needed for agent active scanning)
 */

const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');
const net = require('net');
const os = require('os');
const macLookup = require('mac-lookup');

const app = express();
const PORT = 3000;
const HONEYPOT_PORT = 2323;

// ═══════════════════════════════════════════════════════════════════════════════
//  STARTUP CHECKS
// ═══════════════════════════════════════════════════════════════════════════════

// 1. Privilege check
const isRoot = process.getuid && process.getuid() === 0;
if (!isRoot) {
    console.warn("⚠️  WARNING: Server is NOT running as root.");
    console.warn("   Active ARP scanning will fall back to passive mode.");
    console.warn("   For full functionality: sudo node server.js\n");
}

// 2. Load OUI vendor database
let ouiReady = false;
macLookup.load(() => {
    ouiReady = true;
    console.log("📂 OUI Vendor Database loaded successfully.");
});

app.use(cors());
app.use(express.json());

// ═══════════════════════════════════════════════════════════════════════════════
//  DEVICE CLASSIFICATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Classify a device type based on its vendor name.
 * Returns: "mobile" | "desktop" | "iot" | "network" | "unknown"
 */
function classifyDevice(vendorName) {
    if (!vendorName || vendorName === "Unknown Vendor") return "unknown";

    const v = vendorName.toLowerCase();

    // Mobile manufacturers
    const mobileKeywords = [
        "apple", "samsung", "huawei", "xiaomi", "oppo", "vivo", "oneplus",
        "realme", "motorola", "nokia", "sony mobile", "lg electronics",
        "google", "zte", "honor", "nothing"
    ];
    if (mobileKeywords.some(k => v.includes(k))) return "mobile";

    // Network equipment
    const networkKeywords = [
        "cisco", "ubiquiti", "netgear", "tp-link", "d-link", "asus",
        "linksys", "mikrotik", "aruba", "juniper", "fortinet", "meraki",
        "ruckus", "cambium", "sonicwall", "palo alto", "zyxel"
    ];
    if (networkKeywords.some(k => v.includes(k))) return "network";

    // IoT vendors
    const iotKeywords = [
        "espressif", "raspberry", "arduino", "tuya", "shelly", "sonoff",
        "philips", "ring", "nest", "wyze", "ecobee", "wemo", "hue",
        "tasmota", "broadlink", "yeelight", "meross", "switchbot",
        "amazon", "ezviz", "hikvision", "dahua", "axis"
    ];
    if (iotKeywords.some(k => v.includes(k))) return "iot";

    // Desktop / workstation vendors
    const desktopKeywords = [
        "dell", "hp", "hewlett", "lenovo", "intel", "amd", "microsoft",
        "vmware", "parallels", "qemu", "virtualbox", "acer"
    ];
    if (desktopKeywords.some(k => v.includes(k))) return "desktop";

    return "unknown";
}

// ═══════════════════════════════════════════════════════════════════════════════
//  VENDOR LOOKUP HELPER
// ═══════════════════════════════════════════════════════════════════════════════

function lookupVendor(mac) {
    return new Promise((resolve) => {
        if (!ouiReady) {
            resolve("Unknown Vendor");
            return;
        }
        try {
            macLookup.lookup(mac, (err, name) => {
                resolve(name || "Unknown Vendor");
            });
        } catch (e) {
            resolve("Unknown Vendor");
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT SANITIZATION
// ═══════════════════════════════════════════════════════════════════════════════

const IP_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

function validateIp(ip) {
    if (!ip || typeof ip !== 'string') return false;
    if (ip.length > 15) return false;  // Max IPv4 length
    return IP_REGEX.test(ip);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  API ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── 1. Discovery Scan ───────────────────────────────────────────────────────
app.get('/api/scan', (req, res) => {
    console.log("📡 Scan requested...");

    exec('python3 ../agent.py', { timeout: 30000 }, async (error, stdout, stderr) => {
        if (error) {
            console.error(`Exec error: ${error.message}`);
            return res.status(500).json({ error: "Scanner process failed", detail: error.message });
        }

        // stderr contains diagnostic messages — log them but don't fail
        if (stderr) {
            console.log(`Agent diagnostics: ${stderr.trim()}`);
        }

        try {
            const rawData = JSON.parse(stdout);
            const devices = rawData.devices || [];

            // Enrich each device with vendor name + device type
            const enrichedDevices = await Promise.all(devices.map(async (device) => {
                const vendor = await lookupVendor(device.mac);
                const deviceType = classifyDevice(vendor);
                return { ...device, vendor, deviceType };
            }));

            res.json({
                status: "success",
                scan_mode: rawData.scan_mode || "unknown",
                subnet: rawData.subnet || "unknown",
                count: enrichedDevices.length,
                is_root: isRoot,
                timestamp: new Date().toISOString(),
                devices: enrichedDevices
            });
        } catch (parseError) {
            console.error("JSON Parse Error:", parseError.message);
            console.error("Raw stdout:", stdout);
            res.status(500).json({ error: "Invalid scanner output" });
        }
    });
});

// ── 2. Deep Scan (Port Scanner) ─────────────────────────────────────────────
app.get('/api/inspect', (req, res) => {
    const ip = req.query.ip;

    if (!validateIp(ip)) {
        return res.status(400).json({ error: "Invalid IP address format" });
    }

    console.log(`🔎 Deep Scanning ${ip}...`);

    // SAFE: ip is validated against strict regex — no injection possible
    exec(`python3 ../agent.py ${ip}`, { timeout: 60000 }, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: "Deep scan failed", detail: error.message });
        }
        try {
            const data = JSON.parse(stdout);
            data.timestamp = new Date().toISOString();
            res.json(data);
        } catch (e) {
            res.status(500).json({ error: "Invalid scan output" });
        }
    });
});

// ── 3. Credential Audit ─────────────────────────────────────────────────────
app.get('/api/audit', (req, res) => {
    const ip = req.query.ip;

    if (!validateIp(ip)) {
        return res.status(400).json({ error: "Invalid IP address" });
    }

    console.log(`🔐 Auditing Credentials for ${ip}...`);

    exec(`python3 ../agent.py audit ${ip}`, { timeout: 30000 }, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: "Audit failed", detail: error.message });
        }
        try {
            res.json(JSON.parse(stdout));
        } catch (e) {
            res.status(500).json({ error: "Invalid audit output" });
        }
    });
});

// ── 4. Server Status ────────────────────────────────────────────────────────
app.get('/api/status', (req, res) => {
    res.json({
        server: "Sentinel Bridge v2.0",
        is_root: isRoot,
        oui_loaded: ouiReady,
        honeypot_port: HONEYPOT_PORT,
        uptime_seconds: Math.floor(process.uptime()),
        platform: os.platform(),
        hostname: os.hostname()
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  HONEYPOT TRAP (Fake Telnet on port 2323)
// ═══════════════════════════════════════════════════════════════════════════════

const honeypotLogs = [];

const honeypot = net.createServer((socket) => {
    const intruderIp = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const timestamp = new Date().toISOString();

    console.log(`🚨 HONEYPOT TRIGGERED by ${intruderIp} at ${timestamp}`);

    honeypotLogs.unshift({
        ip: intruderIp,
        time: timestamp,
        port: HONEYPOT_PORT
    });

    // Keep only last 100 entries
    if (honeypotLogs.length > 100) honeypotLogs.pop();

    socket.end();
});

honeypot.listen(HONEYPOT_PORT, () => {
    console.log(`🪤 Honeypot Active on Port ${HONEYPOT_PORT}`);
});

honeypot.on('error', (err) => {
    if (err.code === 'EACCES') {
        console.warn(`⚠️  Cannot bind honeypot to port ${HONEYPOT_PORT} — requires elevated privileges.`);
    } else {
        console.error("Honeypot error:", err.message);
    }
});

app.get('/api/honeypot', (req, res) => {
    res.json(honeypotLogs);
});

// ═══════════════════════════════════════════════════════════════════════════════
//  START SERVER
// ═══════════════════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
    console.log(`\n🚀 Sentinel Bridge v2.0 running on http://localhost:${PORT}`);
    console.log(`   Root: ${isRoot ? "✅ Yes" : "❌ No (passive mode)"}`);
    console.log(`   OUI DB: ${ouiReady ? "✅ Loaded" : "⏳ Loading..."}`);
    console.log(`   Honeypot: Port ${HONEYPOT_PORT}\n`);
});
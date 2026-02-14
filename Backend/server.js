/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Bridge v3.0 — Market-Ready Backend Server
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Features:
 *  ► Cross-platform network scanning via agent.py (no root needed)
 *  ► MAC vendor lookup & device type classification
 *  ► TCP Honeypot on Port 2323 — logs intruder connections
 *  ► Credential Audit endpoint
 *  ► Listens on 0.0.0.0 — accessible from physical phones on LAN
 *
 *  Run:   node server.js
 *  (sudo is optional — only needed for active ARP scanning via scapy)
 */

const express = require('express');
const cors = require('cors');
const net = require('net');
const { exec } = require('child_process');
const macLookup = require('mac-lookup');

const app = express();
const PORT = 3000;
const HONEYPOT_PORT = 2323;

app.use(cors());
app.use(express.json());

// ═══════════════════════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════════════════════

const IS_ROOT = process.getuid ? process.getuid() === 0 : false;
const honeypotLogs = [];  // { ip, timestamp, port }

// ═══════════════════════════════════════════════════════════════════════════════
//  STARTUP BANNER
// ═══════════════════════════════════════════════════════════════════════════════

console.log(`
╔══════════════════════════════════════════════════════╗
║       🛡️  SENTINEL BRIDGE v3.0 — MARKET READY       ║
╠══════════════════════════════════════════════════════╣
║  Root:      ${IS_ROOT ? '✅ Yes (active scan)' : '❌ No  (passive mode)'}              ║
║  Honeypot:  Port ${HONEYPOT_PORT}                              ║
║  Binding:   0.0.0.0:${PORT}                            ║
╚══════════════════════════════════════════════════════╝
`);

// ═══════════════════════════════════════════════════════════════════════════════
//  HONEYPOT TRAP — TCP Server on Port 2323
// ═══════════════════════════════════════════════════════════════════════════════

const honeypot = net.createServer((socket) => {
    const intruderIP = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const timestamp = new Date().toISOString();

    const logEntry = {
        ip: intruderIP,
        timestamp,
        port: HONEYPOT_PORT,
        message: `Unauthorized connection attempt from ${intruderIP}`
    };

    honeypotLogs.push(logEntry);
    console.log(`🪤 HONEYPOT TRIGGERED: ${intruderIP} at ${timestamp}`);

    // Send a fake banner to bait scanners
    socket.write('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n');
    setTimeout(() => socket.destroy(), 3000);
});

honeypot.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.log(`⚠️  Honeypot port ${HONEYPOT_PORT} already in use, skipping.`);
    } else {
        console.error(`❌ Honeypot error: ${err.message}`);
    }
});

honeypot.listen(HONEYPOT_PORT, '0.0.0.0', () => {
    console.log(`🪤 Honeypot listening on port ${HONEYPOT_PORT}`);
});

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Lookup MAC vendor with fallback
 */
function lookupVendor(mac) {
    return new Promise((resolve) => {
        try {
            const vendor = macLookup.lookup(mac);
            resolve(vendor || 'Unknown');
        } catch {
            resolve('Unknown');
        }
    });
}

/**
 * Classify device type based on vendor/hostname/ports
 */
function classifyDevice(vendor, hostname = '') {
    const v = (vendor + ' ' + hostname).toLowerCase();

    if (/apple|iphone|ipad|macbook|airpods/.test(v)) return 'Apple Device';
    if (/samsung|galaxy|android/.test(v)) return 'Android Device';
    if (/tp-link|netgear|asus|linksys|d-link|huawei|router|gateway/.test(v)) return 'Router/Gateway';
    if (/amazon|alexa|echo|ring/.test(v)) return 'Smart Home (Amazon)';
    if (/google|nest|chromecast|pixel/.test(v)) return 'Google Device';
    if (/intel|dell|lenovo|hp|microsoft|windows/.test(v)) return 'PC/Laptop';
    if (/espressif|tuya|shelly|smart|iot/.test(v)) return 'IoT Device';
    if (/camera|hikvision|dahua|rtsp|axis/.test(v)) return 'IP Camera';
    if (/printer|brother|canon|epson|xerox/.test(v)) return 'Printer';
    if (/raspberry|pi/.test(v)) return 'Raspberry Pi';
    if (/sonos|roku|fire|tv|media/.test(v)) return 'Media Device';

    return 'Unknown Device';
}

// ═══════════════════════════════════════════════════════════════════════════════
//  API: GET /api/scan — Network Discovery
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/scan', (req, res) => {
    console.log('📡 Scan requested...');

    exec('python3 ../agent.py', { timeout: 30000 }, async (error, stdout, stderr) => {
        if (stderr) console.log('Agent diagnostics:', stderr.trim());

        if (error) {
            console.error('❌ Agent error:', error.message);
            return res.json({
                status: 'error',
                message: error.message,
                devices: [],
                scan_mode: 'error'
            });
        }

        try {
            const data = JSON.parse(stdout);

            // Enrich each device with vendor + type
            const enrichedDevices = await Promise.all(
                (data.devices || []).map(async (device) => {
                    const vendor = await lookupVendor(device.mac);
                    return {
                        ...device,
                        vendor,
                        type: classifyDevice(vendor),
                        risk: 'LOW'
                    };
                })
            );

            res.json({
                status: 'success',
                scan_mode: data.scan_mode || 'passive',
                subnet: data.subnet || 'unknown',
                count: enrichedDevices.length,
                is_root: IS_ROOT,
                devices: enrichedDevices
            });
        } catch (parseError) {
            console.error('❌ JSON parse error:', parseError.message);
            console.error('Raw output:', stdout);
            res.json({
                status: 'error',
                message: 'Failed to parse agent output',
                devices: [],
                raw: stdout.substring(0, 500)
            });
        }
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  API: GET /api/inspect?ip=X.X.X.X — Deep Scan
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/inspect', (req, res) => {
    const ip = req.query.ip;
    if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        return res.status(400).json({ error: 'Valid IP address required (?ip=X.X.X.X)' });
    }

    console.log(`🔍 Deep scan: ${ip}`);

    exec(`python3 ../agent.py ${ip}`, { timeout: 60000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent diagnostics:', stderr.trim());

        if (error) {
            return res.json({ error: error.message });
        }

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.json({ error: 'Failed to parse deep scan output', raw: stdout.substring(0, 500) });
        }
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  API: GET /api/audit?ip=X.X.X.X — Credential Audit
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/audit', (req, res) => {
    const ip = req.query.ip;
    if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        return res.status(400).json({ error: 'Valid IP address required (?ip=X.X.X.X)' });
    }

    console.log(`🔐 Credential audit: ${ip}`);

    exec(`python3 ../agent.py audit ${ip}`, { timeout: 30000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent diagnostics:', stderr.trim());

        if (error) {
            return res.json({ error: error.message });
        }

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.json({ error: 'Failed to parse audit output', raw: stdout.substring(0, 500) });
        }
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  API: GET /api/honeypot — Retrieve Honeypot Logs
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/honeypot', (req, res) => {
    res.json(honeypotLogs);
});

// ═══════════════════════════════════════════════════════════════════════════════
//  API: GET /api/status — Server Health Check
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/status', (req, res) => {
    let ouiLoaded = false;
    try {
        const testResult = macLookup.lookup('00:00:00');
        ouiLoaded = true;
    } catch {
        ouiLoaded = false;
    }

    res.json({
        server: 'Sentinel Bridge v3.0',
        is_root: IS_ROOT,
        oui_loaded: ouiLoaded,
        honeypot_port: HONEYPOT_PORT,
        honeypot_triggers: honeypotLogs.length,
        uptime_seconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString()
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  START SERVER — Listen on 0.0.0.0 for physical device access
// ═══════════════════════════════════════════════════════════════════════════════

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Server listening on http://0.0.0.0:${PORT}`);
    console.log(`   → Physical phone access: http://192.168.1.103:${PORT}`);
    console.log(`   → Emulator access:       http://10.0.2.2:${PORT}`);
    console.log(`   → Local access:          http://localhost:${PORT}\n`);
});
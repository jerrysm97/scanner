/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Bridge v4.0 — Enterprise-Grade Backend with Supabase
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Features:
 *  ► Supabase Integration — devices upserted by MAC (conflict target)
 *  ► Cross-platform agent.py (no root needed)
 *  ► TCP Honeypot on Port 2323
 *  ► Credential Audit endpoint
 *  ► Listens on 0.0.0.0 for physical phone access via LAN
 *  ► MAC vendor lookup & device type classification
 *
 *  Run:   node server.js
 */

const express = require('express');
const cors = require('cors');
const net = require('net');
const { exec } = require('child_process');
const macLookup = require('mac-lookup');
const { createClient } = require('@supabase/supabase-js');

// ═══════════════════════════════════════════════════════════════════════════════
//  CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const PORT = 3000;
const HONEYPOT_PORT = 2323;

// ── Supabase Credentials ─────────────────────────────────────────────────────
// Replace YOUR_SUPABASE_URL with your project URL from:
//   Supabase Dashboard → Settings → API → Project URL
const SUPABASE_URL = 'YOUR_SUPABASE_URL';
const SUPABASE_KEY = 'sb_publishable_Zj5IMTRJQJQIaImdBHiQUQ_fLSm792l';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ═══════════════════════════════════════════════════════════════════════════════
//  EXPRESS APP
// ═══════════════════════════════════════════════════════════════════════════════

const app = express();
app.use(cors());
app.use(express.json());

// ═══════════════════════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════════════════════

const IS_ROOT = process.getuid ? process.getuid() === 0 : false;
const honeypotLogs = [];
let totalDevicesLogged = 0;  // Track total unique devices seen across all scans

// ═══════════════════════════════════════════════════════════════════════════════
//  STARTUP BANNER
// ═══════════════════════════════════════════════════════════════════════════════

console.log(`
╔══════════════════════════════════════════════════════════╗
║        🛡️  SENTINEL BRIDGE v4.0 — ENTERPRISE EDITION     ║
╠══════════════════════════════════════════════════════════╣
║  Supabase:   ${SUPABASE_URL === 'YOUR_SUPABASE_URL' ? '⚠️  NOT CONFIGURED' : '✅ Connected'}                          ║
║  Root:       ${IS_ROOT ? '✅ Yes (active scan)' : '❌ No  (passive mode)'}                         ║
║  Honeypot:   Port ${HONEYPOT_PORT}                                     ║
║  Binding:    0.0.0.0:${PORT}                                   ║
╚══════════════════════════════════════════════════════════╝
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
        message: `Unauthorized connection from ${intruderIP}`,
    };

    honeypotLogs.push(logEntry);
    console.log(`🪤 HONEYPOT TRIGGERED: ${intruderIP} at ${timestamp}`);

    // Fake SSH banner to bait port scanners
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
    console.log(`🪤 Honeypot active on port ${HONEYPOT_PORT}`);
});

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

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

/**
 * Save devices to Supabase using UPSERT with MAC as conflict target.
 * This updates the 'last_seen' column every time a device is re-discovered.
 *
 * Required Supabase table schema:
 *   CREATE TABLE devices (
 *     mac TEXT PRIMARY KEY,
 *     ip TEXT,
 *     vendor TEXT,
 *     type TEXT,
 *     status TEXT DEFAULT 'online',
 *     risk TEXT DEFAULT 'LOW',
 *     last_seen TIMESTAMPTZ DEFAULT now()
 *   );
 */
async function saveToSupabase(devices) {
    if (SUPABASE_URL === 'YOUR_SUPABASE_URL') {
        console.log('⚠️  Supabase not configured — skipping database save.');
        return { saved: 0, error: null };
    }

    try {
        const rows = devices.map(d => ({
            mac: d.mac,
            ip: d.ip,
            vendor: d.vendor || 'Unknown',
            type: d.type || 'Unknown Device',
            status: 'online',
            risk: d.risk || 'LOW',
            last_seen: new Date().toISOString(),
        }));

        const { data, error } = await supabase
            .from('devices')
            .upsert(rows, { onConflict: 'mac' });

        if (error) {
            console.error('❌ Supabase upsert error:', error.message);
            return { saved: 0, error: error.message };
        }

        console.log(`💾 Saved ${rows.length} device(s) to Supabase.`);
        return { saved: rows.length, error: null };
    } catch (err) {
        console.error('❌ Supabase connection error:', err.message);
        return { saved: 0, error: err.message };
    }
}

/**
 * Get total device count from Supabase.
 */
async function getDeviceCount() {
    if (SUPABASE_URL === 'YOUR_SUPABASE_URL') {
        return totalDevicesLogged;
    }

    try {
        const { count, error } = await supabase
            .from('devices')
            .select('*', { count: 'exact', head: true });

        if (error) {
            console.error('❌ Supabase count error:', error.message);
            return totalDevicesLogged;
        }

        return count || 0;
    } catch {
        return totalDevicesLogged;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  API: GET /api/scan — Network Discovery + Supabase Upsert
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/scan', (req, res) => {
    console.log('📡 Scan requested...');

    exec('python3 ../agent.py', { timeout: 30000 }, async (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());

        if (error) {
            console.error('❌ Agent error:', error.message);
            return res.json({
                status: 'error',
                message: error.message,
                devices: [],
                scan_mode: 'error',
            });
        }

        try {
            const data = JSON.parse(stdout);

            // Enrich with vendor + device type
            const enrichedDevices = await Promise.all(
                (data.devices || []).map(async (device) => {
                    const vendor = await lookupVendor(device.mac);
                    return {
                        ...device,
                        vendor,
                        type: classifyDevice(vendor),
                        risk: 'LOW',
                    };
                })
            );

            // Save to Supabase (upsert by MAC)
            const dbResult = await saveToSupabase(enrichedDevices);

            // Track total locally
            const seenMacs = new Set(enrichedDevices.map(d => d.mac));
            totalDevicesLogged = Math.max(totalDevicesLogged, seenMacs.size);

            // Get total from DB
            const totalInDB = await getDeviceCount();

            res.json({
                status: 'success',
                scan_mode: data.scan_mode || 'passive',
                subnet: data.subnet || 'unknown',
                count: enrichedDevices.length,
                is_root: IS_ROOT,
                devices: enrichedDevices,
                database: {
                    saved: dbResult.saved,
                    total_logged: totalInDB,
                    error: dbResult.error,
                },
            });
        } catch (parseError) {
            console.error('❌ JSON parse error:', parseError.message);
            res.json({
                status: 'error',
                message: 'Failed to parse agent output',
                devices: [],
                raw: stdout.substring(0, 500),
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
        return res.status(400).json({ error: 'Valid IP required (?ip=X.X.X.X)' });
    }

    console.log(`🔍 Deep scan: ${ip}`);

    exec(`python3 ../agent.py ${ip}`, { timeout: 60000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());
        if (error) return res.json({ error: error.message });

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.json({ error: 'Parse failed', raw: stdout.substring(0, 500) });
        }
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  API: GET /api/audit?ip=X.X.X.X — Credential Audit
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/audit', (req, res) => {
    const ip = req.query.ip;
    if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
        return res.status(400).json({ error: 'Valid IP required (?ip=X.X.X.X)' });
    }

    console.log(`🔐 Credential audit: ${ip}`);

    exec(`python3 ../agent.py audit ${ip}`, { timeout: 30000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());
        if (error) return res.json({ error: error.message });

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.json({ error: 'Parse failed', raw: stdout.substring(0, 500) });
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
//  API: GET /api/status — Server Health + Database Stats
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/status', async (req, res) => {
    const totalInDB = await getDeviceCount();

    let ouiLoaded = false;
    try {
        macLookup.lookup('00:00:00');
        ouiLoaded = true;
    } catch {
        ouiLoaded = false;
    }

    res.json({
        server: 'Sentinel Bridge v4.0 Enterprise',
        is_root: IS_ROOT,
        oui_loaded: ouiLoaded,
        honeypot_port: HONEYPOT_PORT,
        honeypot_triggers: honeypotLogs.length,
        supabase_connected: SUPABASE_URL !== 'YOUR_SUPABASE_URL',
        total_devices_logged: totalInDB,
        uptime_seconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString(),
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  START SERVER — Listen on 0.0.0.0
// ═══════════════════════════════════════════════════════════════════════════════

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Server listening on http://0.0.0.0:${PORT}`);
    console.log(`   → Physical phone: http://192.168.1.103:${PORT}`);
    console.log(`   → Emulator:       http://10.0.2.2:${PORT}`);
    console.log(`   → Local:          http://localhost:${PORT}\n`);
});
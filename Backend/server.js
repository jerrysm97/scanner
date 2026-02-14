/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Bridge v5.0 — Production-Ready Enterprise Backend
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Security:
 *  ► helmet()          — Sets secure HTTP headers (XSS, HSTS, etc.)
 *  ► express-rate-limit — 100 req/15min per IP (prevents API abuse)
 *  ► Input validation   — Strict regex IP check (prevents command injection)
 *  ► dotenv             — Secrets in .env, NOT in source code
 *
 *  Logging:
 *  ► morgan ('combined') — Full request log with timestamps
 *
 *  Database:
 *  ► Supabase upsert    — MAC as conflict target → updates last_seen
 *
 *  Run:   node server.js
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const net = require('net');
const dns = require('dns');
const { exec } = require('child_process');
const macLookup = require('mac-lookup');
const { createClient } = require('@supabase/supabase-js');

// ═══════════════════════════════════════════════════════════════════════════════
//  CONFIGURATION (from .env)
// ═══════════════════════════════════════════════════════════════════════════════

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HONEYPOT_PORT = parseInt(process.env.HONEYPOT_PORT, 10) || 2323;
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';

// ── Supabase Client ──────────────────────────────────────────────────────────
// Edge case: If URL/KEY missing, supabase calls fail gracefully (caught below).
const supabase = (SUPABASE_URL && SUPABASE_KEY)
    ? createClient(SUPABASE_URL, SUPABASE_KEY)
    : null;

// ═══════════════════════════════════════════════════════════════════════════════
//  EXPRESS APP + SECURITY MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════════

const app = express();

// Security headers (XSS protection, HSTS, content-type sniffing prevention)
app.use(helmet());

// CORS — allow all origins for mobile app access
app.use(cors());

// Body parsing
app.use(express.json());

// Request logging with timestamps
app.use(morgan(':date[iso] :method :url :status :response-time ms'));

// Rate limiting — 100 requests per 15 minutes per IP
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait 15 minutes.' },
});
app.use('/api/', apiLimiter);

// ═══════════════════════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════════════════════

const IS_ROOT = process.getuid ? process.getuid() === 0 : false;
const honeypotLogs = [];
let totalDevicesLogged = 0;

// ═══════════════════════════════════════════════════════════════════════════════
//  STARTUP BANNER
// ═══════════════════════════════════════════════════════════════════════════════

console.log(`
╔═══════════════════════════════════════════════════════════╗
║         🛡️  SENTINEL BRIDGE v5.0 — ENTERPRISE            ║
╠═══════════════════════════════════════════════════════════╣
║  Supabase:    ${supabase ? '✅ Connected' : '⚠️  NOT CONFIGURED'}                            ║
║  Helmet:      ✅ Security headers active                  ║
║  Rate Limit:  ✅ 100 req / 15 min                         ║
║  Logging:     ✅ Morgan (combined)                        ║
║  Root:        ${IS_ROOT ? '✅ Yes' : '❌ No '}                                       ║
║  Honeypot:    Port ${HONEYPOT_PORT}                                    ║
║  Binding:     0.0.0.0:${PORT}                                  ║
╚═══════════════════════════════════════════════════════════╝
`);

// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT VALIDATION — Prevents Command Injection
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Validate that a string is a valid IPv4 address.
 * SECURITY: This is the ONLY gate before the IP reaches exec().
 * Rejects anything that isn't exactly n.n.n.n with each octet 0-255.
 *
 * Edge cases:
 *   - Missing parameter     → returns false
 *   - Contains shell chars   → returns false (;, |, &, etc.)
 *   - Octet > 255            → returns false
 *   - Leading zeros          → allowed (some network tools use them)
 */
function isValidIPv4(ip) {
    if (!ip || typeof ip !== 'string') return false;

    // Strict pattern: only digits and dots
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return false;

    // Validate each octet is 0-255
    const octets = ip.split('.');
    return octets.every(o => {
        const num = parseInt(o, 10);
        return num >= 0 && num <= 255;
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HONEYPOT TRAP — TCP Server on Port 2323
// ═══════════════════════════════════════════════════════════════════════════════

const honeypot = net.createServer((socket) => {
    const intruderIP = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const timestamp = new Date().toISOString();

    honeypotLogs.push({
        ip: intruderIP,
        timestamp,
        port: HONEYPOT_PORT,
        message: `Unauthorized connection from ${intruderIP}`,
    });

    console.log(`🪤 HONEYPOT: ${intruderIP} at ${timestamp}`);

    // Fake SSH banner
    socket.write('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n');
    setTimeout(() => socket.destroy(), 3000);
});

honeypot.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.log(`⚠️  Honeypot port ${HONEYPOT_PORT} in use, skipping.`);
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

/**
 * Lookup MAC vendor with fallback.
 * Edge case: mac-lookup might throw on malformed MACs → caught.
 */
function lookupVendor(mac) {
    return new Promise((resolve) => {
        try {
            resolve(macLookup.lookup(mac) || 'Unknown');
        } catch {
            resolve('Unknown');
        }
    });
}

/**
 * Classify device type based on vendor string.
 * Edge case: null/undefined vendor → defaults to 'Unknown Device'.
 */
function classifyDevice(vendor) {
    const v = (vendor || '').toLowerCase();

    if (/apple|iphone|ipad|macbook|airpods/.test(v)) return 'Apple Device';
    if (/samsung|galaxy|android/.test(v)) return 'Android Device';
    if (/tp-link|netgear|asus|linksys|d-link|router|gateway/.test(v)) return 'Router/Gateway';
    if (/amazon|alexa|echo|ring/.test(v)) return 'Smart Home';
    if (/google|nest|chromecast|pixel/.test(v)) return 'Google Device';
    if (/intel|dell|lenovo|hp|microsoft/.test(v)) return 'PC/Laptop';
    if (/espressif|tuya|shelly|iot/.test(v)) return 'IoT Device';
    if (/camera|hikvision|dahua|axis/.test(v)) return 'IP Camera';
    if (/printer|brother|canon|epson/.test(v)) return 'Printer';
    if (/raspberry|pi/.test(v)) return 'Raspberry Pi';
    if (/sonos|roku|fire|tv|media/.test(v)) return 'Media Device';

    return 'Unknown Device';
}

/**
 * Check if an IP is multicast (224-239.x.x.x) or broadcast.
 * These are protocol-level addresses, not real devices.
 */
function isMulticast(ip) {
    if (!ip || typeof ip !== 'string') return true;
    const parts = ip.split('.');
    if (parts.length !== 4) return true;
    const firstOctet = parseInt(parts[0], 10);
    if (firstOctet >= 224 && firstOctet <= 239) return true;
    if (ip === '255.255.255.255') return true;
    return false;
}

/**
 * Resolve hostname for a local device using multiple strategies:
 * 1. dns-sd (macOS mDNS/Bonjour) — resolves names like "Jerry's-iPhone"
 * 2. dns.reverse() — standard reverse DNS
 * 3. Fallback to "Unknown"
 *
 * dns-sd is run with a 3-second timeout.
 */
function resolveHostname(ip) {
    return new Promise((resolve) => {
        // Strategy 1: Use arp -a to see if hostname was broadcast
        exec(`arp -a | grep '(${ip})'`, { timeout: 3000 }, (err1, stdout1) => {
            if (!err1 && stdout1) {
                // macOS format: "hostname.local (192.168.1.x) at ..."
                const match = stdout1.match(/^([\w.-]+)\s+\(/);
                if (match && match[1] !== '?') {
                    return resolve(match[1].replace('.local', ''));
                }
            }

            // Strategy 2: Standard reverse DNS
            dns.promises.reverse(ip)
                .then(names => {
                    if (names && names.length > 0 && names[0] !== ip) {
                        resolve(names[0]);
                    } else {
                        resolve('Unknown');
                    }
                })
                .catch(() => resolve('Unknown'));
        });
    });
}

/**
 * Supabase upsert — saves devices with MAC as conflict target.
 * Updates 'last_seen' column every time a device is re-discovered.
 *
 * Required table schema:
 *   CREATE TABLE devices (
 *     mac TEXT PRIMARY KEY,
 *     ip TEXT,
 *     vendor TEXT,
 *     type TEXT,
 *     status TEXT DEFAULT 'online',
 *     risk TEXT DEFAULT 'LOW',
 *     last_seen TIMESTAMPTZ DEFAULT now()
 *   );
 *
 * Edge cases:
 *   - Supabase not configured → returns gracefully with saved: 0
 *   - Network error           → logs error, returns saved: 0
 *   - Duplicate MACs in batch → handled by upsert (updates in place)
 */
async function saveToSupabase(deviceList) {
    if (!supabase) {
        console.log('⚠️  Supabase not configured — skipping save.');
        return { saved: 0, error: null };
    }

    try {
        const rows = deviceList.map(d => ({
            mac: d.mac,
            ip: d.ip,
            vendor: d.vendor || 'Unknown',
            type: d.type || 'Unknown Device',
            hostname: d.hostname || 'Unknown',
            status: 'online',
            last_seen: new Date().toISOString(),
        }));

        const { error } = await supabase
            .from('devices')
            .upsert(rows, { onConflict: 'mac' });

        if (error) {
            console.error('❌ Supabase upsert error:', error.message);
            return { saved: 0, error: error.message };
        }

        console.log(`💾 Upserted ${rows.length} device(s) to Supabase.`);
        return { saved: rows.length, error: null };
    } catch (err) {
        console.error('❌ Supabase connection error:', err.message);
        return { saved: 0, error: err.message };
    }
}

/**
 * Get total device count from Supabase.
 * Edge case: Supabase offline → returns local counter.
 */
async function getDeviceCount() {
    if (!supabase) return totalDevicesLogged;

    try {
        const { count, error } = await supabase
            .from('devices')
            .select('*', { count: 'exact', head: true });

        if (error) return totalDevicesLogged;
        return count || 0;
    } catch {
        return totalDevicesLogged;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ── Health Check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

// ── Network Scan ──────────────────────────────────────────────────────────────
app.get('/api/scan', (req, res) => {
    console.log('📡 Scan requested...');

    exec('python3 ../agent.py', { timeout: 30000 }, async (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());

        if (error) {
            console.error('❌ Agent error:', error.message);
            return res.status(500).json({
                status: 'error',
                message: error.message,
                devices: [],
            });
        }

        try {
            const scanData = JSON.parse(stdout);

            const enrichedDevices = await Promise.all(
                (scanData.devices || []).map(async (device) => {
                    // Skip multicast/broadcast IPs
                    if (isMulticast(device.ip)) return null;

                    const vendor = await lookupVendor(device.mac);
                    const hostname = await resolveHostname(device.ip);
                    return { ...device, vendor, type: classifyDevice(vendor), hostname };
                })
            );

            // Remove null entries (filtered multicast)
            const filteredDevices = enrichedDevices.filter(d => d !== null);

            // Supabase upsert
            const dbResult = await saveToSupabase(filteredDevices);
            totalDevicesLogged = Math.max(totalDevicesLogged, filteredDevices.length);
            const dbDeviceCount = await getDeviceCount();

            res.json({
                status: 'success',
                scan_mode: scanData.scan_mode || 'passive',
                subnet: scanData.subnet || 'unknown',
                count: filteredDevices.length,
                devices: filteredDevices,
                database: {
                    saved: dbResult.saved,
                    total_logged: dbDeviceCount,
                    error: dbResult.error,
                },
            });
        } catch (parseError) {
            console.error('❌ Parse error:', parseError.message);
            res.status(500).json({
                status: 'error',
                message: 'Failed to parse agent output',
                devices: [],
            });
        }
    });
});

// ── Deep Scan ─────────────────────────────────────────────────────────────────
app.get('/api/inspect', (req, res) => {
    const targetIP = req.query.ip;

    // SECURITY: Strict IP validation before exec()
    if (!isValidIPv4(targetIP)) {
        return res.status(400).json({ error: 'Invalid IP address format.' });
    }

    console.log(`🔍 Deep scan: ${targetIP}`);

    exec(`python3 ../agent.py ${targetIP}`, { timeout: 60000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());
        if (error) return res.status(500).json({ error: error.message });

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.status(500).json({ error: 'Failed to parse deep scan output' });
        }
    });
});

// ── Credential Audit ──────────────────────────────────────────────────────────
app.get('/api/audit', (req, res) => {
    const targetIP = req.query.ip;

    // SECURITY: Strict IP validation before exec()
    if (!isValidIPv4(targetIP)) {
        return res.status(400).json({ error: 'Invalid IP address format.' });
    }

    console.log(`🔐 Credential audit: ${targetIP}`);

    exec(`python3 ../agent.py audit ${targetIP}`, { timeout: 30000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());
        if (error) return res.status(500).json({ error: error.message });

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.status(500).json({ error: 'Failed to parse audit output' });
        }
    });
});

// ── Honeypot Logs ─────────────────────────────────────────────────────────────
app.get('/api/honeypot', (req, res) => {
    res.json(honeypotLogs);
});

// ── Device History (from Supabase) ────────────────────────────────────────
app.get('/api/device-history', async (req, res) => {
    const mac = req.query.mac;
    if (!mac || typeof mac !== 'string') {
        return res.status(400).json({ error: 'Missing mac parameter' });
    }

    if (!supabase) {
        return res.json({ mac, history: [], message: 'Supabase not configured' });
    }

    try {
        const { data, error } = await supabase
            .from('devices')
            .select('*')
            .eq('mac', mac)
            .order('last_seen', { ascending: false })
            .limit(20);

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        res.json({ mac, history: data || [] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── Traffic Statistics ────────────────────────────────────────────────────────
app.get('/api/traffic', (req, res) => {
    // Use nettop on macOS or /proc/net/dev on Linux for traffic stats
    const platform = process.platform;

    if (platform === 'darwin') {
        // macOS: use netstat -ib for interface stats
        exec('netstat -ib', { timeout: 5000 }, (error, stdout) => {
            if (error) {
                return res.json({ error: 'Failed to get traffic stats', upload_bytes: 0, download_bytes: 0, connections: 0 });
            }

            let totalIn = 0;
            let totalOut = 0;
            const lines = stdout.split('\n');
            for (const line of lines) {
                // Skip header and loopback
                if (line.includes('Name') || line.includes('lo0') || !line.trim()) continue;
                const parts = line.trim().split(/\s+/);
                // Format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                if (parts.length >= 10) {
                    const ibytes = parseInt(parts[6], 10);
                    const obytes = parseInt(parts[9], 10);
                    if (!isNaN(ibytes)) totalIn += ibytes;
                    if (!isNaN(obytes)) totalOut += obytes;
                }
            }

            // Get active connection count
            exec('netstat -an | grep ESTABLISHED | wc -l', { timeout: 3000 }, (err2, stdout2) => {
                const connections = parseInt((stdout2 || '0').trim(), 10) || 0;
                res.json({
                    upload_bytes: totalOut,
                    download_bytes: totalIn,
                    connections,
                    upload_mb: (totalOut / (1024 * 1024)).toFixed(1),
                    download_mb: (totalIn / (1024 * 1024)).toFixed(1),
                    timestamp: new Date().toISOString(),
                });
            });
        });
    } else {
        // Linux: read /proc/net/dev
        exec('cat /proc/net/dev', { timeout: 3000 }, (error, stdout) => {
            if (error) {
                return res.json({ error: 'Failed to get traffic stats', upload_bytes: 0, download_bytes: 0, connections: 0 });
            }

            let totalIn = 0;
            let totalOut = 0;
            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.includes('|') || line.includes('lo:') || !line.includes(':')) continue;
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 10) {
                    const rxBytes = parseInt(parts[1], 10);
                    const txBytes = parseInt(parts[9], 10);
                    if (!isNaN(rxBytes)) totalIn += rxBytes;
                    if (!isNaN(txBytes)) totalOut += txBytes;
                }
            }

            exec('netstat -an | grep ESTABLISHED | wc -l', { timeout: 3000 }, (err2, stdout2) => {
                const connections = parseInt((stdout2 || '0').trim(), 10) || 0;
                res.json({
                    upload_bytes: totalOut,
                    download_bytes: totalIn,
                    connections,
                    upload_mb: (totalOut / (1024 * 1024)).toFixed(1),
                    download_mb: (totalIn / (1024 * 1024)).toFixed(1),
                    timestamp: new Date().toISOString(),
                });
            });
        });
    }
});

// ── Server Status ─────────────────────────────────────────────────────────────
app.get('/api/status', async (req, res) => {
    const dbDeviceCount = await getDeviceCount();

    res.json({
        server: 'Sentinel Bridge v5.0 Enterprise',
        is_root: IS_ROOT,
        supabase_connected: !!supabase,
        total_devices_logged: dbDeviceCount,
        honeypot_port: HONEYPOT_PORT,
        honeypot_triggers: honeypotLogs.length,
        uptime_seconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString(),
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  START — 0.0.0.0 for physical device access
// ═══════════════════════════════════════════════════════════════════════════════

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🚀 Server on http://0.0.0.0:${PORT}`);
    console.log(`   → Phone:    http://192.168.1.103:${PORT}`);
    console.log(`   → Emulator: http://10.0.2.2:${PORT}`);
    console.log(`   → Local:    http://localhost:${PORT}\n`);
});
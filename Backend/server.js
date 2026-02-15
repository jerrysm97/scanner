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
const fs = require('fs'); // Added fs
const path = require('path');
const net = require('net');
const dns = require('dns');
const { exec, spawn } = require('child_process');
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

// Security headers — configured to allow web frontend assets
// Security headers — configured to allow web frontend assets
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
            imgSrc: ["'self'", "data:", "blob:"], // Added blob:
            connectSrc: ["'self'"],
        }
    }
}));

// CORS — allow all origins for mobile app access
app.use(cors());

// Body parsing
app.use(express.json());

// Serve web frontend
app.use(express.static(path.join(__dirname, 'public')));
// Serve captured images directory
app.use('/captured_images', express.static(path.join(__dirname, '..', 'captured_images')));

// Request logging with timestamps
app.use(morgan(':date[iso] :method :url :status :response-time ms'));

// Rate limiting — 1000 requests per 15 minutes per IP (generous for local tool)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait a moment.' },
});
app.use('/api/', apiLimiter);

// ═══════════════════════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════════════════════

const IS_ROOT = process.getuid ? process.getuid() === 0 : false;
const honeypotLogs = [];
let totalDevicesLogged = 0;
let savedTargets = {};

// Load saved targets
const targetsFile = path.join(__dirname, 'targets.json');
if (fs.existsSync(targetsFile)) {
    try {
        savedTargets = JSON.parse(fs.readFileSync(targetsFile, 'utf8'));
    } catch (e) {
        console.error('Failed to load targets.json:', e);
    }
}

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

const LOCAL_OUI_DB = {
    '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0a:27': 'Apple', '00:0a:95': 'Apple', '00:0d:93': 'Apple',
    '34:af:2c': 'Apple', '44:4a:db': 'Apple', 'd0:03:4b': 'Apple', 'f0:d1:a9': 'Apple', 'fc:25:3f': 'Apple',
    '00:00:f0': 'Samsung', '00:07:ab': 'Samsung', '00:0d:ae': 'Samsung', '00:12:47': 'Samsung', 'a4:70:d6': 'Samsung',
    '8c:c7:01': 'Samsung', '60:af:6d': 'Samsung', '08:ee:8b': 'Samsung', '1c:5a:3e': 'Samsung',
    '00:1a:11': 'Google', '20:df:b9': 'Google', '3c:5a:b4': 'Google', '94:eb:cd': 'Google', 'da:a1:19': 'Google',
    '00:24:e4': 'Withings', '00:1d:c9': 'Nest', '18:b4:30': 'Nest',
    '00:1c:2b': 'Dell', '00:1d:09': 'Dell', '00:21:70': 'Dell',
    '00:1c:c0': 'HP', '00:1d:0f': 'HP', '00:21:5a': 'HP',
    '04:33:89': 'Huawei', '08:19:a6': 'Huawei',
    '00:19:70': 'ZTE', '00:1a:c4': 'ZTE',
    '00:22:6b': 'Linksys', '00:23:69': 'Linksys',
    '00:18:4d': 'Netgear', '00:1b:2f': 'Netgear', 'c0:3f:0e': 'Netgear',
    '00:1d:7e': 'TP-Link', '00:1e:a6': 'TP-Link', 'b0:4e:26': 'TP-Link', 'f8:1a:67': 'TP-Link',
    '00:26:bb': 'Sony', '00:24:33': 'Sony', '00:1d:ba': 'Sony',
    '00:1f:3b': 'Intel', '00:21:5d': 'Intel',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
    '00:1e:c0': 'Micro-Star (MSI)', '00:24:21': 'Micro-Star (MSI)',
    '24:da:33': 'Tesla', '44:fb:42': 'Tesla',
    '40:9f:38': 'Ring', 'c4:7c:8d': 'Ring', 'f0:d8:19': 'Ring',
    '2c:f7:f1': 'Espressif (IoT)', '30:ae:a4': 'Espressif (IoT)', 'bc:dd:c2': 'Espressif (IoT)'
};

/**
 * Lookup MAC vendor with local cache + library fallback.
 */
function lookupVendor(mac) {
    return new Promise((resolve) => {
        if (!mac) return resolve('Unknown');

        const prefix = mac.substring(0, 8).toLowerCase();
        if (LOCAL_OUI_DB[prefix]) return resolve(LOCAL_OUI_DB[prefix]);

        try {
            const vendor = macLookup.lookup(mac);
            resolve(vendor || 'Unknown');
        } catch {
            resolve('Unknown');
        }
    });
}

/**
 * Classify device type based on vendor string.
 * Edge case: null/undefined vendor → defaults to 'Unknown Device'.
 */
function classifyDevice(vendor, mac) {
    const v = (vendor || 'Unknown').toLowerCase();

    // Check for Locally Administered Address (Randomized/Private MAC)
    // The second-least significant bit of the first octet is 1.
    // e.g. x2, x6, xA, xE in first octet.
    if (mac) {
        const firstOctet = parseInt(mac.split(':')[0], 16);
        if ((firstOctet & 0x02) === 0x02) return 'Privacy-Randomized MAC';
    }

    // Apple Ecosystem
    if (/apple|iphone|ipad|macbook|airpods|imac|watch|beats/.test(v)) return 'Apple Device';

    // Mobile & Tablets
    if (/samsung|galaxy|android|xiaomi|redmi|oppo|vivo|huawei|honor|realme|motorola|nokia|hmd|oneplus/.test(v)) return 'Mobile Device';
    if (/google|pixel|nest|chromecast/.test(v)) return 'Google Device';

    // Computers & Laptops
    if (/intel|dell|lenovo|hp|hewlett-packard|asustek|asus|microsoft|acer|msi|gigabyte|fujitsu|toshiba|sony/.test(v)) return 'PC/Laptop';

    // Networking
    if (/tp-link|netgear|asus|linksys|d-link|router|gateway|ubiquiti|cisco|meraki|mikrotik|zyxel|tenda|huawei|zte|aruba|juniper|synology/.test(v)) return 'Networking Gear';

    // IoT & Smart Home
    if (/amazon|alexa|echo|ring|blink|eero/.test(v)) return 'Amazon Smart Home';
    if (/espressif|tuya|shelly|sonoff|itead|aqara|xiaomi|yeelight|philips|hue|ikea|tradfri/.test(v)) return 'IoT Device';
    if (/tp-link.*smart|kasa|lifx|wemo|tplink|meross/.test(v)) return 'IoT Device';

    // Security / Cameras
    if (/camera|hikvision|dahua|axis|reolink|wyze|arlo|amcrest|ezviz|hanwha|uniview/.test(v)) return 'IP Camera';

    // Entertainment
    if (/sonos|roku|fire|tv|media|nvidia|shield|lg|vizio|panasonic|tcl|hisense|denon|marantz|yamaha|bose/.test(v)) return 'Media Device';
    if (/nintendo|playstation|xbox|sony/.test(v)) return 'Gaming Console';

    // Printers & Peripherals
    if (/printer|brother|canon|epson|xerox|kyocera|lexmark|ricoh|konica/.test(v)) return 'Printer';
    if (/raspberry|pi|arduino|stmicroelectronics|texas instruments|atmel/.test(v)) return 'Dev Board';

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

    const agentPath = path.join(__dirname, '../agent.py');

    exec(`python3 "${agentPath}"`, { timeout: 120000 }, async (error, stdout, stderr) => {
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
                    const customName = savedTargets[device.mac] || null;
                    return { ...device, vendor, type: classifyDevice(vendor, device.mac), hostname, name: customName };
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

    const agentPath = path.join(__dirname, '../agent.py');
    exec(`python3 "${agentPath}" ${targetIP}`, { timeout: 60000 }, (error, stdout, stderr) => {
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

    const agentPath = path.join(__dirname, '../agent.py');
    exec(`python3 "${agentPath}" audit ${targetIP}`, { timeout: 30000 }, (error, stdout, stderr) => {
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

// ── Rename Device (Persistence) ───────────────────────────────────────────────
app.post('/api/device/rename', (req, res) => {
    const { mac, name } = req.body;
    if (!mac || !name) return res.status(400).json({ error: 'MAC and Name required' });

    savedTargets[mac] = name;

    try {
        fs.writeFileSync(targetsFile, JSON.stringify(savedTargets, null, 2));
        res.json({ status: 'success', mac, name });
    } catch (e) {
        res.status(500).json({ error: 'Failed to save targets.json' });
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

// ── MitM / Traffic Monitor API ──────────────────────────────────────────────

// Multi-device monitoring: { "192.168.1.72": process, "192.168.1.65": process }
let activeMonitors = {};
let passiveMonitorProcess = null;

/**
 * Get active network interface (auto-detect for macOS & Linux)
 */
function getNetworkInterface() {
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    const preferred = ['wlan0', 'en0', 'eth0', 'wlp2s0', 'enp0s3', 'Wi-Fi'];
    for (const name of preferred) {
        if (nets[name]) {
            const hasIPv4 = nets[name].some(n => n.family === 'IPv4' && !n.internal);
            if (hasIPv4) return name;
        }
    }
    for (const [name, addrs] of Object.entries(nets)) {
        if (addrs.some(n => n.family === 'IPv4' && !n.internal)) return name;
    }
    return process.platform === 'darwin' ? 'en0' : 'wlan0';
}

/**
 * Get Default Gateway IP
 */
function getGatewayIP() {
    return new Promise((resolve) => {
        const cmd = process.platform === 'darwin'
            ? "netstat -nr | grep default | awk '{print $2}' | head -n 1"
            : "ip route | grep default | awk '{print $3}'";
        exec(cmd, (err, stdout) => {
            if (err || !stdout) return resolve(null);
            resolve(stdout.trim());
        });
    });
}

/**
 * Start Passive DNS Monitor (auto-starts on server boot)
 */
function startPassiveMonitor() {
    if (passiveMonitorProcess) {
        console.log('⚠️  Passive monitor already running.');
        return;
    }
    const scriptPath = path.join(__dirname, '..', 'passive_monitor.py');
    if (!fs.existsSync(scriptPath)) {
        console.log('⚠️  passive_monitor.py not found, skipping.');
        return;
    }

    const iface = getNetworkInterface();
    console.log(`📡 Starting passive DNS monitor on ${iface}...`);

    const cmd = 'python3';
    const args = [scriptPath, '-i', iface];

    passiveMonitorProcess = spawn(cmd, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: path.join(__dirname, '..')
    });

    passiveMonitorProcess.stdout.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg) console.log(`[Passive] ${msg}`);
    });
    passiveMonitorProcess.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg && !msg.includes('WARNING')) console.error(`[Passive ERR] ${msg}`);
    });
    passiveMonitorProcess.on('exit', (code) => {
        console.log(`[Passive] Process exited: ${code}`);
        passiveMonitorProcess = null;
    });
}

// ── MITM: Start Targeted Monitoring ────────────────────────────────────────────
app.post('/api/mitm/start', async (req, res) => {
    const { ip, duration } = req.body;
    if (!ip) return res.status(400).json({ error: 'Target IP required' });

    // If already monitoring this IP, return success
    if (activeMonitors[ip]) {
        return res.json({ status: 'already_monitoring', target: ip });
    }

    // Start monitoring for this specific IP
    const gateway = await getGatewayIP();
    if (!gateway) return res.status(500).json({ error: 'Gateway not found' });

    const scriptPath = path.join(__dirname, '..', 'traffic_monitor.py');
    const iface = getNetworkInterface();

    console.log(`😈 Starting MITM on ${ip} via ${gateway}...`);

    const cmd = 'python3';
    const args = [scriptPath, '-t', ip, '-g', gateway, '-i', iface, '--action', 'monitor'];

    const proc = spawn(cmd, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: path.join(__dirname, '..')
    });

    proc.stdout.on('data', (data) => {
        console.log(`[MITM ${ip}] ${data.toString().trim()}`);
    });
    proc.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg && !msg.includes('WARNING')) console.error(`[MITM ${ip} ERR] ${msg}`);
    });
    proc.on('exit', (code) => {
        console.log(`[MITM ${ip}] Process exited: ${code}`);
        delete activeMonitors[ip];
    });

    activeMonitors[ip] = proc;
    res.json({ status: 'started', target: ip, gateway, active_monitors: Object.keys(activeMonitors) });
});

// ── MITM: Stop (single target or all) ─────────────────────────────────────────
app.post('/api/mitm/stop', (req, res) => {
    const { ip } = req.body || {};

    if (ip && activeMonitors[ip]) {
        activeMonitors[ip].kill('SIGTERM');
        delete activeMonitors[ip];
        return res.json({ status: 'stopped', target: ip });
    }

    // Stop ALL monitors
    for (const [targetIp, proc] of Object.entries(activeMonitors)) {
        try { proc.kill('SIGTERM'); } catch (e) { }
    }
    activeMonitors = {};
    exec('pkill -f "traffic_monitor.py"', () => {
        res.json({ status: 'all_stopped' });
    });
});

// ── Monitor Status ────────────────────────────────────────────────────────────
app.get('/api/monitor/status', (req, res) => {
    const passiveStats = path.join(__dirname, '..', 'passive_stats.json');
    let passive = null;
    if (fs.existsSync(passiveStats)) {
        try { passive = JSON.parse(fs.readFileSync(passiveStats, 'utf8')); } catch { }
    }

    res.json({
        active_monitors: Object.keys(activeMonitors),
        passive_monitor: !!passiveMonitorProcess,
        passive_stats: passive,
        monitor_count: Object.keys(activeMonitors).length
    });
});

// ── MITM: Details (Traffic Inspector) ─────────────────────────────────────────
app.get('/api/mitm/details', (req, res) => {
    const statsFile = path.join(__dirname, '..', 'traffic_stats.json');
    if (fs.existsSync(statsFile)) {
        try {
            const data = JSON.parse(fs.readFileSync(statsFile, 'utf8'));
            data.active_monitors = Object.keys(activeMonitors);
            res.json(data);
        } catch { res.json({ error: 'Stats read error' }); }
    } else {
        res.json({ error: 'No stats yet', active_monitors: Object.keys(activeMonitors) });
    }
});

// ── FOOTPRINT: Per-Device Organized History ───────────────────────────────────
app.get('/api/footprint', (req, res) => {
    const footprintFile = path.join(__dirname, '..', 'footprint_db.json');
    const targetIP = req.query.ip;

    if (fs.existsSync(footprintFile)) {
        try {
            const db = JSON.parse(fs.readFileSync(footprintFile, 'utf8'));
            if (targetIP && db[targetIP]) {
                res.json({ ip: targetIP, ...db[targetIP] });
            } else if (targetIP) {
                res.json({ ip: targetIP, domains: {}, sessions: [], total_bytes: 0 });
            } else {
                res.json(db);
            }
        } catch (e) {
            res.status(500).json({ error: 'Footprint read error' });
        }
    } else {
        res.json(targetIP ? { ip: targetIP, domains: {}, sessions: [], total_bytes: 0 } : {});
    }
});

// ── BLOCK: Start Blocking (Deny Internet) ─────────────────────────────────────
app.post('/api/block/start', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'Target IP required' });

    // Kill existing monitor for this IP if any
    if (activeMonitors[`block_${ip}`]) {
        try { activeMonitors[`block_${ip}`].kill('SIGTERM'); } catch (e) { }
        delete activeMonitors[`block_${ip}`];
    }

    const gateway = await getGatewayIP();
    if (!gateway) return res.status(500).json({ error: 'Gateway not found' });

    const scriptPath = path.join(__dirname, '..', 'traffic_monitor.py');
    const iface = getNetworkInterface();
    console.log(`🚫 Blocking ${ip} via ${gateway}...`);

    const cmd = 'python3';
    const args = [scriptPath, '-t', ip, '-g', gateway, '-i', iface, '--action', 'block'];

    const proc = spawn(cmd, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: path.join(__dirname, '..')
    });
    proc.on('exit', (code) => {
        console.log(`[Block ${ip}] Exited: ${code}`);
        delete activeMonitors[`block_${ip}`];
    });

    activeMonitors[`block_${ip}`] = proc;
    res.json({ status: 'blocking_started', target: ip });
});

// ── BLOCK: Stop ───────────────────────────────────────────────────────────────
app.post('/api/block/stop', (req, res) => {
    const { ip } = req.body || {};
    if (ip && activeMonitors[`block_${ip}`]) {
        activeMonitors[`block_${ip}`].kill('SIGTERM');
        delete activeMonitors[`block_${ip}`];
        return res.json({ status: 'stopped', target: ip });
    }
    // Stop all blockers
    for (const key of Object.keys(activeMonitors)) {
        if (key.startsWith('block_')) {
            try { activeMonitors[key].kill('SIGTERM'); } catch (e) { }
            delete activeMonitors[key];
        }
    }
    res.json({ status: 'all_blocks_stopped' });
});

/**
 * Get Real-time MitM Stats
 */
app.get('/api/mitm/stats', (req, res) => {
    const statsFile = path.join(__dirname, '..', 'traffic_stats.json');

    fs.readFile(statsFile, 'utf8', (err, data) => {
        if (err) {
            return res.json({ status: 'no_data', error: err.message });
        }
        try {
            const json = JSON.parse(data);
            res.json(json);
        } catch (e) {
            res.json({ status: 'error', error: 'Invalid JSON' });
        }
    });
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
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    let localIP = 'localhost';

    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                localIP = net.address;
                break;
            }
        }
    }

    console.log(`\n🚀 Server on http://0.0.0.0:${PORT}`);
    console.log(`   → Phone:    http://${localIP}:${PORT}`);
    console.log(`   → Emulator: http://10.0.2.2:${PORT}`);
    console.log(`   → Local:    http://localhost:${PORT}\n`);

    // Auto-start passive DNS monitor
    const IS_ROOT = process.getuid && process.getuid() === 0;
    if (IS_ROOT) {
        startPassiveMonitor();
    } else {
        console.log('⚠️  Not root — passive DNS monitor requires sudo. Run: sudo node Backend/server.js');
    }
});
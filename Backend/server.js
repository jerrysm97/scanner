const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');
const app = express();

const macLookup = require('mac-lookup');

// Helper to load the vendor database - Load once at startup
macLookup.load(() => {
    console.log("📂 OUI Database loaded successfully.");
});

app.use(cors()); // Allow cross-origin requests

// 1. Discovery Scan Endpoint
app.get('/api/scan', (req, res) => {
    console.log("📡 Scan requested...");
    // Run without sudo; agent.py handles permission fallback
    exec('python3 ../agent.py', async (error, stdout, stderr) => {
        if (error || stderr) {
            console.error(`Exec error: ${error || stderr}`);
            return res.status(500).json({ error: "Failed to run scanner" });
        }

        try {
            // FIX: agent.py output is already JSON string if exec returns it as stdout
            let rawData = typeof stdout === 'string' ? JSON.parse(stdout) : stdout;
            let devices = rawData.devices || [];

            // Enrich data with Vendor Name
            const enrichedDevices = await Promise.all(devices.map(async (device) => {
                const vendor = await new Promise(resolve => {
                    // mac-lookup uses .lookup(oui, callback)
                    macLookup.lookup(device.mac, (err, name) => resolve(name || "Unknown Vendor"));
                });
                return { ...device, vendor };
            }));

            res.json({ status: "success", count: enrichedDevices.length, devices: enrichedDevices });
        } catch (parseError) {
            console.error("Parse Error:", parseError, "Raw output:", stdout);
            res.json({ error: "Invalid scanner output", raw_output: stdout.trim() });
        }
    });
});

// 2. NEW Deep Scan Endpoint
app.get('/api/inspect', (req, res) => {
    const ip = req.query.ip;

    // STRICT INPUT SANITIZATION
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

    if (!ip || !ipRegex.test(ip)) {
        return res.status(400).json({ error: "Invalid IP address format" });
    }

    console.log(`🔎 Deep Scanning ${ip}...`);

    // Calls python script WITH the IP address as an argument
    exec(`python3 ../agent.py ${ip}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: "Scan failed" });
        }
        try {
            res.json(JSON.parse(stdout));
        } catch (e) {
            res.json({ error: "Invalid Python Output" });
        }
    });
});

// 3. AUDIT Endpoint (Vulnerability Scanner)
app.get('/api/audit', (req, res) => {
    const ip = req.query.ip;
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ip || !ipRegex.test(ip)) return res.status(400).json({ error: "Invalid IP" });

    console.log(`🔓 Auditing Credentials for ${ip}...`);
    // Calls python script with 'audit <IP>' arguments
    exec(`python3 ../agent.py audit ${ip}`, (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: "Audit failed" });
        try {
            res.json(JSON.parse(stdout));
        } catch (e) {
            res.json({ error: "Invalid Output" });
        }
    });
});

// 4. ACTIVE HONEYPOT TRAP
const net = require('net');
const honeypotLogs = [];

// Lightweight TCP Server on Port 2323 (Fake Telnet)
const honeypot = net.createServer((socket) => {
    const intruderIp = socket.remoteAddress?.replace('::ffff:', '');
    const timestamp = new Date().toLocaleTimeString();

    console.log(`🚨 HONEYPOT TRIGGERED by ${intruderIp} at ${timestamp}`);
    honeypotLogs.unshift({ ip: intruderIp, time: timestamp }); // Add to start

    // Don't actually let them connect, just log and close
    socket.end();
});

honeypot.listen(2323, () => {
    console.log("🪤 Honeypot Active on Port 2323");
});

// Endpoint to fetch honeypot logs
app.get('/api/honeypot', (req, res) => {
    res.json(honeypotLogs);
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Sentinel Bridge running on http://localhost:${PORT}`);
    console.log(`💡 NOTE: Run with 'sudo node server.js' for Active Scanning features.`);
});
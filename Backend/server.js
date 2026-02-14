const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');
const app = express();

app.use(cors()); // Allow cross-origin requests

// 1. Discovery Scan Endpoint
app.get('/api/scan', (req, res) => {
    console.log("📡 Scan requested...");
    exec('python3 ../agent.py', (error, stdout, stderr) => {
        if (error) {
            console.error(`Exec error: ${error}`);
            return res.status(500).json({ error: "Failed to run scanner" });
        }

        try {
            res.json(JSON.parse(stdout));
        } catch (parseError) {
            res.json({ raw_output: stdout.trim() });
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
});
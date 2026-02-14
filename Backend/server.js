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
    if (!ip) return res.status(400).json({ error: "IP required" });

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

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Sentinel Bridge running on http://localhost:${PORT}`);
});
const express = require('express');
const { exec } = require('child_process');
const cors = require('cors');
const app = express();

app.use(cors()); // Allow cross-origin requests from your mobile app

// Endpoint to trigger the scan
app.get('/api/scan', (req, res) => {
    console.log("📡 Scan requested...");

    // Executes your agent.py script
    // Note: Adjusted path to your actual project location
    exec('python3 ../agent.py', (error, stdout, stderr) => {
        if (error) {
            console.error(`Exec error: ${error}`);
            return res.status(500).json({ error: "Failed to run scanner" });
        }

        try {
            // Parse the JSON output from your Python script
            const scanResult = JSON.parse(stdout);
            res.json(scanResult);
        } catch (parseError) {
            // Fallback if Python output isn't pure JSON yet
            res.json({ raw_output: stdout.trim() });
        }
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Sentinel Bridge running on http://localhost:${PORT}`);
});
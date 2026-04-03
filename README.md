# 🔍 Scanner

**Network Traffic Monitor & Security Agent**

A Python-based network security toolkit for passive traffic monitoring, active scanning, and automated threat detection. Includes a mobile companion app (SentinelMobile).

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Network_Security-red)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## 🚀 Features

- **Passive Traffic Monitor** — real-time packet capture and analysis
- **Active Network Agent** — automated scanning and threat classification
- **Traffic Verification** — validate monitor accuracy against known baselines
- **SentinelMobile** — companion mobile app for remote monitoring
- **Shell Automation** — setup and command scripts for rapid deployment

## 📁 Architecture

```
scanner/
├── agent.py                    # Active scanning agent (25KB)
├── traffic_monitor.py          # Passive packet capture & analysis (22KB)
├── passive_monitor.py          # Lightweight passive listener
├── verify_traffic_monitor.py   # Monitor accuracy verification
├── commands.sh                 # Common network commands reference
├── setup_linux.sh              # One-click Linux environment setup
├── run.sh                      # Launch script
├── Backend/                    # API backend for data aggregation
└── SentinelMobile/             # Mobile companion app
```

## ⚡ Quick Start

```bash
git clone https://github.com/jerrysm97/scanner.git
cd scanner
sudo bash setup_linux.sh
sudo bash run.sh
```

## 🛠️ Tech Stack

- **Core:** Python 3, Scapy, Socket
- **Backend:** Node.js API
- **Mobile:** SentinelMobile (companion app)

## ⚠️ Disclaimer

For authorized security testing and educational purposes only. Only monitor networks you own or have explicit permission to test.

## 📜 License

MIT License

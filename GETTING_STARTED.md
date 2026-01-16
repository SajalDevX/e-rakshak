# RAKSHAK - Getting Started Guide

> How to set up and test RAKSHAK on your local machine without hardware

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Running RAKSHAK](#3-running-rakshak)
4. [Testing Without Hardware](#4-testing-without-hardware)
5. [Using the Dashboard](#5-using-the-dashboard)
6. [Running Demo Attacks](#6-running-demo-attacks)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended) or Windows with WSL2
- **Python**: 3.10 or higher
- **RAM**: 4GB minimum (8GB recommended for LLM features)
- **Disk**: 5GB free space (10GB if using LLM)

### Check Python Version
```bash
python3 --version
# Should show Python 3.10 or higher
```

If Python is not installed:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

---

## 2. Installation

### Step 1: Navigate to Project Directory
```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv venv
```

### Step 3: Activate Virtual Environment
```bash
source venv/bin/activate
```

You should see `(venv)` at the start of your terminal prompt.

### Step 4: Install Dependencies

**Option A: Install all dependencies (full features, larger download)**
```bash
pip install -r requirements.txt
```

**Option B: Install minimal dependencies (faster, no LLM)**
```bash
pip install flask flask-socketio flask-cors eventlet
pip install numpy loguru pyyaml click rich
pip install scapy python-nmap
```

### Step 5: Verify Installation
```bash
python -c "import flask; import numpy; print('Installation successful!')"
```

---

## 3. Running RAKSHAK

### Start in Simulation Mode (Recommended for Testing)

Simulation mode creates fake IoT devices and doesn't require root access or real network scanning.

```bash
# Make sure venv is activated
source venv/bin/activate

# Run RAKSHAK
python main.py --simulate
```

### Expected Output
```
    ██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗
    ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝
    ██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝
    ...

RAKSHAK Started in SIMULATION mode
Dashboard: http://localhost:5000
```

### Command Line Options
```bash
python main.py --help

Options:
  --simulate, -s    Run in simulation mode (fake devices)
  --debug, -d       Enable debug logging
  --port, -p        Dashboard port (default: 5000)
  --config, -c      Custom config file path
```

---

## 4. Testing Without Hardware

RAKSHAK includes a full **Simulation Mode** that works without any hardware or real network.

### What Simulation Mode Does

1. **Creates 8 Fake IoT Devices**:
   - Smart TV (Samsung)
   - IP Camera (Wyze)
   - Smart Speaker (Alexa)
   - Smart Bulb (Philips Hue)
   - Router (TP-Link)
   - Smart Thermostat (Nest)
   - Gaming Console (PlayStation)
   - Smart Lock (August)

2. **Simulates Network Traffic**: No actual scanning required

3. **Generates Test Threats**: You can trigger fake attacks via the dashboard

4. **Deploys Functional Honeypots**: Real TCP servers that respond to connections

### Running Tests

**Terminal 1 - Start RAKSHAK:**
```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
source venv/bin/activate
python main.py --simulate --debug
```

**Terminal 2 - Run Demo Attacks:**
```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
source venv/bin/activate
python scripts/demo_attack.py --type all
```

---

## 5. Using the Dashboard

### Access the Dashboard

Open your web browser and go to:
```
http://localhost:5000
```

### Dashboard Features

| Section | Description |
|---------|-------------|
| **Stats Cards** | Shows device count, threats, honeypots, actions |
| **Network Devices** | List of discovered/simulated IoT devices with risk scores |
| **Live Events** | Real-time log of threats and actions |
| **Active Honeypots** | Currently running honeypot services |
| **Quick Actions** | Export data, deploy honeypots, view intelligence |

### Dashboard Actions You Can Try

1. **Simulate Attack Button**: Click "Simulate Attack" to generate a fake threat
2. **Deploy Honeypot**: Click "Deploy" to start a new honeypot
3. **Isolate Device**: Click "Isolate" next to any device
4. **Export CCTNS**: Export threat data in law enforcement format
5. **Language Toggle**: Switch between English and Hindi

---

## 6. Running Demo Attacks

The demo script simulates real attack patterns against RAKSHAK.

### Available Attack Types

```bash
# Port scan simulation
python scripts/demo_attack.py --type port_scan

# Brute force login attempts
python scripts/demo_attack.py --type brute_force --port 2323

# Interactive honeypot session
python scripts/demo_attack.py --type interact --port 2323

# Full demo (all attacks)
python scripts/demo_attack.py --type all
```

### Manual Honeypot Testing

If a honeypot is running on port 2323, you can connect manually:

```bash
# Connect via telnet
telnet localhost 2323

# Or using netcat
nc localhost 2323
```

**Try these commands in the honeypot:**
```
admin          # Username
admin          # Password
whoami
cat /etc/passwd
ls -la
uname -a
exit
```

---

## 7. Troubleshooting

### Common Issues

#### Issue: "ModuleNotFoundError: No module named 'flask'"
**Solution:** Make sure virtual environment is activated
```bash
source venv/bin/activate
pip install flask flask-socketio flask-cors eventlet
```

#### Issue: "Address already in use" on port 5000
**Solution:** Either kill the existing process or use a different port
```bash
# Use different port
python main.py --simulate --port 5001

# Or find and kill existing process
lsof -i :5000
kill <PID>
```

#### Issue: "Permission denied" for network scanning
**Solution:** Use simulation mode (doesn't need root)
```bash
python main.py --simulate
```

#### Issue: PyTorch/Transformers not installing
**Solution:** Use minimal install without LLM features
```bash
pip install flask flask-socketio flask-cors eventlet numpy loguru pyyaml click rich
```
The system will use template-based responses instead of LLM.

#### Issue: Dashboard not loading
**Solution:** Check if server is running and try:
```bash
# Check if port is listening
netstat -tlnp | grep 5000

# Try accessing with curl
curl http://localhost:5000/api/status
```

### Checking Logs

```bash
# View real-time logs
tail -f data/logs/rakshak.log

# View threat logs
cat data/threats/threats_*.json
```

---

## Quick Test Checklist

- [ ] Virtual environment created and activated
- [ ] Dependencies installed (at least minimal)
- [ ] `python main.py --simulate` runs without errors
- [ ] Dashboard opens at http://localhost:5000
- [ ] "Simulate Attack" button creates a threat event
- [ ] "Deploy" button creates a honeypot
- [ ] `demo_attack.py` connects to honeypot successfully

---

## Next Steps After Testing

1. **Test on Raspberry Pi 5**: Transfer code and run on actual hardware
2. **Enable Real Scanning**: Remove `--simulate` flag (requires sudo)
3. **Add LLM Features**: Install full requirements for TinyLlama responses
4. **Customize Config**: Edit `config/config.yaml` for your network

---

## Quick Reference Commands

```bash
# Activate environment
source venv/bin/activate

# Start RAKSHAK (simulation)
python main.py --simulate

# Start with debug logs
python main.py --simulate --debug

# Run demo attacks
python scripts/demo_attack.py --type all

# Check API status
curl http://localhost:5000/api/status

# View devices
curl http://localhost:5000/api/devices

# Simulate a threat via API
curl -X POST http://localhost:5000/api/simulate/threat
```

---

**Need help?** Check `docs/RAKSHAK_DOCS.md` for complete technical documentation.

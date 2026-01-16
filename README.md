# RAKSHAK - रक्षक

> **India's First Agentic AI Cyber Guardian for Home IoT**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform: Raspberry Pi 5](https://img.shields.io/badge/platform-Raspberry%20Pi%205-red.svg)](https://www.raspberrypi.com/)

*"Har Ghar Ki Cyber Suraksha" - Cyber Security for Every Home*

---

## Overview

RAKSHAK is a revolutionary consumer cybersecurity device that combines:

- **Agentic AI**: Autonomous decision-making using Reinforcement Learning (Dueling DQN)
- **Dynamic Deception**: LLM-powered honeypots (TinyLlama 1.1B) that mimic real IoT devices
- **Edge Computing**: 100% local processing on Raspberry Pi 5 - no cloud dependency

## Five Core Features

| Feature | Name | Description |
|---------|------|-------------|
| **MAYA** | Morphing Adaptive Yielding Architecture | Auto-clones IoT devices as decoys |
| **KAAL** | Knowledge-Augmented Autonomous Learner | RL agent for autonomous defense |
| **PRAHARI** | Protocol-Aware Response & Honeypot AI | LLM-powered dynamic responses |
| **CHAKRAVYUH** | Circular Defense Trap Network | Multi-layer deception trap |
| **DRISHTI** | Dashboard & Real-time Intelligence | Web dashboard with Hindi/English |

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
# Clone the repository
cd /home/sajal/Desktop/Hackathons/e-raksha

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running RAKSHAK

```bash
# Run in simulation mode (recommended for first run)
python main.py --simulate

# Run with debug logging
python main.py --simulate --debug

# Access dashboard
open http://localhost:5000
```

### Demo Attack Simulation

```bash
# In a separate terminal
python scripts/demo_attack.py --type all
```

## Project Structure

```
e-raksha/
├── main.py                    # Main entry point
├── requirements.txt           # Python dependencies
├── config/
│   └── config.yaml           # Configuration file
├── core/
│   ├── network_scanner.py    # MAYA - Device discovery
│   ├── agentic_defender.py   # KAAL - RL Agent
│   ├── llm_honeypot.py       # PRAHARI - LLM responses
│   ├── deception_engine.py   # CHAKRAVYUH - Deception
│   └── threat_logger.py      # Event logging
├── api/
│   └── app.py                # Flask REST API
├── dashboard/
│   ├── templates/            # HTML templates
│   └── static/               # CSS/JS files
├── scripts/
│   └── demo_attack.py        # Demo attack simulator
└── docs/
    └── RAKSHAK_DOCS.md       # Full documentation
```

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      RAKSHAK SYSTEM                         │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1: NETWORK    →  LAYER 2: AI BRAIN  →  LAYER 3: ACTIONS
│  (Scanner/MAYA)         (KAAL/DQN)             (Honeypot/Alert)
│                                │
│                                ▼
│  ┌──────────────────────────────────────────────────────────┐
│  │           DECEPTION ENGINE (CHAKRAVYUH)                 │
│  │   [Device Clones]  [LLM Honeypot]  [Intel Capture]      │
│  └──────────────────────────────────────────────────────────┘
│                                │
│                                ▼
│  ┌──────────────────────────────────────────────────────────┐
│  │              DASHBOARD (DRISHTI)                        │
│  │         Flask API + WebSocket + Web UI                   │
│  └──────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | System status |
| `/api/devices` | GET | List all devices |
| `/api/threats` | GET | Recent threats |
| `/api/honeypots` | GET | Active honeypots |
| `/api/honeypots/deploy` | POST | Deploy honeypot |
| `/api/threats/export/cctns` | POST | Export CCTNS report |

## Hardware Requirements

| Component | Specification | Purpose |
|-----------|---------------|---------|
| Raspberry Pi 5 | 8GB RAM | Main device |
| SD Card | 128GB Class 10 | Storage |
| Power Supply | 27W USB-C PD | Power |

## Configuration

Edit `config/config.yaml` to customize:

- Network scanning parameters
- Honeypot ports and personas
- AI agent hyperparameters
- Dashboard settings
- Alert messages (Hindi/English)

## Technologies Used

- **Python 3.11+** - Core language
- **PyTorch** - Dueling DQN neural network
- **TinyLlama 1.1B** - LLM for honeypot responses
- **Flask** - REST API framework
- **Flask-SocketIO** - Real-time WebSocket
- **Scapy** - Network packet manipulation
- **python-nmap** - Service fingerprinting

## Contributing

This project was developed for **eRaksha Hackathon 2026** by IIT Delhi + CyberPeace.

## License

MIT License - See LICENSE file for details.

---

**RAKSHAK** - *Detect. Deceive. Defend. Autonomously.*

*"Har Ghar Ki Cyber Suraksha"*

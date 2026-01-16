# RAKSHAK - Complete Project Documentation

> **India's First Agentic AI Cyber Guardian for Home IoT**
> "Har Ghar Ki Cyber Suraksha" - Cyber Security for Every Home

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture & Design](#2-architecture--design)
3. [Step-by-Step Implementation Log](#3-step-by-step-implementation-log)
4. [Completed Work](#4-completed-work)
5. [Pending Work](#5-pending-work)
6. [Next Steps](#6-next-steps)
7. [Risks & Notes](#7-risks--notes)
8. [Installation Guide](#8-installation-guide)
9. [API Reference](#9-api-reference)
10. [Demo Guide](#10-demo-guide)

---

## 1. Project Overview

### 1.1 Project Goal

Build RAKSHAK - an affordable, consumer-friendly cybersecurity device that uses Agentic AI and deception technology to protect home IoT networks from cyber attacks.

### 1.2 Key Features

| Feature | Name | Description |
|---------|------|-------------|
| **MAYA** | Morphing Adaptive Yielding Architecture | Automatically clones IoT devices to create decoys |
| **KAAL** | Knowledge-Augmented Autonomous Learner | RL-based (Dueling DQN) autonomous defense agent |
| **PRAHARI** | Protocol-Aware Response & Honeypot AI | LLM-powered dynamic honeypot responses |
| **CHAKRAVYUH** | Circular Defense Trap Network | Multi-layer deception trap inspired by Mahabharata |
| **DRISHTI** | Dashboard & Real-time Intelligence | Web dashboard with Hindi/English alerts |

### 1.3 Target Users

- Indian households with multiple IoT devices
- Non-technical users needing plug-and-play security
- Small businesses with limited security budgets
- Security researchers studying IoT attack patterns

### 1.4 Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Hardware | Raspberry Pi 5 (8GB) | Edge computing platform |
| OS | Raspberry Pi OS Lite 64-bit | Lightweight Linux |
| Backend | Python 3.11+, Flask, Flask-SocketIO | API and real-time updates |
| AI/ML | PyTorch, Dueling DQN | Reinforcement learning agent |
| LLM | TinyLlama 1.1B (INT8 quantized) | Dynamic response generation |
| Network | Scapy, python-nmap | Packet capture, device scanning |
| Database | SQLite, Redis (optional) | Local storage, caching |
| Frontend | HTML/CSS/JS, Chart.js | Dashboard visualization |

---

## 2. Architecture & Design

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        RAKSHAK SYSTEM                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐   │
│  │   LAYER 1   │   │   LAYER 2   │   │      LAYER 3        │   │
│  │   NETWORK   │──▶│  AI BRAIN   │──▶│      ACTIONS        │   │
│  │   SCANNER   │   │   (KAAL)    │   │                     │   │
│  │   (MAYA)    │   │ Dueling DQN │   │ - Deploy Honeypot   │   │
│  └─────────────┘   └─────────────┘   │ - Isolate Device    │   │
│        │                 │           │ - Alert User        │   │
│        │                 │           │ - Engage Attacker   │   │
│        ▼                 ▼           └─────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              DECEPTION ENGINE (CHAKRAVYUH)              │   │
│  │  ┌───────────┐  ┌────────────┐  ┌────────────────────┐ │   │
│  │  │  Device   │  │    LLM     │  │      Threat        │ │   │
│  │  │  Clones   │  │  Honeypot  │  │   Intelligence     │ │   │
│  │  │  (MAYA)   │  │ (PRAHARI)  │  │     Capture        │ │   │
│  │  └───────────┘  └────────────┘  └────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────┘   │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                 DASHBOARD (DRISHTI)                     │   │
│  │      Flask API  +  WebSocket  +  Web Interface          │   │
│  │        Real-time alerts in Hindi & English              │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

```
1. Network Scanner (MAYA)
   │
   ├──▶ Discovers devices via ARP scan
   ├──▶ Fingerprints devices (OS, services, ports)
   ├──▶ Calculates risk scores
   │
   ▼
2. Threat Detection
   │
   ├──▶ Monitors traffic for anomalies
   ├──▶ Detects port scans, brute-force, exploits
   │
   ▼
3. Agentic Defender (KAAL)
   │
   ├──▶ Encodes threat as state vector
   ├──▶ Dueling DQN selects optimal action
   ├──▶ Actions: MONITOR, DEPLOY_HONEYPOT, ISOLATE, ENGAGE, ALERT
   │
   ▼
4. Deception Engine (CHAKRAVYUH)
   │
   ├──▶ Deploys honeypots mimicking real devices
   ├──▶ LLM (PRAHARI) generates realistic responses
   ├──▶ Captures attacker TTPs (Tactics, Techniques, Procedures)
   │
   ▼
5. Dashboard (DRISHTI)
   │
   ├──▶ Real-time visualization via WebSocket
   ├──▶ Push notifications in Hindi/English
   └──▶ Export to CCTNS format
```

### 2.3 Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| RL Algorithm | Dueling DQN | Separates value and advantage streams for better action selection |
| LLM Model | TinyLlama 1.1B | Small enough for Pi 5 (8GB), good instruction following |
| Quantization | INT8 | Balance between model size and quality |
| Database | SQLite | No external dependencies, portable |
| Web Framework | Flask + SocketIO | Simple, real-time capable |
| Config Format | YAML | Human-readable, widely supported |

---

## 3. Step-by-Step Implementation Log

### Step 1: Project Directory Structure

**What**: Created the base directory structure for the project.

**Why**: Organize code into logical modules for maintainability.

**How**: Created directories for core modules, API, dashboard, config, data, tests, and documentation.

```bash
mkdir -p core api dashboard/static dashboard/templates models config data/logs data/threats tests scripts docs
touch core/__init__.py api/__init__.py tests/__init__.py
```

**Structure**:
```
e-raksha/
├── core/           # Core modules (MAYA, KAAL, PRAHARI, CHAKRAVYUH)
├── api/            # Flask API backend
├── dashboard/      # Web dashboard files
├── models/         # Trained ML models
├── config/         # Configuration files
├── data/           # Logs and threat data
├── tests/          # Unit tests
├── scripts/        # Utility scripts
└── docs/           # Documentation
```

---

### Step 2: Requirements File

**What**: Created `requirements.txt` with all Python dependencies.

**Why**: Enable reproducible installations and document dependencies.

**How**: Listed all required packages with version constraints.

**Key Dependencies**:
- `torch>=2.1.0` - PyTorch for Dueling DQN
- `transformers>=4.36.0` - Hugging Face for TinyLlama
- `scapy>=2.5.0` - Network packet manipulation
- `flask>=3.0.0` - Web framework
- `flask-socketio>=5.3.6` - Real-time WebSocket support

---

### Step 3: Configuration File

**What**: Created `config/config.yaml` with all system settings.

**Why**: Centralize configuration, enable easy customization, support simulation mode.

**How**: Defined sections for each component with sensible defaults.

**Key Sections**:
- `simulation` - Fake devices for testing without real network
- `network` - Scanner settings, whitelist IPs
- `agent` - Dueling DQN hyperparameters
- `llm` - TinyLlama model settings and device personas
- `deception` - Honeypot port mappings
- `alerts` - Hindi/English notification messages

---

### Step 4: Main Entry Point

**What**: Created `main.py` orchestrator.

**Why**: Provide single entry point that coordinates all components.

**How**:
- Implemented `RakshakOrchestrator` class
- Background threads for scanning and threat processing
- Signal handlers for graceful shutdown
- CLI options via Click

**Key Features**:
- `--simulate` flag for simulation mode
- `--debug` flag for verbose logging
- `--port` option for dashboard port
- ASCII banner with Rich console

---

## 4. Completed Work

| # | Task | Status | Date |
|---|------|--------|------|
| 1 | Project directory structure | ✅ Completed | 2026-01-13 |
| 2 | requirements.txt | ✅ Completed | 2026-01-13 |
| 3 | config/config.yaml | ✅ Completed | 2026-01-13 |
| 4 | main.py entry point | ✅ Completed | 2026-01-13 |
| 5 | RAKSHAK_DOCS.md | ✅ Completed | 2026-01-13 |
| 6 | Threat Logger (threat_logger.py) | ✅ Completed | 2026-01-13 |
| 7 | Network Scanner - MAYA (network_scanner.py) | ✅ Completed | 2026-01-13 |
| 8 | Agentic Defender - KAAL (agentic_defender.py) | ✅ Completed | 2026-01-13 |
| 9 | LLM Honeypot - PRAHARI (llm_honeypot.py) | ✅ Completed | 2026-01-13 |
| 10 | Deception Engine - CHAKRAVYUH (deception_engine.py) | ✅ Completed | 2026-01-13 |
| 11 | Flask API Backend (api/app.py) | ✅ Completed | 2026-01-13 |
| 12 | Dashboard - DRISHTI (HTML/CSS/JS) | ✅ Completed | 2026-01-13 |
| 13 | Demo Attack Scripts (demo_attack.py) | ✅ Completed | 2026-01-13 |
| 14 | README.md | ✅ Completed | 2026-01-13 |

---

## 5. Pending Work

| # | Task | Priority | Notes |
|---|------|----------|-------|
| 1 | Install dependencies on target machine | HIGH | Run `pip install -r requirements.txt` |
| 2 | Test in simulation mode | HIGH | Run `python main.py --simulate` |
| 3 | Deploy to Raspberry Pi 5 | MEDIUM | Transfer and test on actual hardware |
| 4 | Pre-train KAAL model | LOW | Optional: improves initial decisions |
| 5 | Add more device personas | LOW | Expand honeypot variety |

---

## 6. Next Steps

### Immediate Next Steps

1. **Implement `core/threat_logger.py`**
   - Event logging class
   - Threat queue for async processing
   - CCTNS export format

2. **Implement `core/network_scanner.py` (MAYA)**
   - ARP device discovery
   - Nmap fingerprinting
   - Risk score calculation
   - Simulation mode support

3. **Implement `core/agentic_defender.py` (KAAL)**
   - Dueling DQN neural network
   - State encoder
   - Action executor
   - Experience replay

4. **Implement `core/llm_honeypot.py` (PRAHARI)**
   - TinyLlama wrapper
   - Device personas
   - Response generator

### Prerequisites

- Python 3.11+ installed
- Virtual environment created
- Dependencies installed (`pip install -r requirements.txt`)
- For real network scanning: root/sudo access

---

## 7. Risks & Notes

### Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| TinyLlama slow on Pi 5 | Poor UX | Use INT4 quantization, limit response length |
| Scapy requires root | Permission issues | Document sudo requirement, use simulation mode |
| Memory constraints | System crashes | Monitor memory, lazy load models |
| Network scan triggers IDS | False positives | Add whitelist, rate limiting |

### Notes

- **Simulation Mode**: Always test in simulation mode first before live network
- **Model Download**: TinyLlama is ~2GB, first run will download
- **Pi 5 Deployment**: Recommend 8GB model, active cooling
- **CCTNS Integration**: Export format ready for law enforcement reporting

### Future Improvements

- React Native mobile app
- Federated learning across multiple RAKSHAK devices
- Integration with threat intelligence feeds
- Voice alerts in regional languages

---

## 8. Installation Guide

### Prerequisites

```bash
# Python 3.11+
python3 --version

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Quick Start

```bash
# Clone/navigate to project
cd /home/sajal/Desktop/Hackathons/e-raksha

# Activate virtual environment
source venv/bin/activate

# Run in simulation mode
python main.py --simulate

# Access dashboard
open http://localhost:5000
```

### Raspberry Pi 5 Deployment

```bash
# Flash Raspberry Pi OS Lite 64-bit
# SSH into Pi and clone project

# Install system dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv nmap

# Create venv and install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run with real network scanning (requires sudo)
sudo venv/bin/python main.py
```

---

## 9. API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | System status |
| `/api/devices` | GET | List all devices |
| `/api/threats` | GET | List all threats |
| `/api/honeypots` | GET | Active honeypots |
| `/api/config` | GET/POST | View/update config |

### WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `connect` | Client→Server | Client connected |
| `alert` | Server→Client | New threat alert |
| `device_update` | Server→Client | Device status change |
| `threat_detected` | Server→Client | New threat detected |
| `action_taken` | Server→Client | AI action executed |

---

## 10. Demo Guide

### 5-Minute Demo Script

**0:00-1:00 - SETUP**
```bash
python main.py --simulate
# Open http://localhost:5000
# Show: 8 devices discovered with risk scores
```

**1:00-2:00 - DETECTION**
```bash
# In another terminal:
python scripts/demo_attack.py --type port_scan
# Watch: Dashboard shows "THREAT DETECTED"
```

**2:00-3:00 - DECEPTION**
```bash
# Connect to honeypot
telnet localhost 2323
# Type: cat /etc/passwd
# Show: LLM generates fake Linux user list
```

**3:00-4:00 - AUTONOMOUS**
```bash
python scripts/demo_attack.py --type brute_force
# Watch: KAAL auto-quarantines device
```

**4:00-5:00 - DASHBOARD**
```
# Show: Attack map visualization
# Show: CCTNS export button
# Show: Hindi notification toggle
```

---

## Document Info

- **Version**: 1.0.0
- **Last Updated**: 2026-01-13
- **Author**: Team RAKSHAK
- **License**: MIT

---

*RAKSHAK - Detect. Deceive. Defend. Autonomously.*
*"Har Ghar Ki Cyber Suraksha"*

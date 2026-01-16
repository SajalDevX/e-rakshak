# RAKSHAK - Complete Implementation Documentation
## eRaksha Hackathon 2026 | IIT Delhi + CyberPeace

---

# Executive Summary

| Field | Details |
|-------|---------|
| **Project** | RAKSHAK - India's First Agentic AI Cyber Guardian for Home IoT |
| **Tagline** | "Har Ghar Ki Cyber Suraksha" - Cyber Security for Every Home |
| **Architecture** | **Inline Security Gateway** (NOT passive monitoring) |
| **Hardware** | Nvidia Jetson Xavier NX + USB-to-Ethernet Adapter |
| **Network Role** | Gateway between ISP modem and home router |

---

# Part 1: Architecture Overview

## 1.1 The Problem with Passive Monitoring

Most consumer IoT security products use passive monitoring - they sit on the network and observe traffic without control. This approach has fundamental limitations:

| Passive Monitoring | Limitation |
|-------------------|------------|
| Device Isolation | Can only set a flag - traffic still flows |
| Traffic Blocking | No authority to block packets |
| Honeypot Redirection | Impossible - router routes all traffic |
| Autonomous Defense | Simulation only - no real enforcement |

**RAKSHAK solves this by operating as an inline security gateway.**

## 1.2 Inline Gateway Architecture

RAKSHAK physically sits between the ISP modem and home router, giving it **complete control** over all network traffic.

```
                           INTERNET
                               |
                               v
                    +------------------+
                    |    ISP MODEM     |
                    |  (Bridge Mode)   |
                    +--------+---------+
                             |
                             | eth0 (WAN)
                             | Gets IP via DHCP from ISP
                             v
    +----------------------------------------------------+
    |              JETSON XAVIER NX                       |
    |              RAKSHAK GATEWAY                        |
    |                                                     |
    |  +-----------------------------------------------+  |
    |  |           NETWORK FUNCTIONS                   |  |
    |  |                                               |  |
    |  |  +----------+  +----------+  +------------+   |  |
    |  |  |   NAT    |  |   DHCP   |  |  FIREWALL  |   |  |
    |  |  |MASQUERADE|  | SERVER   |  | (iptables) |   |  |
    |  |  +----------+  +----------+  +------------+   |  |
    |  |                                               |  |
    |  |  +----------+  +----------+  +------------+   |  |
    |  |  |    IP    |  |    DNS   |  |    DPI     |   |  |
    |  |  | FORWARD  |  |  SERVER  |  | (nfqueue)  |   |  |
    |  |  +----------+  +----------+  +------------+   |  |
    |  +-----------------------------------------------+  |
    |                                                     |
    |  +-----------------------------------------------+  |
    |  |           DEFENSE FUNCTIONS                   |  |
    |  |                                               |  |
    |  |  +----------+  +----------+  +------------+   |  |
    |  |  |   KAAL   |  |CHAKRAVYUH|  |    MAYA    |   |  |
    |  |  | AI Agent |  |Honeypots |  |  Scanner   |   |  |
    |  |  +----------+  +----------+  +------------+   |  |
    |  +-----------------------------------------------+  |
    |                                                     |
    +------------------------+----------------------------+
                             |
                             | eth1 (LAN)
                             | Static IP: 192.168.100.1
                             | (USB-to-Ethernet adapter)
                             v
                    +------------------+
                    |   WIFI ROUTER    |
                    |   (AP MODE)      |
                    |                  |
                    |  - WiFi ONLY     |
                    |  - No DHCP       |
                    |  - No NAT        |
                    |  - Bridge mode   |
                    +--------+---------+
                             | WiFi
         +--------+----------+----------+--------+
         |        |          |          |        |
         v        v          v          v        v
    +------+  +------+  +------+  +------+  +------+
    |Alexa |  |Camera|  | Smart|  | Smart|  |Other |
    | .10  |  | .11  |  | TV   |  | Bulbs|  | IoT  |
    +------+  +------+  +------+  +------+  +------+
```

**All devices get IP from Jetson DHCP (192.168.100.10-250)**
**All traffic flows THROUGH Jetson - Full control achieved**

---

# Part 2: Hardware Requirements

## 2.1 Required Hardware

| Component | Specification | Purpose |
|-----------|---------------|---------|
| **Jetson Xavier NX** | 8GB RAM, 384 CUDA cores | Main gateway + AI inference |
| **USB-to-Ethernet Adapter** | USB 3.0, Gigabit | Second NIC (LAN interface) |
| **Home Router** | Any router with AP mode | WiFi access point only |
| **ISP Modem** | Standard modem | Internet connection |

## 2.2 Network Interfaces

The Jetson requires **two network interfaces**:

| Interface | Connection | IP Address |
|-----------|------------|------------|
| **eth0** (WAN) | Connected to ISP modem | Dynamic (DHCP from ISP) |
| **eth1** (LAN) | Connected to router | Static: 192.168.100.1 |

USB ethernet adapters are detected as: `eth1`, `enx*`, or `enp*s*u*`

## 2.3 Router Configuration (AP Mode)

Your existing router must be reconfigured as an access point:

### Step-by-Step Router Setup

1. **Disable DHCP Server**
   - Router Settings → LAN → DHCP → Disable
   - Jetson will provide DHCP

2. **Disable NAT**
   - Router Settings → WAN → NAT → Disable
   - Jetson will handle NAT

3. **Set Static IP**
   - Router IP: 192.168.100.2 (on same subnet as Jetson LAN)
   - Subnet mask: 255.255.255.0

4. **Enable Bridge/AP Mode**
   - Some routers have explicit "AP Mode" or "Bridge Mode"
   - If not, disabling DHCP and NAT achieves the same effect

5. **Connect Router WAN Port to Jetson eth1**
   - Use ethernet cable from router WAN port to Jetson USB ethernet

---

# Part 3: Traffic Flow

## 3.1 Outbound Traffic (IoT to Internet)

```
1. IoT Device (192.168.100.50) wants to reach google.com

2. Packet: SRC=192.168.100.50 DST=142.250.185.78

3. WiFi Router (AP mode) forwards unchanged to Jetson eth1

4. Jetson receives packet on eth1 (LAN interface)

5. NFQUEUE (Deep Packet Inspection):
   - Check if source IP is blocked -> DROP
   - Check if rate-limited -> LIMIT
   - Check payload for malicious patterns
   - If clean -> ACCEPT

6. FORWARD chain allows LAN->WAN forwarding

7. NAT POSTROUTING (MASQUERADE):
   - Original: SRC=192.168.100.50 DST=142.250.185.78
   - After NAT: SRC=<Jetson_WAN_IP> DST=142.250.185.78
   - Connection tracked for return traffic

8. Packet exits eth0 to modem and Internet
```

## 3.2 Inbound Traffic (Internet to IoT)

```
1. Response arrives from Internet

2. NAT connection tracking matches to original request

3. Packet de-NATed back to private IP:
   - SRC=142.250.185.78 DST=192.168.100.50

4. FORWARD chain allows established connections

5. Packet forwarded to eth1 -> router -> IoT device
```

---

# Part 4: Gateway Functions

## 4.1 NAT (Network Address Translation)

RAKSHAK performs NAT masquerading so all IoT devices can share the single public IP from your ISP:

```bash
# NAT rule (set by gateway)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

## 4.2 DHCP Server (dnsmasq)

RAKSHAK provides DHCP services to all IoT devices:

| Setting | Value |
|---------|-------|
| Gateway IP | 192.168.100.1 |
| DHCP Range | 192.168.100.10 - 192.168.100.250 |
| DNS Server | 192.168.100.1 (Jetson) |
| Lease Time | 24 hours |

All devices automatically connect and receive IP from Jetson.

## 4.3 Firewall (iptables)

RAKSHAK uses organized iptables chains for manageable rule control:

| Chain | Table | Purpose |
|-------|-------|---------|
| `RAKSHAK_FORWARD` | filter | General forwarding decisions |
| `RAKSHAK_ISOLATED` | filter | Blocked device rules |
| `RAKSHAK_RATELIMIT` | filter | Rate limiting rules |
| `RAKSHAK_HONEYPOT` | nat | Honeypot redirection rules |

### Default Blocked Ports

| Port | Protocol | Reason |
|------|----------|--------|
| 4444 | TCP | Metasploit default |
| 5555 | TCP | Android ADB |
| 6667 | TCP | IRC botnet |
| 31337 | TCP | Elite backdoor |

## 4.4 Deep Packet Inspection (nfqueue)

Optional DPI inspects packet payloads for malicious patterns:

```python
# Suspicious patterns detected
suspicious_patterns = [
    "/bin/sh",
    "/bin/bash",
    "wget ",
    "curl ",
    "nc -e",
    "chmod 777",
    "rm -rf"
]
```

---

# Part 5: Device Isolation (REAL)

## 5.1 How It Works

When KAAL (AI agent) detects a threat and decides to isolate a device, RAKSHAK **actually blocks traffic** using iptables:

```
KAAL Decision: {"action": "ISOLATE_DEVICE", "target": "192.168.100.50"}

Gateway executes:
iptables -I RAKSHAK_ISOLATED 1 -s 192.168.100.50 -j DROP
iptables -I RAKSHAK_ISOLATED 1 -d 192.168.100.50 -j DROP
```

**Result**: Device can ping the gateway but cannot reach any other device or the Internet.

## 5.2 Isolation Levels

| Level | Behavior |
|-------|----------|
| `FULL` | Block all traffic to/from device |
| `INTERNET_ONLY` | Block Internet, allow LAN |
| `RATE_LIMITED` | Apply rate limiting (10/sec) |
| `HONEYPOT` | Redirect to honeypot |

## 5.3 Automatic Expiration

Isolation can be time-limited:
```python
gateway.isolate_device(
    ip_address="192.168.100.50",
    level=IsolationLevel.FULL,
    reason="Malware detected",
    duration_minutes=60  # Auto-release after 1 hour
)
```

---

# Part 6: Honeypot Redirection (REAL)

## 6.1 How It Works

When an attacker is detected, RAKSHAK can transparently redirect their traffic to a honeypot using NAT:

```
Attacker (192.168.100.99) tries: telnet 192.168.100.11:23 (camera)

KAAL Decision: {"action": "ENGAGE_ATTACKER", "target": "192.168.100.99"}

Gateway executes:
iptables -t nat -I RAKSHAK_HONEYPOT 1 \
    -s 192.168.100.99 \
    -p tcp --dport 23 \
    -j REDIRECT --to-port 2323
```

**Result**: Attacker thinks they connected to the camera but actually talking to our LLM-powered honeypot.

## 6.2 Honeypot with Redirect (One Command)

The deception engine provides a combined deployment:

```python
# Deploy honeypot AND setup NAT redirect
honeypot = deception_engine.deploy_honeypot_with_redirect(
    threat_info={
        "source_ip": "192.168.100.99",
        "target_port": 23,
        "target_device": "wyze_cam"
    },
    protocol="telnet",
    persona="wyze_cam"
)
```

---

# Part 7: The Five Core Components

## 7.1 MAYA - Network Scanner

Discovers and profiles all IoT devices using DHCP leases (gateway mode) or ARP scanning (standalone).

| Feature | Gateway Mode | Standalone Mode |
|---------|--------------|-----------------|
| Discovery | DHCP leases (authoritative) | ARP scanning (best effort) |
| Device Info | Hostname, MAC, IP | MAC, IP only |
| Accuracy | 100% (we assign IPs) | ~80% |

## 7.2 KAAL - Agentic Defender

Dueling DQN neural network that makes autonomous defense decisions:

```
Input: 10-dimensional state vector
       [attack_type, severity, src_port, dst_port, rate,
        duration, known_attacker, device_risk, time, protocol]

Output: One of 5 actions
       0 = MONITOR
       1 = DEPLOY_HONEYPOT
       2 = ISOLATE_DEVICE
       3 = ENGAGE_ATTACKER
       4 = ALERT_USER
```

**Key Difference in Gateway Mode**: Actions are REAL, not simulated.

## 7.3 PRAHARI - LLM Honeypot

Intelligent honeypot powered by Ollama (Mistral 7B):

| Feature | Description |
|---------|-------------|
| Personas | Wyze Cam, TP-Link Router, Samsung TV, Alexa |
| Protocols | Telnet, SSH, HTTP |
| Response | LLM-generated contextual responses |
| Intelligence | All commands captured for analysis |

## 7.4 CHAKRAVYUH - Deception Engine

Multi-layer defense trap inspired by Mahabharata:

| Ring | Function | Gateway Enhancement |
|------|----------|---------------------|
| Detection | Monitor traffic | Real packet inspection |
| Decoys | Fake devices | NAT-redirected honeypots |
| Trap | LLM honeypot | Transparent redirection |
| Intelligence | TTP capture | CCTNS export |

## 7.5 DRISHTI - Dashboard

Real-time web dashboard with Hindi/English support:

- Device listing with risk scores
- Threat timeline
- Active honeypots
- AI decision log
- One-click CCTNS export

---

# Part 8: Installation Guide

## 8.1 Prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y \
    python3-pip \
    python3-venv \
    dnsmasq \
    iptables \
    nmap \
    net-tools

# Install Ollama for LLM
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral:7b
```

## 8.2 Python Setup

```bash
# Clone repository
git clone https://github.com/your-repo/e-raksha.git
cd e-raksha

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install netfilterqueue for DPI (optional)
pip install NetfilterQueue
```

## 8.3 Hardware Setup

1. **Connect USB-to-Ethernet adapter** to Jetson USB 3.0 port
2. **Connect eth0 (built-in)** to ISP modem
3. **Connect eth1 (USB adapter)** to router WAN port
4. **Configure router** as access point (see Part 2.3)

## 8.4 Gateway Setup Script

```bash
# Check prerequisites
sudo ./scripts/setup_gateway.sh --check

# Start gateway mode
sudo ./scripts/setup_gateway.sh --start

# View status
sudo ./scripts/setup_gateway.sh --status

# Stop gateway
sudo ./scripts/setup_gateway.sh --stop
```

---

# Part 9: Running RAKSHAK

## 9.1 Gateway Mode (Default - Production)

```bash
sudo python main.py
```

This is the **recommended mode** for real deployment. Requires:
- Root privileges (sudo)
- Two network interfaces
- Router in AP mode

RAKSHAK will:
1. Check prerequisites
2. Configure LAN interface
3. Enable IP forwarding
4. Setup NAT and firewall
5. Start DHCP server
6. Begin monitoring and defense

## 9.2 Standalone Mode (Testing Only)

```bash
python main.py --standalone
```

For development/testing when you don't have the full hardware setup.

**WARNING**: In standalone mode:
- Device isolation is SIMULATED (traffic still flows)
- Honeypot redirection is SIMULATED (no NAT)
- Useful for testing AI logic but NOT real defense

## 9.3 Simulation Mode

```bash
sudo python main.py --simulate
```

Uses fake devices from config file. Good for demos without real network.

## 9.4 Debug Mode

```bash
sudo python main.py --debug
```

Verbose logging showing all AI decisions and actions.

## 9.5 Command Line Options

| Option | Description |
|--------|-------------|
| `--standalone` | Run without gateway (passive mode) |
| `--simulate` | Use fake devices |
| `--debug` | Enable debug logging |
| `--port 5000` | Dashboard port |
| `--skip-checks` | Skip prerequisite checks (dangerous) |

---

# Part 10: API Reference

## Device Endpoints

### GET /api/devices
```json
{
  "success": true,
  "data": [
    {
      "ip": "192.168.100.10",
      "mac": "F0:27:2D:XX:XX:XX",
      "hostname": "amazon-echo",
      "risk_score": 35,
      "status": "active",
      "isolation_status": null
    }
  ]
}
```

### GET /api/status
```json
{
  "running": true,
  "gateway_mode": true,
  "devices_count": 5,
  "threats_count": 12,
  "honeypots_active": 2,
  "isolated_devices": 1
}
```

## Honeypot Endpoints

### POST /api/honeypots/deploy
```json
// Request
{
  "protocol": "telnet",
  "persona": "wyze_cam"
}

// Response
{
  "success": true,
  "data": {
    "id": "HP-0001",
    "port": 2323,
    "has_redirection": false
  }
}
```

### POST /api/honeypots/deploy-with-redirect
```json
// Request
{
  "source_ip": "192.168.100.99",
  "target_port": 23,
  "protocol": "telnet",
  "persona": "wyze_cam"
}

// Response (Gateway Mode)
{
  "success": true,
  "data": {
    "id": "HP-0001",
    "port": 2323,
    "has_redirection": true,
    "redirect_source": "192.168.100.99",
    "redirect_original_port": 23
  }
}
```

## Gateway Endpoints

### POST /api/gateway/isolate
```json
// Request
{
  "ip_address": "192.168.100.50",
  "level": "full",
  "reason": "Malware detected",
  "duration_minutes": 60
}

// Response
{
  "success": true,
  "message": "Device 192.168.100.50 isolated via iptables"
}
```

### DELETE /api/gateway/isolate/{ip}
```json
{
  "success": true,
  "message": "Device 192.168.100.50 unisolated"
}
```

### GET /api/gateway/status
```json
{
  "is_gateway_mode": true,
  "wan_interface": "eth0",
  "lan_interface": "eth1",
  "lan_ip": "192.168.100.1",
  "dhcp_leases": 5,
  "isolated_devices": ["192.168.100.50"],
  "active_redirections": 1
}
```

---

# Part 11: Troubleshooting

## Gateway Issues

### "Must run as root"
```bash
sudo python main.py
```

### "Need 2 ethernet interfaces"
- Connect USB-to-Ethernet adapter
- Check with: `ip link show`
- Look for: eth0, eth1, enx*, enp*s*u*

### "Failed to start DHCP server"
```bash
# Check dnsmasq status
sudo systemctl status dnsmasq

# Check for port conflicts
sudo lsof -i :53
sudo lsof -i :67
```

### "No devices discovered"
- Ensure router is in AP mode (not routing)
- Check router is connected to eth1 (not eth0)
- Verify DHCP is working: `cat /var/lib/misc/dnsmasq.leases`

## Network Issues

### IoT devices can't reach Internet
```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# Check NAT rules
iptables -t nat -L -n -v

# Check WAN has IP
ip addr show eth0
```

### Devices not getting DHCP
```bash
# Check dnsmasq is running
systemctl status dnsmasq

# Check config
cat /etc/dnsmasq.d/rakshak.conf

# Restart dnsmasq
sudo systemctl restart dnsmasq
```

## Honeypot Issues

### "Port already in use"
```bash
lsof -i :2323
kill -9 <PID>
```

### LLM not responding
```bash
# Check Ollama
ollama list
ollama serve  # If not running
```

---

# Part 12: Passive vs Inline Comparison

| Feature | Passive Monitoring | RAKSHAK Inline Gateway |
|---------|-------------------|------------------------|
| **Traffic Control** | None | Full |
| **Device Isolation** | Flag only | Real iptables DROP |
| **Traffic Blocking** | Impossible | Real firewall |
| **Honeypot Redirect** | Impossible | Real NAT redirect |
| **DHCP Server** | No | Yes (authoritative) |
| **Device Discovery** | ARP scan (unreliable) | DHCP leases (100% accurate) |
| **Autonomous Defense** | Simulated | Real enforcement |
| **Hardware Required** | Single NIC | Two NICs |
| **Root Required** | For ARP only | Yes (full) |
| **Router Changes** | None | AP mode required |

---

# Part 13: Project Structure

```
e-raksha/
├── main.py                    # Entry point (RakshakOrchestrator)
├── requirements.txt           # Python dependencies
├── DOCUMENTATION.md           # This file
├── README.md                  # Quick start
│
├── config/
│   └── config.yaml           # Configuration (gateway, AI, honeypots)
│
├── core/
│   ├── __init__.py
│   ├── gateway.py            # Inline gateway (NAT, DHCP, Firewall)
│   ├── packet_filter.py      # Deep packet inspection
│   ├── network_scanner.py    # MAYA - Device discovery
│   ├── agentic_defender.py   # KAAL - RL Agent
│   ├── llm_honeypot.py       # PRAHARI - LLM responses
│   ├── deception_engine.py   # CHAKRAVYUH - Honeypots
│   └── threat_logger.py      # Logging, CCTNS export
│
├── api/
│   ├── __init__.py
│   └── app.py                # Flask REST API
│
├── dashboard/
│   ├── templates/index.html
│   └── static/
│
├── scripts/
│   ├── setup_gateway.sh      # Gateway setup script
│   └── demo_attack.py        # Attack simulator
│
├── data/
│   ├── logs/
│   ├── threats/
│   └── dns_blocklist.txt
│
└── models/                   # DQN model weights
```

---

# Part 14: Security Considerations

## 14.1 This is Defensive Security

RAKSHAK is a **defensive security tool** designed for:
- Protecting home IoT networks
- Authorized security testing
- Research and education
- CTF competitions

## 14.2 Access Control

- Runs on your own network only
- Requires physical access to hardware
- Root privileges controlled by system owner

## 14.3 Data Privacy

- All processing is local (edge-based)
- No cloud dependencies
- No telemetry or data collection
- Logs stored locally only

---

# Document Info

- **Version**: 2.0.0 (Inline Gateway Architecture)
- **Updated**: 2026-01-15
- **Author**: Team RAKSHAK
- **License**: MIT

---

**RAKSHAK** - *Detect. Deceive. Defend. Autonomously.*

*"Har Ghar Ki Cyber Suraksha"*

**Now with REAL traffic control via inline gateway architecture.**

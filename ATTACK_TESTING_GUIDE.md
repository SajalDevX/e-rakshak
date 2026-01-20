# ESP32-CAM Attack Testing Guide

## Overview

This guide explains how to test RAKSHAK's threat detection and automatic isolation capabilities using the ESP32-CAM attack simulation script.

## Target Device

**ESP32-CAM Specifications:**
- **MAC Address:** `94:B9:7E:FA:E3:58`
- **IP Address:** `10.42.0.103` (or `10.42.0.136` for the other camera)
- **Service:** HTTP Camera Stream on port 80
- **Manufacturer:** Espressif
- **Type:** esp32_cam

## Attack Script

Location: `tests/attack_esp32cam.py`

### Prerequisites

1. **RAKSHAK must be running:**
   ```bash
   ./start_monitoring.sh
   ```

2. **ESP32-CAM must be powered on and connected:**
   - Upload the ESP32-CAM code to the device
   - Ensure it connects to WiFi: `TP-Link_695A`
   - Verify it appears in RAKSHAK dashboard at `http://localhost:5000`

3. **Required tools:**
   - Python 3
   - nmap (already installed)
   - requests library (install with: `pip install requests`)

## Usage

### 1. Basic Attack Test (Non-Root)

```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
python3 tests/attack_esp32cam.py
```

This will run:
- TCP Connect Scan (noisy, easily detected)
- Repeated HTTP access (50 unauthorized stream requests)
- Banner grabbing
- Connection flood

### 2. Full Attack Test (Root - Recommended)

```bash
sudo python3 tests/attack_esp32cam.py
```

This adds:
- SYN Stealth Scan (more stealthy, harder to detect)
- Aggressive OS/Service detection

### 3. Custom Attacks

Run specific attack types:
```bash
# Only port scanning and HTTP flood
python3 tests/attack_esp32cam.py --attacks tcp_scan,http_flood

# Only banner grabbing
python3 tests/attack_esp32cam.py --attacks banner_grab

# Different target IP
python3 tests/attack_esp32cam.py --target 10.42.0.136
```

### 4. Quick Test Mode

For faster testing with fewer requests:
```bash
python3 tests/attack_esp32cam.py --quick
```

## Attack Types

| Attack | Detection Difficulty | Expected RAKSHAK Response |
|--------|---------------------|---------------------------|
| **TCP Connect Scan** | Easy | PortScanDetector triggers immediately |
| **SYN Stealth Scan** | Medium | PortScanDetector may detect with threshold |
| **Service Detection** | Medium | Multiple connection attempts flagged |
| **HTTP Flood** | Easy | Repeated unauthorized access detected |
| **Banner Grabbing** | Medium | Suspicious probing behavior |
| **Connection Flood** | Easy | Rapid connection attempts trigger alert |

## Expected RAKSHAK Behavior

### Detection Sequence

1. **PortScanDetector** (core/port_scan_detector.py):
   - Detects multiple connection attempts to different ports
   - Threshold: 5+ ports in 60 seconds triggers alert
   - Creates threat log entry

2. **AgenticDefender** (KAAL AI):
   - Analyzes attack pattern
   - Calculates threat severity
   - Decides on response action

3. **ResponseDecisionEngine**:
   - Evaluates threat level
   - If auto_exec_threshold met (severity >= 4)
   - Executes automatic isolation

4. **Gateway Isolation**:
   - Device added to iptables DROP rules
   - All traffic from/to device blocked
   - Device status updated to "isolated"

### Logs to Monitor

While the attack is running, monitor RAKSHAK logs:

```bash
# Main log
tail -f data/logs/rakshak_*.log | grep -E "port.*scan|isolation|threat|ESP32|10.42.0.103"

# Threat log
tail -f data/threats/*.json

# System journal (for iptables)
sudo journalctl -f | grep "RAKSHAK"
```

### Dashboard Monitoring

Open dashboard: `http://localhost:5000`

Watch for:
1. **Device status change** from "active" → "isolated"
2. **Risk score increase** (should go from 25% → 60%+)
3. **Threat alerts** appearing in events feed
4. **Red "Isolated" status badge** on device

## Verification

### 1. Check Device Status via API

```bash
curl http://localhost:5000/api/devices/10.42.0.103 | jq '.data | {status, risk_score, risk_factors}'
```

Expected after attack:
```json
{
  "status": "isolated",
  "risk_score": 75,
  "risk_factors": [
    "Port scan detected",
    "Unauthorized access attempts",
    "DIY camera (ESP32) - often insecure"
  ]
}
```

### 2. Check Firewall Rules

```bash
sudo iptables -L RAKSHAK_ISOLATED -v -n
```

Should show DROP rule for 10.42.0.103:
```
Chain RAKSHAK_ISOLATED (1 references)
 pkts bytes target     prot opt in     out     source          destination
    0     0 DROP       all  --  *      *       10.42.0.103     0.0.0.0/0
```

### 3. Verify Camera Inaccessible

After isolation, these should fail:
```bash
# Ping should timeout
ping -c 3 10.42.0.103

# HTTP should fail
curl http://10.42.0.103/

# Port scan should show all filtered
nmap 10.42.0.103
```

## Manual Recovery

If you need to un-isolate the device for further testing:

### Via Dashboard UI
1. Go to `http://localhost:5000`
2. Find device DEV-0007 or DEV-0010
3. Click "Un-isolate" button

### Via API
```bash
curl -X POST http://localhost:5000/api/devices/10.42.0.103/unisolate
```

### Manual Firewall Clear
```bash
sudo iptables -D RAKSHAK_ISOLATED -s 10.42.0.103 -j DROP
```

## Attack Script Output

The script provides real-time feedback:

```
╔══════════════════════════════════════════════════════════════════════════╗
║                   ESP32-CAM ATTACK SIMULATION                            ║
║                   Testing RAKSHAK Detection                              ║
╚══════════════════════════════════════════════════════════════════════════╝

Target Device:  ESP32-CAM (Espressif)
MAC Address:   94:B9:7E:FA:E3:58
IP Address:    10.42.0.103
Service:       HTTP Camera Stream (Port 80)

⚠️  This is a controlled security test on authorized devices only

Initial device check...
  Device Status: active
  Risk Score: 25%
  Isolated: False

✓ Device is reachable. Starting attack sequence...

============================================================================
ATTACK 1: TCP Connect Scan (Noisy, Easily Detected)
============================================================================

[03:45:12] TCP Connect Scan               STARTING   nmap -sT -p 1-1000 10.42.0.103
[03:45:25] TCP Connect Scan               SUCCESS    Found 1 open port(s)

Open Ports:
  80/tcp open  http

  Device still active (Risk: 35%)

============================================================================
ATTACK 4: Repeated Unauthorized HTTP Access (50 requests)
============================================================================

[03:45:30] HTTP Access Attack             STARTING   Attempting 50 unauthorized stream accesses
  [1/50] Stream accessed (1024 bytes)
  [11/50] Stream accessed (1024 bytes)
  [21/50] Failed: Connection refused

🚨 [03:45:42] DEVICE ISOLATED BY RAKSHAK!
============================================================================
  Status: isolated
  Risk Score: 75%
  Duration: 30s since attack start

🎯 SUCCESS! Device isolated after http_flood
============================================================================
```

## Testing Different Scenarios

### Scenario 1: Stealth Attack
Test if RAKSHAK detects slower, more careful attacks:
```bash
# Modify script to add longer delays between requests
# Should still be detected but may take longer
```

### Scenario 2: Multiple Attackers
Run attack from multiple machines simultaneously:
```bash
# Machine 1
python3 tests/attack_esp32cam.py --attacks tcp_scan

# Machine 2 (simultaneously)
python3 tests/attack_esp32cam.py --attacks http_flood
```

### Scenario 3: Legitimate vs Malicious Traffic
Access camera normally while attack is running:
```bash
# Normal access
curl http://10.42.0.103/

# Attack in background
python3 tests/attack_esp32cam.py &
```

## Troubleshooting

### Device Not Getting Isolated

**Check:**
1. PortScanDetector is enabled in config
2. ResponseDecisionEngine auto_exec_threshold is not too high
3. Check logs for detection: `grep "port scan" data/logs/rakshak_*.log`
4. Verify RAKSHAK is in gateway mode (not standalone)

### Attack Script Fails

**Common issues:**
- nmap not installed: `sudo apt install nmap`
- Target unreachable: Verify ESP32-CAM IP with `ping 10.42.0.103`
- Permissions: Run with `sudo` for SYN scan
- RAKSHAK not running: Start with `./start_monitoring.sh`

### False Positives

If legitimate devices are getting isolated:
1. Adjust thresholds in `core/port_scan_detector.py`
2. Whitelist trusted IPs
3. Review auto_exec_threshold in config

## Success Criteria

✅ **Attack detected within 30 seconds**
✅ **Device automatically isolated**
✅ **Threat logged in database**
✅ **Dashboard shows isolation status**
✅ **Firewall rules applied**
✅ **Camera stream inaccessible after isolation**

## Demo Flow for Presentation

1. **Show dashboard** - Device active, low risk score
2. **Run attack script** - `sudo python3 tests/attack_esp32cam.py`
3. **Show real-time logs** - Detection in progress
4. **Dashboard update** - Status changes to isolated
5. **Verify isolation** - Camera unreachable
6. **Show threat log** - Complete attack chain documented
7. **Demonstrate recovery** - Un-isolate via dashboard

## Notes

- This script performs **real network attacks** - use only on authorized devices
- ESP32-CAM should be on an isolated test network
- Do not run against production devices
- Attacks will be logged in RAKSHAK database for analysis
- Can be used for hackathon demos and security testing

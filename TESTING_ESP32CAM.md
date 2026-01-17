# Testing e-raksha with ESP32-CAM (10.42.0.103)

## Overview

This guide explains how to test e-raksha's detection and response capabilities using your vulnerable ESP32-CAM at `10.42.0.103`.

## What We've Implemented

### Phase 3: Enhanced Detection & Response

1. **Response Decision Engine** - 7-level graduated response:
   - Level 0: MONITOR
   - Level 1: ALERT
   - Level 2: RATE_LIMIT
   - Level 3: DEPLOY_HONEYPOT
   - Level 4: QUARANTINE
   - Level 5: ISOLATE
   - Level 6: FULL_BLOCK

2. **Port Scan Detector** - Detects:
   - SYN scans (10+ ports/minute)
   - Network sweeps (5+ targets in 5 min)
   - UDP scans (20+ rapid probes)
   - Stealth scans (FIN/NULL/XMAS)

3. **ARP Spoofing Detector** - Detects:
   - MAC address changes
   - Gratuitous ARP flooding

4. **ESP32-CAM Device Identification**:
   - Added 10 Espressif MAC OUI prefixes
   - Device type: `esp32_cam`
   - Risk score: 60+ (high risk)
   - Risk factors: "DIY camera (ESP32) - often insecure"

---

## Pre-Test Setup

### 1. Flash ESP32-CAM

Upload the code you provided:
```bash
# Using Arduino IDE or PlatformIO
# WiFi credentials: TP-Link_695A / 35717775
# Camera will start HTTP server on port 80
```

### 2. Start e-raksha in Gateway Mode

```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
sudo python main.py
```

Expected output:
```
====================================================================
         RAKSHAK INLINE SECURITY GATEWAY MODE
====================================================================

  WAN Interface: eth0
  LAN Interface: eth1
  Bridge Mode:   ENABLED (br0)
  Gateway IP:    10.42.0.1
  Jetson:        True

Phase 3 detection systems initialized (Response Engine, ARP Spoofing, Port Scan)
Phase 3 detectors connected to packet filter
RAKSHAK Started in GATEWAY mode
Dashboard: http://localhost:5000
```

### 3. Verify ESP32-CAM Connection

Check the dashboard at `http://10.42.0.1:5000`:

**Expected Device Entry:**
```
IP: 10.42.0.103
MAC: XX:XX:XX:XX:XX:XX (Espressif OUI)
Device Type: esp32_cam
Manufacturer: Espressif
Risk Score: 60-75 (HIGH)
Risk Factors:
  - High-risk device type
  - DIY camera (ESP32) - often insecure
  - HTTP service exposed (port 80)
Zone: iot (if auto-assigned) or guest (default)
Status: active
```

**If showing as "unknown":**
- Check MAC address starts with one of these prefixes:
  - 24:0A:C4, 30:AE:A4, 3C:71:BF, 7C:9E:BD, A4:CF:12
  - B4:E6:2E, CC:50:E3, DC:4F:22, EC:FA:BC, F4:CF:A2
- If not, e-raksha will use hostname/service detection
- Camera will still be detected as high-risk due to HTTP service

---

## Attack Testing

### Method 1: Automated Test Script (Recommended)

Run the provided attack simulation script:

```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
python3 tests/test_esp32cam_attacks.py
```

This will automatically run:
1. Port scan (10 ports in <5s)
2. HTTP enumeration (8 endpoints)
3. Repeated unauthorized stream access (15 requests)
4. Simulated exploit attempts (4 payloads)

**Expected e-raksha Response:**

```
Test 1: Port Scan
→ Response Level: RATE_LIMIT (Level 2)
→ Severity: MEDIUM
→ Threat logged, rate limiting applied

Test 2: HTTP Enumeration
→ Response Level: DEPLOY_HONEYPOT (Level 3)
→ Severity: MEDIUM
→ Honeypot deployed on port 80

Test 3: Repeat Offender
→ Response Level: QUARANTINE (Level 4) - ESCALATED
→ Severity: HIGH
→ Device moved to quarantine zone

Test 4: Exploit Simulation
→ Response Level: ISOLATE (Level 5)
→ Severity: CRITICAL
→ Device fully isolated from network
```

### Method 2: Manual Testing with nmap

From another device on the network:

```bash
# Test 1: Port Scan
nmap -sS 10.42.0.103

# Expected Detection:
# - Port scan detected in <5 seconds
# - Source IP flagged for rate limiting
# - Dashboard shows "port_scan" threat

# Test 2: Aggressive Scan
nmap -A -T4 10.42.0.103

# Expected Detection:
# - Multiple scan types detected
# - Escalated response (DEPLOY_HONEYPOT)
# - Honeypot activated
```

### Method 3: Manual HTTP Testing

```bash
# Test unauthorized stream access
for i in {1..20}; do
  curl -s http://10.42.0.103/stream --max-time 1 > /dev/null
  echo "Request $i sent"
  sleep 0.5
done

# Expected Detection:
# - Repeat offender pattern recognized
# - Response escalated to QUARANTINE
# - Device isolated after 10-15 requests
```

---

## Expected e-raksha Behavior

### Detection Timeline

| Time | Event | Detection | Response Level | Action |
|------|-------|-----------|----------------|--------|
| T+0s | Port scan starts | Port Scan Detector | RATE_LIMIT (L2) | Log + Alert |
| T+10s | HTTP enum starts | High request rate | DEPLOY_HONEYPOT (L3) | Deploy honeypot |
| T+30s | Repeat access | Repeat offender | QUARANTINE (L4) | Move to quarantine zone |
| T+45s | Exploit attempt | IDS + Malicious pattern | ISOLATE (L5) | Full network isolation |
| T+60s | Continued attacks | Confirmed breach | FULL_BLOCK (L6) | Permanent block |

### Dashboard Indicators

**Threats Tab:**
```
[MEDIUM] Port Scan - 10.42.0.103
  - Scanned 10 ports in 4.2s
  - Action: RATE_LIMIT
  - Timestamp: 2026-01-18 02:30:15

[MEDIUM] HTTP Enumeration - 10.42.0.103
  - 8 endpoints probed rapidly
  - Action: DEPLOY_HONEYPOT
  - Timestamp: 2026-01-18 02:30:28

[HIGH] Repeat Offender - 10.42.0.103 (esp32_cam)
  - 15 unauthorized stream accesses
  - Action: QUARANTINE
  - Timestamp: 2026-01-18 02:30:42

[CRITICAL] Exploit Attempt - 10.42.0.103
  - Malicious payload detected
  - Action: ISOLATE
  - Timestamp: 2026-01-18 02:30:55
```

**Device Status:**
```
10.42.0.103 (esp32_cam)
Status: isolated
Risk Score: 95 (CRITICAL)
Zone: quarantine
Last Seen: 2026-01-18 02:30:55
Isolation Reason: Multiple security violations
```

### Logs to Monitor

```bash
# Real-time threat detection
tail -f data/logs/rakshak.log | grep -E "Response Engine|Port Scan|ISOLATE"

# Expected log entries:
# [INFO] Port Scan Detector: SYN scan from 10.42.0.103
# [INFO] Response Engine: RATE_LIMIT - apply_rate_limit
# [INFO] Port Scan Detector: 10 ports scanned in 4.2s
# [WARNING] Response Engine escalating to: DEPLOY_HONEYPOT
# [WARNING] Repeat offender detected: 10.42.0.103
# [WARNING] Response Engine escalating to: QUARANTINE
# [CRITICAL] IDS detected malicious payload from 10.42.0.103
# [CRITICAL] Response Engine escalating to: ISOLATE
# [INFO] Device 10.42.0.103 ISOLATED via gateway (REAL)
```

---

## Verification

### 1. Check Isolation Status

```bash
# From ESP32-CAM (if you have serial console)
# Try to ping gateway:
ping 10.42.0.1
# Expected: Network unreachable or timeout

# From attacker machine
# Try to access camera:
curl http://10.42.0.103
# Expected: Connection timeout or refused
```

### 2. Check iptables Rules

```bash
sudo iptables -L -v -n | grep 10.42.0.103

# Expected output:
# DROP       all  --  *      *       10.42.0.103          0.0.0.0/0
# DROP       all  --  *      *       0.0.0.0/0            10.42.0.103
```

### 3. Query Database

```bash
sqlite3 data/rakshak.db

SELECT * FROM devices WHERE ip = '10.42.0.103';
# Expected: status='isolated', risk_score>=90

SELECT * FROM threats WHERE source_ip = '10.42.0.103' ORDER BY timestamp DESC LIMIT 5;
# Should show: port_scan, repeat_access, exploit_attempt

SELECT * FROM port_scan_events WHERE scanner_ip = '10.42.0.103';
# Should show scan details

.exit
```

### 4. Check Response Engine Statistics

Add this to your Python console:

```python
# Connect to running e-raksha
import sys
sys.path.insert(0, '/home/sajal/Desktop/Hackathons/e-raksha')

from core.response_decision_engine import ResponseDecisionEngine
from core.threat_logger import ThreatLogger
import yaml

# Load config
with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

# Create instances
threat_logger = ThreatLogger(config)
response_engine = ResponseDecisionEngine(config)

# Check stats
stats = response_engine.get_response_statistics()
print(stats)

# Expected output:
# {
#   'total_responses': 4,
#   'total_devices': 1,
#   'responses_by_level': {
#     'MONITOR': 0,
#     'ALERT': 0,
#     'RATE_LIMIT': 1,
#     'DEPLOY_HONEYPOT': 1,
#     'QUARANTINE': 1,
#     'ISOLATE': 1,
#     'FULL_BLOCK': 0
#   },
#   'repeat_offenders': 1
# }
```

---

## Troubleshooting

### Issue: ESP32-CAM Shows as "unknown"

**Cause:** MAC OUI not in database or hostname not recognized

**Fix:**
```bash
# Check MAC address
arp -a | grep 10.42.0.103

# If MAC doesn't match Espressif OUIs, manually update:
sqlite3 data/rakshak.db
UPDATE devices SET device_type='esp32_cam', manufacturer='Espressif' WHERE ip='10.42.0.103';
.exit

# Restart e-raksha
```

### Issue: Port Scan Not Detected

**Cause:** Packet filter not running or nfqueue not available

**Check:**
```bash
# Verify nfqueue rule
sudo iptables -L -v -n | grep NFQUEUE

# Check logs
tail -f data/logs/rakshak.log | grep "Port Scan"

# If no detection, check if packet filter is running:
ps aux | grep python | grep rakshak
```

**Fix:**
```bash
# Ensure netfilterqueue is installed
pip install NetfilterQueue

# Run e-raksha with root
sudo python main.py
```

### Issue: Device Not Isolated

**Cause:** Gateway mode not active or isolation failed

**Check:**
```bash
# Verify gateway mode
sudo iptables -L -v -n | grep FORWARD

# Check isolation logs
grep "ISOLATE" data/logs/rakshak.log
```

**Fix:**
```bash
# Ensure running in gateway mode (not standalone)
sudo python main.py  # WITHOUT --standalone flag

# Manually isolate if needed:
# From e-raksha console
from core.gateway import IsolationLevel
orchestrator.gateway.isolate_device('10.42.0.103', IsolationLevel.FULL, 'Manual test')
```

### Issue: No Threats Showing in Dashboard

**Cause:** Threat processor not running or IDS classifier missing

**Check:**
```bash
# Check threat processor thread
grep "ThreatProcessor" data/logs/rakshak.log

# Check if threats are being logged
sqlite3 data/rakshak.db
SELECT COUNT(*) FROM threats;
.exit
```

---

## Success Criteria

### ✅ Complete Success

- [ ] ESP32-CAM identified as `esp32_cam` device type
- [ ] Risk score: 60-75 (HIGH)
- [ ] Port scan detected within 5 seconds
- [ ] Response escalated from RATE_LIMIT → DEPLOY_HONEYPOT → QUARANTINE → ISOLATE
- [ ] Device status changed to "isolated" in dashboard
- [ ] Cannot access ESP32-CAM from network after isolation
- [ ] All threats logged in database
- [ ] iptables rules block 10.42.0.103 traffic

### ⚠️ Partial Success

- [ ] Device detected but type="unknown"
- [ ] Port scan detected but no escalation
- [ ] Threats logged but device not isolated
- [ ] Dashboard shows alerts but iptables rules missing

### ❌ Failure

- Device not detected at all
- No threats logged despite attacks
- Isolation command fails
- Dashboard not accessible

---

## Next Steps

1. **Record Test Results:**
   - Screenshot dashboard before/after attacks
   - Export threat logs: `sqlite3 data/rakshak.db ".dump threats" > test_results.sql`
   - Save iptables rules: `sudo iptables-save > iptables_test.txt`

2. **Analyze Response Times:**
   - Time to first detection
   - Time to isolation
   - False positive rate

3. **Test Recovery:**
   ```bash
   # Unisolate device via dashboard or:
   orchestrator.gateway.unisolate_device('10.42.0.103')

   # Verify recovery
   curl http://10.42.0.103
   ```

4. **Test with Real IoT Devices:**
   - Repeat with Wyze Cam, TP-Link plug, etc.
   - Compare detection accuracy
   - Validate risk scoring

---

## Summary

This integration completes **Phase 3** of the e-raksha enhancement plan:

✅ Response Decision Engine (7-level escalation)
✅ Port Scan Detector (SYN/UDP/Stealth)
✅ ARP Spoofing Detector
✅ ESP32-CAM Device Identification
✅ Packet Filter Integration
✅ Automated Testing Script

**Your ESP32-CAM at 10.42.0.103 will be:**
1. Automatically identified as high-risk IoT device
2. Monitored by port scan and ARP detectors
3. Subject to graduated response escalation
4. Isolated if repeat violations or exploit attempts detected

**Result:** Real-world demonstration of autonomous IoT threat response! 🎯

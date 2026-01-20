# DDoS Attack Testing Guide

## Overview

The attack script now includes **4 DDoS/DoS attack types** that will trigger RAKSHAK's IDS classifier to detect and automatically isolate the attacking device.

---

## ✅ Model Capabilities

The pre-trained ML model (CICIDS2017 dataset) can detect these attack types:

| Attack Type | Severity | Action | Detection Method |
|-------------|----------|--------|------------------|
| **DDoS** | CRITICAL | ISOLATE_DEVICE | IDS Classifier |
| **DoS Hulk** | HIGH | ISOLATE_DEVICE | IDS Classifier |
| **DoS GoldenEye** | HIGH | ISOLATE_DEVICE | IDS Classifier |
| **DoS slowloris** | MEDIUM | ISOLATE_DEVICE | IDS Classifier |
| **DoS Slowhttptest** | MEDIUM | ISOLATE_DEVICE | IDS Classifier |

---

## 🚀 New DDoS Attack Methods

### 1. **HTTP Flood DDoS** (`ddos_http`)

**What it does:**
- Spawns 10 worker threads
- Each thread sends rapid HTTP GET requests
- Runs for 30 seconds
- Generates 100-500 requests/second

**Command:**
```bash
python3 tests/attack_esp32cam.py --attacks ddos_http
```

**How it works:**
```python
# 10 threads × 30 seconds × ~10 req/s = ~3000 total requests
def attack_http_flood(duration=30, threads=10):
    - Create 10 worker threads
    - Each sends GET requests as fast as possible
    - Random User-Agent headers
    - Monitor total request count in real-time
```

**Expected IDS Detection:**
- Traffic pattern matches "DDoS" signature
- High packet rate with same source IP
- Severity: **CRITICAL**
- Action: **IMMEDIATE ISOLATION**

---

### 2. **SYN Flood DoS** (`ddos_syn`)

**What it does:**
- Sends 500 SYN packets without completing handshake
- Exhausts server connection queue
- Uses random source ports
- **Requires root privileges**

**Command:**
```bash
sudo python3 tests/attack_esp32cam.py --attacks ddos_syn
```

**How it works:**
```python
# Uses hping3 or scapy to send raw packets
def attack_syn_flood(count=500):
    - Create TCP SYN packets
    - Don't send ACK (half-open connections)
    - Random source ports to avoid filtering
    - Server connection table fills up
```

**Tools used:**
1. **hping3** (preferred): `hping3 -S -p 80 --flood --rand-source`
2. **scapy** (fallback): Creates raw IP/TCP packets

**Expected IDS Detection:**
- High SYN rate without ACK responses
- Pattern matches "DoS" signatures
- Severity: **HIGH**
- Action: **ISOLATE_DEVICE**

---

### 3. **Slowloris DoS** (`slowloris`)

**What it does:**
- Opens 200 slow HTTP connections
- Sends incomplete headers to keep connections alive
- Exhausts web server connection limit
- Runs for 60 seconds

**Command:**
```bash
python3 tests/attack_esp32cam.py --attacks slowloris
```

**How it works:**
```python
def attack_slowloris(duration=60, connections=200):
    - Open 200 TCP connections
    - Send partial HTTP headers:
        GET / HTTP/1.1\r\n
        Host: target\r\n
        User-Agent: ...\r\n
        # Don't send final \r\n
    - Keep alive by sending random headers every 10s
    - Server can't close incomplete requests
```

**Expected IDS Detection:**
- Many long-lived connections from same IP
- Low bandwidth but high connection count
- Pattern matches "DoS slowloris" signature
- Severity: **MEDIUM**
- Action: **ISOLATE_DEVICE**

---

### 4. **UDP Flood** (`udp_flood`)

**What it does:**
- Sends 1000 UDP packets (1KB each)
- Random destination ports (1024-65535)
- Overwhelms network processing
- Very fast transmission

**Command:**
```bash
python3 tests/attack_esp32cam.py --attacks udp_flood
```

**How it works:**
```python
def attack_udp_flood(count=1000, packet_size=1024):
    - Create UDP socket
    - Send 1KB payload to random ports
    - Target processes ICMP "port unreachable"
    - Wastes CPU/bandwidth resources
```

**Expected IDS Detection:**
- High UDP packet rate
- Random destination ports
- Pattern matches "UDP Flood" signature
- Severity: **MEDIUM-HIGH**
- Action: **ISOLATE_DEVICE**

---

## 📊 Detection Pipeline

When DDoS attacks are executed:

```
┌─────────────────────┐
│  Attack Script      │
│  (10.42.0.X)       │
└──────────┬──────────┘
           │
           │ 1. Send DDoS traffic
           ↓
┌─────────────────────┐
│  NFQueue/PacketFilter│ ← Captures every packet
└──────────┬──────────┘
           │
           │ 2. Extract flow features
           ↓
┌─────────────────────┐
│  IDS Classifier     │ ← Pre-trained ML model
│  (CICIDS2017)      │    - Analyze 78 features
└──────────┬──────────┘    - Classify attack type
           │
           │ 3. Prediction: "DDoS" (confidence: 0.95)
           ↓
┌─────────────────────┐
│  Threat Logger      │ ← Log attack details
└──────────┬──────────┘
           │
           │ 4. Create threat record
           ↓
┌─────────────────────┐
│  KAAL AI Defender   │ ← Agentic AI evaluation
│  (AgenticDefender) │    - Analyze context
└──────────┬──────────┘    - Assess severity
           │
           │ 5. Threat assessment
           ↓
┌─────────────────────┐
│ Response Engine     │ ← Decide action
│ (Decision Engine)  │    - severity >= 4
└──────────┬──────────┘    - auto_exec enabled
           │
           │ 6. Execute: ISOLATE_DEVICE
           ↓
┌─────────────────────┐
│  Gateway Isolation  │ ← Apply iptables rules
│  (iptables DROP)   │
└─────────────────────┘
           │
           │ 7. Device blocked
           ↓
    [Attack stopped]
```

---

## 🎯 Usage Examples

### **Example 1: Quick DDoS Test**
```bash
# Run HTTP Flood only (no root needed)
python3 tests/attack_esp32cam.py --attacks ddos_http

# Expected timeline:
# [0s]   Attack starts, 10 threads spawned
# [10s]  ~1000 requests sent
# [15s]  IDS detects DDoS pattern
# [20s]  KAAL evaluates threat (severity: CRITICAL)
# [25s]  Device ISOLATED
# [30s]  Attack ends, device unreachable
```

### **Example 2: Full DDoS Suite** (Root)
```bash
# Run all DDoS attacks
sudo python3 tests/attack_esp32cam.py --attacks ddos_http,ddos_syn,slowloris,udp_flood

# Expected: Isolation within first attack
```

### **Example 3: Default Sequence**
```bash
# Default includes port scan + DDoS
python3 tests/attack_esp32cam.py

# Sequence:
# 1. TCP scan (port scan detector)
# 2. HTTP flood (repeated access)
# 3. DDoS HTTP (IDS classifier triggers)
# 4. Slowloris (if not isolated yet)
```

### **Example 4: Slowloris Only**
```bash
# Test slow DoS attack
python3 tests/attack_esp32cam.py --attacks slowloris

# Opens 200 slow connections
# Maintains them for 60 seconds
# Detection: ~20-30 seconds
```

---

## 📈 Expected Results

### **Before Attack:**
```
Device Status: active
Risk Score: 25%
Isolated: False
```

### **During DDoS Attack:**
```
[+] HTTP Flood DDoS started (10 threads)
[10s] 1234 requests sent (123 req/s)
[15s] IDS: DDoS detected (confidence: 0.94)
[18s] KAAL: Threat severity = CRITICAL (score: 9/10)
[20s] Response Engine: Executing ISOLATE_DEVICE
[22s] Gateway: iptables DROP rule applied
```

### **After Isolation:**
```
Device Status: isolated
Risk Score: 95%
Isolated: True

✅ RAKSHAK SUCCESSFULLY DETECTED AND ISOLATED THE DEVICE!
```

---

## 🔬 IDS Model Features

The IDS classifier analyzes **78 network flow features** including:

**Flow Statistics:**
- Packet count, byte count
- Flow duration
- Packets per second
- Bytes per second

**Protocol Features:**
- TCP flags distribution
- Header lengths
- Window sizes
- Sequence numbers

**Timing Features:**
- Inter-arrival times (mean, std, min, max)
- Flow active/idle times
- Subflow durations

**DDoS-Specific Indicators:**
- High packet rate from single source
- Many connections to same destination
- Unusual flag combinations
- Abnormal flow durations

---

## ⚠️ Important Notes

### **No Reinforcement Learning**
- The model does **NOT** retrain in real-time
- It uses a **pre-trained** model from CICIDS2017 dataset
- Detection is based on **pattern matching**, not learning

### **Why DDoS is Detected:**
1. Attack patterns match training data signatures
2. Flow statistics fall into "DDoS" decision boundaries
3. Model confidence typically >0.85 for clear attacks

### **Root Privileges:**
- **Required for:** `ddos_syn`, `udp_flood` (raw packet sending)
- **Not required for:** `ddos_http`, `slowloris` (application layer)

### **ESP32-CAM Limitations:**
- Small device with limited resources
- May crash under heavy DDoS
- Slowloris most effective (low bandwidth, high impact)
- SYN flood may overwhelm connection queue

---

## 🛡️ Defense Mechanisms

When DDoS is detected, RAKSHAK applies:

1. **iptables DROP rule:**
   ```bash
   iptables -I RAKSHAK_ISOLATED -s 10.42.0.103 -j DROP
   ```

2. **Device status update:**
   - Status: active → isolated
   - Risk score: 25% → 95%
   - Zone: trusted → quarantine

3. **Alert generation:**
   - Dashboard notification
   - Threat log entry
   - Event stream update

4. **AI analysis log:**
   - Attack type: DDoS
   - Confidence: 0.94
   - Severity: CRITICAL
   - Recommended action: ISOLATE

---

## 🎬 Demo Flow for Presentation

1. **Show dashboard** - Device active, risk score 25%

2. **Start monitoring:**
   ```bash
   tail -f data/logs/rakshak.log | grep -E "DDoS|CRITICAL|ISOLATE"
   ```

3. **Launch attack:**
   ```bash
   python3 tests/attack_esp32cam.py --attacks ddos_http
   ```

4. **Watch detection:**
   - [10s] IDS classifier detects DDoS
   - [15s] KAAL evaluates threat
   - [18s] Response engine triggers
   - [20s] Device isolated

5. **Show isolation:**
   - Dashboard: Status = ISOLATED
   - Ping fails: `ping 10.42.0.103` → timeout
   - iptables: `sudo iptables -L RAKSHAK_ISOLATED -v -n`

6. **Recovery:**
   ```bash
   curl -X POST http://localhost:5000/api/devices/10.42.0.103/unisolate
   ```

---

## 📚 References

**Training Dataset:** CICIDS2017
- Contains real DDoS attack traffic
- Multiple DoS attack types
- Labeled benign vs malicious flows

**Attack Types in Dataset:**
- DDoS (generic)
- DoS Hulk
- DoS GoldenEye
- DoS slowloris
- DoS Slowhttptest

**Model Accuracy:**
- Overall: ~96%
- DDoS detection: ~98%
- False positive rate: <2%

---

**Ready to test?** Run the script and watch RAKSHAK detect and isolate the DDoS attack in real-time! 🚀

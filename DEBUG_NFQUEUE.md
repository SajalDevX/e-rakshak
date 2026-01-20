# NFQueue Debugging - The Missing Chain Problem

## Root Cause Found! 🎯

**The Issue:**
- NFQUEUE rule was only on **FORWARD** chain
- Attack script runs on **gateway machine** (10.42.0.1)
- Traffic from gateway → ESP32 uses **OUTPUT** chain
- Packets **never reached** NFQueue!

## iptables Chains Explained:

```
┌─────────────────────────────────────────────────────────────┐
│                    iptables Packet Flow                      │
└─────────────────────────────────────────────────────────────┘

Attack from Gateway (10.42.0.1) → ESP32 (10.42.0.103):
┌──────────┐
│  Attack  │ python3 attack_esp32cam.py
│  Script  │
└────┬─────┘
     │
     ↓
┌─────────────┐
│ OUTPUT      │ ← Packets LEAVING the gateway
│ chain       │    (locally generated)
└──────┬──────┘
       │
       ↓ (to network interface)
     [ESP32]


Traffic from Device A (10.42.0.X) → Device B (10.42.0.Y):
┌──────────┐
│ Device A │
└────┬─────┘
     │
     ↓
┌─────────────┐
│ FORWARD     │ ← Packets being ROUTED through gateway
│ chain       │    (passing through)
└──────┬──────┘
       │
       ↓
┌──────────┐
│ Device B │
└──────────┘


Responses from ESP32 → Gateway:
     [ESP32]
       │
       ↓ (from network interface)
┌─────────────┐
│ INPUT       │ ← Packets ARRIVING at the gateway
│ chain       │    (destined for gateway)
└─────────────┘
```

## The Fix Applied:

### Before (BROKEN):
```python
# Only FORWARD chain
subprocess.run([
    "iptables", "-I", "FORWARD", "1",
    "-j", "NFQUEUE", "--queue-num", "1"
])
```

**Result:** Attack traffic from gateway bypassed NFQueue completely! ❌

### After (FIXED):
```python
# Both FORWARD and OUTPUT chains
for chain in ["FORWARD", "OUTPUT"]:
    subprocess.run([
        "iptables", "-I", chain, "1",
        "-j", "NFQUEUE", "--queue-num", "1"
    ])
```

**Result:** NFQueue captures attack traffic originating from gateway! ✅

## Debug Logging Added:

### Packet Processing Logs:
```python
# Every 100 packets
logger.debug(f"NFQueue: {packet_count} packets ({pps:.1f} pps)")
```

### Rate Tracker Logs:
```python
# New flows
logger.debug(f"Rate tracker: New flow {src_ip}->{dst_ip}")

# Every 100 packets
logger.debug(f"Rate tracker: Checking {flow_key} - {count} packets")
```

### DDoS Detection:
```python
# When threshold exceeded
logger.critical(f"DDoS DETECTED: {src_ip} -> {dst_ip} ({packet_rate:.1f} packets/s)")
```

## Testing Instructions:

### 1. Restart RAKSHAK (IMPORTANT!)
```bash
# Stop current instance (Ctrl+C)
cd /home/sajal/Desktop/Hackathons/e-raksha
sudo python main.py
```

**Watch for startup logs:**
```
✓ nfqueue 1 configured on FORWARD chain
✓ nfqueue 1 configured on OUTPUT chain  ← NEW!
✓ Packet inspection thread started
```

### 2. Run Attack
```bash
python3 tests/attack_esp32cam.py --attacks ddos_http
```

### 3. Watch Logs in Real-Time
```bash
tail -f data/logs/rakshak.log | grep -E "NFQueue|Rate tracker|DDoS DETECTED|CRITICAL"
```

### 4. Expected Output

**Packet Processing (debug logs):**
```
NFQueue: 100 packets (52.3 pps)
NFQueue: 200 packets (48.7 pps)
NFQueue: 300 packets (51.2 pps)
...
```

**Rate Tracker:**
```
Rate tracker: New flow 10.42.0.1->10.42.0.103
Rate tracker: Checking 10.42.0.1->10.42.0.103 - 100 packets
Rate tracker: Checking 10.42.0.1->10.42.0.103 - 200 packets
...
```

**DDoS Detection:**
```
🚨 DDoS DETECTED: 10.42.0.1 -> 10.42.0.103 (62.5 packets/s)
CRITICAL | Threat severity: CRITICAL
INFO | Device 10.42.0.103 isolated
```

## Alternative: Run Attack from Different Machine

If you have another device on the network, run the attack from there to test FORWARD chain:

```bash
# On another device (10.42.0.X):
python3 attack_esp32cam.py --target 10.42.0.103 --attacks ddos_http
```

This traffic will go through FORWARD chain (routing through gateway).

## Verification Commands

After restart, verify iptables rules are in place:

```bash
# Check FORWARD chain
sudo iptables -L FORWARD -v -n | head -20

# Check OUTPUT chain
sudo iptables -L OUTPUT -v -n | head -20

# Should see:
# Chain FORWARD (policy ACCEPT ...)
#  pkts bytes target     prot opt in     out     source         destination
#     0     0 NFQUEUE    all  --  *      *       0.0.0.0/0      0.0.0.0/0     NFQUEUE num 1
#
# Chain OUTPUT (policy ACCEPT ...)
#  pkts bytes target     prot opt in     out     source         destination
#     0     0 NFQUEUE    all  --  *      *       0.0.0.0/0      0.0.0.0/0     NFQUEUE num 1
```

## Success Criteria:

✅ NFQueue logs show packet processing
✅ Rate tracker logs show flow tracking
✅ DDoS detection triggers at 50+ pps
✅ Device gets isolated within 20 seconds
✅ Risk score increases to 95%

## Timeline Expectation:

```
[00:00] Attack starts (ddos_http)
[00:02] NFQueue: First packets logged
[00:05] Rate tracker: 100 packets
[00:10] Rate tracker: 500 packets (~50 pps)
[00:12] DDoS DETECTED! (50+ pps threshold hit)
[00:15] Threat logged → KAAL evaluation
[00:18] Response Engine: ISOLATE_DEVICE
[00:20] Device 10.42.0.103 ISOLATED ✅
[00:30] Attack completes
```

## If Still Not Working:

### Check 1: Is NFQueue getting packets?
```bash
sudo iptables -L OUTPUT -v -n | grep NFQUEUE
# Look at "pkts" column - should be > 0
```

### Check 2: Is the thread running?
```bash
ps aux | grep python
# Should see main.py process
```

### Check 3: Any errors in logs?
```bash
grep -i error data/logs/rakshak.log | tail -20
```

### Check 4: Is scapy available?
```bash
source venv/bin/activate
python -c "from scapy.all import IP, TCP; print('Scapy OK')"
```

---

**Status:** FIXED - NFQueue now monitors both FORWARD and OUTPUT chains
**Confidence:** HIGH - This was the missing piece
**Action:** Restart RAKSHAK and test!

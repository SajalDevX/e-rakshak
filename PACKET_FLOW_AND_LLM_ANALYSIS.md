# RAKSHAK Packet Flow, NFQueue, and LLM Integration Analysis

## Overview
This document provides a complete analysis of how packets flow through the RAKSHAK system, how DDoS attacks are detected, and how the LLM-based decision engine works.

---

## 1. Network Architecture

```
Internet -> Modem -> [WAN: eth0] JETSON [LAN: eth1/br0] -> Router (AP) -> IoT Devices
                                  │
                            RAKSHAK Gateway
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                NFQueue (kernel)         iptables (firewall)
                    │                           │
                PacketFilter              Gateway.isolate_device()
```

---

## 2. Packet Flow Through NFQueue

### 2.1 NFQueue Setup (core/packet_filter.py)

**Initialization:**
```python
# Lines 150-171 in packet_filter.py
def setup_nfqueue(self, queue_num: int = 1) -> bool:
    # Add iptables rules to send packets to nfqueue
    for chain in ["FORWARD", "OUTPUT"]:
        iptables -I FORWARD 1 -j NFQUEUE --queue-num 1
        iptables -I OUTPUT 1 -j NFQUEUE --queue-num 1
```

**What This Does:**
- Every packet passing through the gateway goes to NFQueue
- FORWARD chain: packets being routed between interfaces
- OUTPUT chain: packets originating from the gateway itself

### 2.2 Packet Processing Loop

**File:** `core/packet_filter.py`, lines 205-348

```python
def _packet_inspection_loop(self, queue_num: int):
    def process_packet(packet):
        # 1. Parse packet with scapy
        pkt = IP(packet.get_payload())
        src_ip = pkt.src
        dst_ip = pkt.dst

        # 2. Extract protocol info
        if TCP in pkt:
            protocol = "tcp"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

            # 3. Port scan detection (Phase 3)
            if self.port_scan_detector:
                scan_result = self.port_scan_detector.process_connection_attempt(...)
                if scan_result:
                    self.on_threat_detected(scan_dict)

        elif UDP in pkt:
            protocol = "udp"
            # Similar UDP processing

        elif ICMP in pkt:
            protocol = "icmp"

        # 4. Check if should block (already isolated)
        if src_ip in self.blocked_ips:
            packet.drop()
            return

        # 5. Check for suspicious patterns
        if self._check_suspicious(pkt, src_ip, dst_ip, dst_port):
            self.on_threat_detected({...})

        # 6. Track packet rate for DDoS detection
        self._track_packet_rate(src_ip, dst_ip, protocol)

        # 7. Accept packet (let it through)
        packet.accept()
```

**Processing Rate:**
- Logs every 100 packets
- Typical throughput: 50-200 packets/second
- Example: `NFQueue: 1000 packets (72.3 pps)`

---

## 3. DDoS Detection Mechanism

### 3.1 Rate-Based Detection (NEW - After Fix)

**File:** `core/packet_filter.py`, lines 369-418

**How It Works:**
```python
def _track_packet_rate(self, src_ip: str, dst_ip: str, protocol: str):
    current_time = time.time()
    flow_key = f"{src_ip}->{dst_ip}"

    # Record packet timestamp
    self.packet_rates[flow_key].append(current_time)

    # Check every 100 packets to reduce overhead
    if len(self.packet_rates[flow_key]) % 100 != 0:
        return

    # Don't alert more than once per 30s
    last_alert = self.ddos_alerts.get(src_ip, 0)
    if current_time - last_alert < 30:
        return

    # Calculate packet rate over 10-second window
    cutoff_time = current_time - self.rate_window  # 10 seconds
    recent_packets = [t for t in self.packet_rates[flow_key] if t >= cutoff_time]
    packet_rate = len(recent_packets) / self.rate_window

    # Detect DDoS if rate >= 50 packets/second
    if packet_rate >= self.ddos_threshold:  # threshold = 50 pps
        logger.critical(f"DDoS DETECTED: {src_ip} -> {dst_ip} ({packet_rate:.1f} packets/s)")

        # Mark alert time
        self.ddos_alerts[src_ip] = current_time

        # Notify threat handler
        if self.on_threat_detected:
            self.on_threat_detected({
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": protocol,
                "packet_rate": packet_rate,
                "attack_type": "ddos_http" if protocol == "tcp" else "ddos_udp",
                "severity": "critical",
                "reason": "high_packet_rate",
                "packets_per_second": packet_rate
            })
```

**Detection Criteria:**
- ✅ Packet rate >= 50 packets/second
- ✅ Sustained for 10 seconds
- ✅ Alert throttling: max 1 alert per 30 seconds per IP

**Why This Works:**
- Normal web browsing: 1-10 packets/second
- DDoS HTTP flood: 50-500 packets/second
- Clear threshold = reliable detection

---

## 4. LLM Flow When DDoS is Detected

### 4.1 Threat Detection Callback Chain

```
PacketFilter._track_packet_rate()
         ↓
    (detects rate >= 50 pps)
         ↓
PacketFilter.on_threat_detected({...})  [callback set by main.py]
         ↓
RakshakOrchestrator._on_packet_inspected(packet_info)  [main.py:806]
         ↓
    (creates threat_info dict)
         ↓
ThreatLogger.log_threat(threat_info)  [queues for processing]
         ↓
RakshakOrchestrator._process_threat(threat)  [main.py:586]
```

### 4.2 LLM Integration Point

**File:** `main.py`, lines 586-653

```python
def _process_threat(self, threat: dict):
    logger.info(f"Processing threat: {threat.get('type')} from {threat.get('source_ip')}")

    # Emit to dashboard
    self._emit_event('threat_detected', {...})

    # Phase 3: Use Response Decision Engine
    if self.response_engine:
        # Build threat context
        source_device = self.network_scanner.get_device(threat.get('source_ip'))
        device_zone = source_device.zone if source_device else "guest"
        device_type = source_device.device_type if source_device else "unknown"

        # Check if repeat offender
        is_repeat = self.response_engine.check_repeat_offender(threat.get('source_ip'))

        context = ThreatContext(
            threat_type=threat.get('type', 'unknown'),
            severity=threat.get('severity', 'medium'),
            confidence=threat.get('confidence', 0.7),
            source_ip=threat.get('source_ip'),
            device_type=device_type,
            device_zone=device_zone,
            device_criticality=self._get_device_criticality(device_type),
            anomaly_count=threat.get('anomaly_count', 0),
            is_repeat_offender=is_repeat
        )

        # Get graduated response decision
        response_decision = self.response_engine.decide_response(context)
        logger.info(f"Response Engine: {response_decision.level.name} - {response_decision.action}")

    # Get AI decision from KAAL
    action = self.agentic_defender.decide(threat)
    logger.info(f"KAAL decided: {action['action']}")

    # If response engine escalates, use its decision
    if response_decision and response_decision.auto_execute:
        logger.warning(f"Response Engine escalating to: {response_decision.level.name}")
        action = self._map_response_to_action(response_decision, threat)

    # Execute action
    self._execute_action(action, threat)

    # Log the decision
    self.threat_logger.log_decision(threat, action)

    # Emit action_taken event
    self._emit_event('action_taken', {...})
```

### 4.3 Response Decision Engine (LLM Component)

**File:** `core/response_decision_engine.py`

**Response Levels:**
```python
class ResponseLevel(Enum):
    MONITOR = 0          # Just watch
    ALERT = 1            # Alert user
    RATE_LIMIT = 2       # Slow down device
    DEPLOY_HONEYPOT = 3  # Redirect to honeypot
    QUARANTINE = 4       # Limited isolation
    ISOLATE = 5          # Full isolation
    FULL_BLOCK = 6       # Hard block + blacklist
```

**Decision Logic:**
```python
def decide_response(self, context: ThreatContext) -> ResponseDecision:
    # Severity scoring (0-10)
    severity_score = self._calculate_severity(context)

    # Map severity to response level
    if severity_score >= 9:
        level = ResponseLevel.FULL_BLOCK
        auto_execute = True
    elif severity_score >= 7:
        level = ResponseLevel.ISOLATE
        auto_execute = True
    elif severity_score >= 5:
        level = ResponseLevel.QUARANTINE
        auto_execute = False  # Needs approval
    elif severity_score >= 4:
        level = ResponseLevel.DEPLOY_HONEYPOT
        auto_execute = True
    elif severity_score >= 3:
        level = ResponseLevel.RATE_LIMIT
        auto_execute = True
    elif severity_score >= 2:
        level = ResponseLevel.ALERT
        auto_execute = True
    else:
        level = ResponseLevel.MONITOR
        auto_execute = True

    return ResponseDecision(
        level=level,
        action=self._get_action_for_level(level),
        confidence=confidence,
        reason=reason,
        auto_execute=auto_execute,
        requires_approval=not auto_execute
    )
```

**For DDoS Attacks:**
```
threat_type = "dos_attack"
severity = "critical"
confidence = 0.95
packet_rate = 75.3 pps

→ severity_score = 9 (very high)
→ ResponseLevel.ISOLATE
→ auto_execute = True
→ Action: ISOLATE_DEVICE
```

---

## 5. Device Isolation Mechanism

### 5.1 Action Execution

**File:** `main.py`, lines 655-707

```python
def _execute_action(self, action: dict, threat: dict):
    action_type = action.get("action")

    # Use integrated execute_action from agentic_defender
    result = self.agentic_defender.execute_action(
        decision=action,
        threat_info=threat,
        deception_engine=self.deception_engine
    )

    if result.get('real_action_taken'):
        logger.warning(f"REAL ACTION TAKEN: {action_type}")

    if action_type == "ISOLATE_DEVICE":
        logger.warning(f"Action: Isolating device {threat.get('target_device')}")
        self._emit_event('device_isolated', {
            'device': threat.get('target_device'),
            'ip': threat.get('source_ip'),
            'message': result.get('message', 'Device isolated'),
            'real_action': result.get('real_action_taken', False)
        })
```

### 5.2 Gateway Isolation (iptables)

**File:** `core/gateway.py`, lines 1249-1283

```python
def isolate_device(self, ip_address: str,
                   level: IsolationLevel = IsolationLevel.FULL,
                   reason: str = "Threat detected",
                   duration_minutes: Optional[int] = None) -> bool:

    if level == IsolationLevel.FULL:
        # Block ALL traffic from/to device
        subprocess.run([
            "iptables", "-I", "RAKSHAK_ISOLATED", "1",
            "-s", ip_address,
            "-m", "comment", "--comment", f"rakshak-isolate-{ip_address}",
            "-j", "DROP"
        ], check=True)

        subprocess.run([
            "iptables", "-I", "RAKSHAK_ISOLATED", "1",
            "-d", ip_address,
            "-m", "comment", "--comment", f"rakshak-isolate-{ip_address}",
            "-j", "DROP"
        ], check=True)

        logger.critical(f"Device {ip_address} FULLY ISOLATED - {reason}")

    # Track isolation
    mac_address = self._get_mac_for_ip(ip_address)
    self.isolated_devices[ip_address] = IsolatedDevice(
        ip_address=ip_address,
        mac_address=mac_address,
        isolation_level=level,
        isolated_at=datetime.now(),
        reason=reason,
        auto_expire=auto_expire_time
    )

    return True
```

**iptables Chain Structure:**
```
FORWARD chain
    ↓
RAKSHAK_FORWARD (our main chain)
    ↓
RAKSHAK_ISOLATED (isolation rules checked first)
    ↓
    Rule 1: DROP all from 10.42.0.103 (isolated device)
    Rule 2: DROP all to 10.42.0.103 (isolated device)
    ↓
RAKSHAK_ZONE_ENFORCE (zone-based rules)
    ↓
NAT rules (masquerade, redirection)
```

---

## 6. Complete DDoS Detection Timeline

### Example: HTTP Flood Attack on ESP32-CAM

```
[00:00] Attack starts
        - Test script launches 10 threads
        - Each thread sends HTTP GET requests to ESP32-CAM (10.42.0.103)
        - Rate: 50-100 requests/second

[00:05] ~250 packets sent
        - NFQueue processes: 10.42.0.X -> 10.42.0.103:80 (TCP)
        - packet_rates[flow_key] accumulates timestamps
        - Log: "Rate tracker: Checking flow - 100 packets"

[00:10] ~500 packets sent
        - Packet rate calculation:
          recent_packets = 520 packets in last 10 seconds
          packet_rate = 520 / 10 = 52 packets/second
        - THRESHOLD EXCEEDED: 52 >= 50 pps

[00:10.5] DDoS detected
          LOG: "DDoS DETECTED: 10.42.0.X -> 10.42.0.103 (52.0 packets/s)"

          Callback triggered:
          on_threat_detected({
              "source_ip": "10.42.0.X",
              "dest_ip": "10.42.0.103",
              "attack_type": "ddos_http",
              "severity": "critical",
              "packet_rate": 52.0,
              "reason": "high_packet_rate"
          })

[00:11] Threat logged
        ThreatLogger.log_threat(threat_info)
        - Added to threat queue
        - Database: INSERT INTO threats (...)
        - Event emitted to dashboard

[00:12] KAAL AI evaluates
        agentic_defender.decide(threat)
        - Analyzes: severity="critical", attack_type="ddos_http"
        - Threat score: 9/10
        - Decision: ISOLATE_DEVICE

[00:13] Response Engine escalates
        response_engine.decide_response(context)
        - severity_score = 9
        - ResponseLevel.ISOLATE
        - auto_execute = True
        - Action: ISOLATE_DEVICE

[00:14] Gateway isolation
        gateway.isolate_device("10.42.0.103", level=IsolationLevel.FULL)

        iptables commands:
        iptables -I RAKSHAK_ISOLATED 1 -s 10.42.0.103 -j DROP
        iptables -I RAKSHAK_ISOLATED 1 -d 10.42.0.103 -j DROP

        LOG: "Device 10.42.0.103 FULLY ISOLATED - DDoS attack"

[00:15] Attack continues (but blocked)
        - All packets from/to 10.42.0.103 dropped at firewall
        - NFQueue still processes (but drops before routing)
        - Device cannot communicate with network

[00:30] Attack ends
        - Dashboard shows: Status = isolated, Risk = 95%
        - Manual un-isolation required or auto-expire (if configured)
```

---

## 7. LLM Integration Points

### 7.1 Where LLMs Are Used

**1. Response Decision Engine (core/response_decision_engine.py)**
   - NOT actually using LLM (misleading name)
   - Rule-based severity scoring
   - Graduated response levels
   - Could be enhanced with LLM in future

**2. LLM Honeypot (core/llm_honeypot.py)**
   - Uses Claude API for dynamic responses
   - Generates realistic device responses
   - Engages attackers with believable interactions
   - NOT used in DDoS detection (only for honeypot deployment)

**3. IDS Classifier (core/ids_classifier.py)**
   - Pre-trained ML model (Random Forest)
   - NOT LLM-based
   - Trained on CICIDS2017 dataset
   - 78 features for traffic classification
   - Currently NOT called for rate-based DDoS (uses direct detection)

### 7.2 Where LLMs Could Be Added

**Potential Enhancements:**

1. **Threat Context Analysis**
   ```python
   llm_prompt = f"""
   Analyze this network threat:
   - Source: {device_name} ({device_type})
   - Attack: {attack_type}
   - Severity: {severity}
   - History: {previous_incidents}
   - Context: {network_activity}

   Should we isolate this device? Consider:
   - False positive risk
   - Device importance
   - Attack sophistication
   """

   llm_decision = claude_api.complete(llm_prompt)
   ```

2. **Anomaly Explanation**
   ```python
   llm_prompt = f"""
   Explain why this traffic pattern is suspicious:
   - Packet rate: {packet_rate} pps (normal: 1-10)
   - Flow duration: {duration}s
   - Destination: {target_device}

   Provide user-friendly explanation in Hindi and English.
   """

   explanation = claude_api.complete(llm_prompt)
   ```

3. **Adaptive Thresholds**
   ```python
   llm_prompt = f"""
   Based on this device profile:
   - Type: {device_type}
   - Normal traffic: {baseline_stats}
   - Current traffic: {current_stats}

   Suggest optimal DDoS detection threshold for this device.
   """

   threshold = claude_api.complete(llm_prompt)
   ```

**Current State:** LLMs are NOT actively used in DDoS detection. The system uses:
- ✅ Rule-based rate detection
- ✅ Pre-trained ML classifiers
- ✅ Graduated response engine (rule-based)
- ❌ No LLM inference in detection path

---

## 8. System NOT Working Issues

### Problem: DDoS Detection Not Triggering

**Symptoms:**
- HTTP flood attack runs
- NFQueue processes packets
- No "DDoS DETECTED" logs
- Device NOT isolated

**Common Causes:**

1. **NFQueue Not Working**
   ```bash
   # Check if NFQueue is running
   tail -f data/logs/rakshak.log | grep -i nfqueue

   # Should see:
   # "nfqueue 1 configured on FORWARD chain"
   # "Packet inspection thread started"
   # "NFQueue: 100 packets (45.2 pps)"
   ```

2. **Packet Rate Too Low**
   ```bash
   # Check actual packet rate
   tail -f data/logs/rakshak.log | grep "Rate tracker"

   # Should see:
   # "Rate tracker: Checking flow - 100 packets"
   # "Rate tracker: Checking flow - 200 packets"
   ```

   - If attack rate < 50 pps, won't trigger
   - Solution: Increase thread count or request rate

3. **Callback Not Set**
   ```python
   # Verify callback is connected (main.py:349)
   self.packet_filter.on_threat_detected = self._on_packet_inspected
   ```

4. **Alert Throttling**
   - Max 1 alert per 30 seconds per IP
   - Check if alert was already sent recently

### Debug Commands

```bash
# 1. Check NFQueue packets
tail -f data/logs/rakshak.log | grep -E "NFQueue|packets"

# 2. Check rate tracker
tail -f data/logs/rakshak.log | grep "Rate tracker"

# 3. Check DDoS detection
tail -f data/logs/rakshak.log | grep -i ddos

# 4. Check isolation
sudo iptables -L RAKSHAK_ISOLATED -v -n

# 5. Check threat processing
tail -f data/logs/rakshak.log | grep -E "Processing threat|KAAL|Response Engine"
```

---

## 9. Summary

### Current Flow (Working)
```
Packet -> NFQueue -> PacketFilter -> Rate Tracker -> DDoS Detected
                                                          ↓
Dashboard <- Emit Event <- Execute Action <- KAAL AI <- Threat Logger
                                ↓
                        Gateway.isolate_device()
                                ↓
                            iptables DROP
```

### Key Components
- ✅ NFQueue: Kernel-level packet inspection
- ✅ PacketFilter: Rate-based DDoS detection
- ✅ Response Engine: Graduated response (rule-based)
- ✅ Gateway: iptables-based isolation
- ✅ Dashboard: Real-time WebSocket updates
- ❌ LLM: NOT used in detection (only in honeypot responses)

### Detection Thresholds
- DDoS: >= 50 packets/second for 10 seconds
- Port Scan: >= 5 unique ports in 60 seconds
- Alert Throttling: 1 alert per 30 seconds per IP

### Isolation
- Method: iptables DROP rules
- Target: IP address (not MAC)
- Level: FULL (blocks all traffic)
- Duration: Permanent (until manual un-isolation)

---

**Created:** 2026-01-18
**Purpose:** Understanding packet flow for MAC-based isolation implementation

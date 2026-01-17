# Zero Trust Attack Simulation Guide
## Comprehensive Security Testing for RAKSHAK

---

## Overview

This guide provides step-by-step instructions for simulating attacks against RAKSHAK's Zero Trust architecture to validate security controls.

**WARNING**: Only run these simulations on isolated test networks. Never perform these tests on production networks without explicit authorization.

---

## Table of Contents

1. [Test Environment Setup](#test-environment-setup)
2. [Automated Test Suite](#automated-test-suite)
3. [Manual Test Scenarios](#manual-test-scenarios)
4. [Validation Criteria](#validation-criteria)
5. [Expected Results](#expected-results)

---

## Test Environment Setup

### Minimum Requirements

- **RAKSHAK Gateway**: Configured with Zero Trust enabled
- **Test Devices**: 3+ devices (VMs, containers, or physical devices)
- **Tools**: nmap, hping3, scapy, metasploit (optional)
- **Network**: Isolated test network (no production traffic)

### Setup Instructions

```bash
# 1. Install test tools
sudo apt install -y nmap hping3 hydra netcat-openbsd scapy

# 2. Create test devices (Docker containers)
docker run -d --name test-iot-1 --network rakshak alpine:latest sleep infinity
docker run -d --name test-iot-2 --network rakshak alpine:latest sleep infinity
docker run -d --name test-guest --network rakshak alpine:latest sleep infinity

# 3. Get device IPs
docker exec test-iot-1 ip addr show eth0 | grep "inet "
# Assign to IOT zone (10.42.0.100-199)

docker exec test-guest ip addr show eth0 | grep "inet "
# Should auto-assign to GUEST zone (10.42.0.200-249)
```

---

## Automated Test Suite

### Running the Full Suite

```bash
cd /home/sajal/Desktop/Hackathons/e-raksha
sudo python3 scripts/zero_trust_attack_suite.py --target 10.42.0.1
```

### Individual Test Execution

```bash
# Test 1: Unknown device join
sudo python3 scripts/zero_trust_attack_suite.py --test unknown_device_join

# Test 2: ARP spoofing
sudo python3 scripts/zero_trust_attack_suite.py --test arp_spoofing

# Test 3: Lateral movement
sudo python3 scripts/zero_trust_attack_suite.py --test lateral_movement

# Test 4: RFC1918 access from guest
sudo python3 scripts/zero_trust_attack_suite.py --test guest_rfc1918_isolation

# Test 5: Attack chain detection
sudo python3 scripts/zero_trust_attack_suite.py --test attack_chain
```

### Expected Output

```
[TEST 1] Unknown Device Join Scenario........................ PASS
[TEST 2] ARP Spoofing Attack.................................. PASS
[TEST 3] Lateral Movement Attack.............................. PASS
[TEST 4] RFC1918 Access from Guest Zone....................... PASS
[TEST 5] Attack Chain Detection............................... PASS

=============================================================
ZERO TRUST VALIDATION REPORT
=============================================================
Tests Run: 5
Passed: 5
Failed: 0
Pass Rate: 100.0%
=============================================================
```

---

## Manual Test Scenarios

### Scenario 1: Unknown Device Join

**Objective**: Verify unknown devices are isolated to guest zone

**Steps**:

1. Connect new device to network
2. Check assigned IP address
3. Test internet connectivity
4. Test LAN access
5. Test RFC1918 access

**Commands**:

```bash
# From new device
ip addr show | grep inet

# Should receive IP in range 10.42.0.200-249

# Test internet (should work)
ping -c 3 8.8.8.8

# Test LAN gateway (should fail)
ping -c 3 10.42.0.1

# Test other internal network (should fail)
ping -c 3 192.168.1.1
```

**Expected Results**:
- ✅ IP assigned in guest range (10.42.0.200-249)
- ✅ Internet accessible
- ❌ LAN access blocked
- ❌ RFC1918 access blocked

---

### Scenario 2: Lateral Movement Between IoT Devices

**Objective**: Verify IoT devices cannot attack each other

**Prerequisites**:
- Device A: 10.42.0.100 (assigned to IOT zone)
- Device B: 10.42.0.101 (assigned to IOT zone)

**Steps**:

1. From Device A, attempt SSH to Device B
2. Attempt Telnet to Device B
3. Attempt port scan of Device B

**Commands**:

```bash
# From Device A (10.42.0.100)

# SSH attempt
ssh user@10.42.0.101
# Expected: Connection refused or timeout

# Telnet attempt
telnet 10.42.0.101 23
# Expected: Connection refused or timeout

# Port scan
nmap -p 1-1000 10.42.0.101
# Expected: All ports filtered or no response
```

**Expected Results**:
- ❌ SSH connection blocked
- ❌ Telnet connection blocked
- ❌ Port scan unsuccessful
- ✅ Firewall logs show dropped packets

---

### Scenario 3: ARP Spoofing Attack

**Objective**: Verify ARP spoofing is detected and blocked

**Prerequisites**:
- Attacker device with scapy installed

**Steps**:

1. Send gratuitous ARP packets
2. Check if RAKSHAK detects spoofing
3. Verify attacker is isolated

**Commands**:

```python
# From attacker device
from scapy.all import ARP, Ether, send

# Target device
target_ip = "10.42.0.50"
attacker_mac = "AA:BB:CC:DD:EE:99"

# Send gratuitous ARP
arp = ARP(op=2, psrc=target_ip, hwsrc=attacker_mac,
          pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")

send(Ether(dst="ff:ff:ff:ff:ff:ff")/arp, verbose=False, count=10)

# Wait 5 seconds
time.sleep(5)

# Check if isolated
# Try to ping gateway
!ping -c 3 10.42.0.1
```

**Expected Results**:
- ✅ ARP spoofing detected in logs
- ✅ Attacker device isolated
- ❌ Attacker cannot ping gateway

**Verify in RAKSHAK logs**:
```bash
tail -f data/logs/rakshak.log | grep "ARP_SPOOF"
# Should see: THREAT: arp_spoofing | high | AA:BB:CC:DD:EE:99 -> Device
```

---

### Scenario 4: SSH Brute Force (Internal)

**Objective**: Verify internal brute force attacks are detected

**Prerequisites**:
- Device A: 10.42.0.100 (IoT zone)
- Device B: 10.42.0.101 (IoT zone, SSH server running)

**Steps**:

1. Attempt SSH brute force from Device A to Device B
2. Verify IDS detects attack
3. Check if Device A is isolated

**Commands**:

```bash
# From Device A
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://10.42.0.101 -t 4

# Wait for detection (5-10 seconds)

# Check if isolated
ping -c 3 10.42.0.1
# Should fail if isolated
```

**Expected Results**:
- ✅ Brute force detected by IDS
- ✅ Device A isolated
- ✅ Alert logged in database

**Verify detection**:
```bash
sqlite3 data/rakshak.db \
  "SELECT * FROM threats WHERE type='SSH-Patator' AND source_ip='10.42.0.100';"
```

---

### Scenario 5: Multi-Hop Attack Chain

**Objective**: Verify attack chain detection and full isolation

**Prerequisites**:
- Device A: 10.42.0.100 (compromised camera)
- Device B: 10.42.0.101 (smart TV)
- Device C: 10.42.0.102 (smart lock)

**Steps**:

1. Simulate attack: A → B (SSH brute force)
2. Simulate propagation: B → C (SSH brute force)
3. Verify attack chain detected
4. Confirm all 3 devices isolated

**Commands**:

```bash
# Step 1: Device A attacks Device B
# (From Device A)
nmap -p 22 --script ssh-brute 10.42.0.101

# Wait 10 seconds

# Step 2: Device B attacks Device C
# (From Device B)
nmap -p 22 --script ssh-brute 10.42.0.102

# Wait 10 seconds

# Step 3: Check attack chain tracker
python3 -c "
from core.attack_chain_tracker import AttackChainTracker
tracker = AttackChainTracker('data/rakshak.db')
chains = tracker.get_active_chains()
for chain in chains:
    print(f'Chain: {chain}')
"
```

**Expected Results**:
- ✅ Attack chain detected (A → B → C)
- ✅ All 3 devices isolated
- ✅ Chain logged in database

**Verify chain**:
```bash
sqlite3 data/rakshak.db \
  "SELECT * FROM attack_chains WHERE is_active=1;"

# Should show:
# chain_id | root_device_ip | compromised_devices     | chain_length
# CHAIN-XX | 10.42.0.100    | ["10.42.0.100", "..."]  | 3
```

---

### Scenario 6: Isolation Persistence After Reboot

**Objective**: Verify isolated devices remain isolated after gateway reboot

**Steps**:

1. Isolate a device
2. Verify isolation active
3. Reboot gateway
4. Verify isolation restored

**Commands**:

```bash
# Step 1: Isolate device
curl -X POST http://localhost:5000/api/devices/10.42.0.50/isolate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Test isolation persistence"}'

# Step 2: Verify isolation
sudo iptables -L RAKSHAK_ISOLATED -n -v | grep 10.42.0.50
# Should show DROP rules

# Step 3: Reboot gateway
sudo reboot

# Wait for boot (1-2 minutes)

# Step 4: Verify isolation restored
sudo iptables -L RAKSHAK_ISOLATED -n -v | grep 10.42.0.50
# Should still show DROP rules
```

**Expected Results**:
- ✅ Isolation persists after reboot
- ✅ Database contains persistent isolation record
- ✅ Device still cannot communicate

---

### Scenario 7: Behavioral Anomaly Detection

**Objective**: Verify behavioral baselines detect anomalies

**Prerequisites**:
- Device with established baseline (>24h of normal activity)

**Steps**:

1. Perform unusual activity
2. Check if anomaly detected
3. Review anomaly log

**Commands**:

```bash
# From test device
# Unusual activity: access suspicious port
nc -vz 10.42.0.1 22  # SSH to gateway (unusual for IoT device)

# Different protocol
nc -u -vz 10.42.0.1 161  # SNMP (unusual)

# New internal peer
nc -vz 10.42.0.150 80  # Contact new device (unusual)

# Wait 30 seconds

# Check anomalies
sqlite3 data/rakshak.db \
  "SELECT * FROM device_anomalies WHERE device_ip='<your-device-ip>';"
```

**Expected Results**:
- ✅ NEW_PROTOCOL anomaly detected
- ✅ SUSPICIOUS_PORT anomaly detected
- ✅ NEW_INTERNAL_PEER anomaly detected
- ✅ Anomalies logged with severity and deviation score

---

## Validation Criteria

### Critical Requirements (Must Pass)

1. **Zone Isolation**:
   - ✅ IoT devices CANNOT communicate with each other
   - ✅ Guest devices CANNOT access RFC1918
   - ✅ Quarantined devices CANNOT send any traffic

2. **Unknown Device Handling**:
   - ✅ Auto-assigned to guest zone
   - ✅ Internet access allowed
   - ✅ LAN access blocked

3. **Attack Detection**:
   - ✅ Lateral movement detected within 30 seconds
   - ✅ ARP spoofing detected and attacker isolated
   - ✅ Internal brute force detected

4. **Persistence**:
   - ✅ Isolated devices remain isolated after reboot
   - ✅ Zone assignments preserved

5. **Attack Chain**:
   - ✅ Multi-hop attacks detected
   - ✅ Entire chain isolated (not just root)

### Optional Features (Should Pass)

1. **Behavioral Baselines**:
   - ✅ Anomalies detected after learning period
   - ⚠️ False positive rate < 5%

2. **API Security**:
   - ✅ Unauthenticated requests rejected
   - ✅ Insufficient role permissions blocked

---

## Expected Results Summary

| Test Scenario                 | Expected Outcome               | Critical |
|-------------------------------|-------------------------------|----------|
| Unknown device join           | Guest zone, RFC1918 blocked   | ✅       |
| Lateral movement              | Blocked by firewall           | ✅       |
| ARP spoofing                  | Detected and isolated         | ✅       |
| Internal brute force          | Detected by IDS               | ✅       |
| Attack chain (2+ hops)        | Full chain isolated           | ✅       |
| Isolation persistence         | Survives reboot               | ✅       |
| Behavioral anomaly            | Detected after learning       | ⚠️       |

**Legend**:
- ✅ Critical (must pass)
- ⚠️ Optional (should pass)

---

## Troubleshooting Failed Tests

### Test Fails: Lateral Movement Not Blocked

**Diagnosis**:
```bash
# Check IoT zone rules
sudo iptables -L RAKSHAK_ZONE_IOT -n -v

# Should see:
# DROP all -- * * 10.42.0.100/25 10.42.0.100/25
```

**Fix**:
```python
# Re-apply zone rules
gateway._apply_zone_rules()
```

### Test Fails: Unknown Device Gets Wrong IP

**Diagnosis**:
```bash
# Check DHCP pool
cat /etc/dnsmasq.d/rakshak.conf | grep dhcp-range
```

**Fix**:
```bash
# Update DHCP range
echo "dhcp-range=10.42.0.200,10.42.0.249,24h" | \
  sudo tee -a /etc/dnsmasq.d/rakshak.conf

sudo systemctl reload dnsmasq
```

### Test Fails: Attack Chain Not Detected

**Diagnosis**:
```bash
# Check if attack chain tracker is running
python3 -c "
from core.attack_chain_tracker import AttackChainTracker
tracker = AttackChainTracker('data/rakshak.db')
print(f'Active chains: {len(tracker.get_active_chains())}')
"
```

**Fix**:
```python
# Manually record compromises
tracker.record_compromise(
    source_ip="10.42.0.100",
    target_ip="10.42.0.101",
    attack_type="SSH-Patator",
    severity="high",
    confidence=0.9
)
```

---

## Continuous Testing (CI/CD)

### Integration with pytest

```bash
# Run integration tests
pytest tests/test_zero_trust_integration.py -v

# Run specific test
pytest tests/test_zero_trust_integration.py::test_lateral_movement_detection -v
```

### Automated Regression Testing

```bash
# Add to CI/CD pipeline
#!/bin/bash
set -e

echo "Starting Zero Trust regression tests..."

# Setup
docker-compose -f docker-compose.test.yml up -d
sleep 10

# Run tests
pytest tests/test_zero_trust_integration.py --junit-xml=results.xml

# Cleanup
docker-compose -f docker-compose.test.yml down

echo "All tests passed ✅"
```

---

## Reporting Issues

If a test fails:

1. **Capture logs**:
   ```bash
   tail -n 100 data/logs/rakshak.log > test-failure.log
   sudo iptables-save > iptables-state.txt
   ```

2. **Database dump**:
   ```bash
   sqlite3 data/rakshak.db .dump > db-dump.sql
   ```

3. **System state**:
   ```bash
   ip addr show > network-state.txt
   ps aux | grep rakshak > process-state.txt
   ```

4. **Create GitHub issue** with:
   - Test scenario name
   - Expected vs actual result
   - Attached logs
   - System configuration

---

## Security Considerations

**WARNING**: These are offensive security tests.

- ✅ Only run on isolated test networks
- ✅ Obtain written authorization before testing
- ✅ Never test production environments
- ✅ Verify no actual attacks are launched externally
- ✅ Document all test activities

---

**Document Version**: 1.0
**Last Updated**: 2026-01-17
**Author**: Team RAKSHAK

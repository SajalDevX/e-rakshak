# Zero Trust Security Architecture for RAKSHAK
## Lateral Movement Prevention & Network Segmentation

---

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Trust Zones](#trust-zones)
4. [Security Guarantees](#security-guarantees)
5. [Components](#components)
6. [Threat Model](#threat-model)
7. [Limitations](#limitations)

---

## Overview

RAKSHAK implements a comprehensive Zero Trust security architecture to prevent lateral movement and unauthorized access on IoT networks. This document describes the architecture, design decisions, and security guarantees.

### Problem Statement

Traditional home networks operate on an implicit trust model: once a device joins the network, it can communicate with any other device. This creates severe risks:

- **Lateral Movement**: Compromised IoT devices can attack other devices on the LAN
- **Unknown Devices**: New devices automatically gain full network access
- **No Segmentation**: All devices share the same broadcast domain
- **Persistent Access**: Attackers maintain access across reboots

### Solution

RAKSHAK's Zero Trust architecture implements:

1. **Default Deny**: All traffic denied by default, explicitly allowed per zone
2. **Device Enrollment**: Manual approval required for network access
3. **Zone Segmentation**: Firewall-based network zones without VLAN hardware
4. **Lateral Movement Detection**: IDS analysis of internal traffic
5. **Persistent Isolation**: Database-backed isolation survives reboots
6. **Attack Chain Tracking**: Graph-based multi-hop compromise detection

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    INTERNET (WAN)                            │
└──────────────────┬──────────────────────────────────────────┘
                   │ wlo1 (WiFi)
                   │
┌──────────────────▼──────────────────────────────────────────┐
│              RAKSHAK GATEWAY (10.42.0.1)                     │
│  ┌────────────────────────────────────────────────────┐     │
│  │ Zero Trust Enforcement Engine                       │     │
│  │ • Device Enrollment & Trust Management             │     │
│  │ • Zone-based Firewall (6 zones)                    │     │
│  │ • Lateral Movement Detection (IDS)                 │     │
│  │ • Multi-Layer Quarantine                           │     │
│  │ • Device Authentication                            │     │
│  │ • Attack Chain Tracker                             │     │
│  └────────────────────────────────────────────────────┘     │
│                 │ enx207bd51a6a7d (USB Ethernet)             │
└─────────────────┼────────────────────────────────────────────┘
                  │ 10.42.0.0/24
    ┌─────────────┴──────────┬──────────┬───────────┬─────────┐
    │                        │          │           │         │
┌───▼────┐  ┌───▼────┐  ┌───▼────┐  ┌──▼──────┐  ┌──▼──────┐
│ MGMT   │  │ MAIN   │  │  IOT   │  │  GUEST  │  │QUARANT. │
│ .1-.9  │  │.10-.99 │  │.100-.199│  │.200-.249│  │.250-.254│
└────────┘  └────────┘  └────────┘  └─────────┘  └─────────┘
  Admin      Trusted     Limited    Untrusted     Hostile
```

### Network Topology

- **WAN Interface**: `wlo1` (WiFi connection to internet)
- **LAN Interface**: `enx207bd51a6a7d` (USB Ethernet to router in AP mode)
- **LAN Network**: `10.42.0.0/24` (single subnet, no VLANs)
- **Gateway IP**: `10.42.0.1`

### Key Design Decision: Firewall-Based Segmentation

RAKSHAK uses **iptables rules** instead of VLANs for segmentation because:

1. **No hardware requirements**: Works on standard Linux box
2. **IP-based enforcement**: Devices assigned to zones by IP range
3. **Granular control**: Per-port, per-protocol rules
4. **Centralized enforcement**: All traffic passes through gateway

---

## Trust Zones

### Zone Definitions

| Zone       | IP Range             | Trust Level | Purpose                          |
|------------|---------------------|-------------|----------------------------------|
| MGMT       | 10.42.0.1 - .9      | Admin       | Gateway and admin devices        |
| MAIN       | 10.42.0.10 - .99    | Trusted     | Laptops, phones, trusted devices |
| IOT        | 10.42.0.100 - .199  | Limited     | IoT devices (cameras, bulbs)     |
| GUEST      | 10.42.0.200 - .249  | Untrusted   | Unknown/new devices              |
| QUARANTINE | 10.42.0.250 - .254  | Hostile     | Isolated threats                 |

### Zone Communication Matrix

```
           ┌──────┬──────┬─────┬───────┬───────────┐
           │ MGMT │ MAIN │ IOT │ GUEST │ QUARANTINE│
┌──────────┼──────┼──────┼─────┼───────┼───────────┤
│ MGMT     │  ✓   │  ✓   │  ✓  │   ✓   │     ✓     │
│ MAIN     │  ✓   │  ✓   │  *  │   ✗   │     ✗     │
│ IOT      │  ✓   │  ✗   │  ✗  │   ✗   │     ✗     │
│ GUEST    │  ✓   │  ✗   │  ✗  │   ✗   │     ✗     │
│QUARANTINE│  ✗   │  ✗   │  ✗  │   ✗   │     ✗     │
└──────────┴──────┴──────┴─────┴───────┴───────────┘

Legend:
✓ = Full communication allowed
* = Limited ports only (80, 443, 554, 1883)
✗ = Blocked
```

### Critical Rules

1. **IoT Isolation**: `IOT -> IOT` traffic **BLOCKED** (prevents lateral movement)
2. **Guest RFC1918 Block**: Guest devices **CANNOT** access any private IPs
3. **Quarantine Full Block**: Quarantined devices **CANNOT** send any traffic

---

## Security Guarantees

### 1. Unknown Device Isolation

**Guarantee**: Unknown devices are automatically isolated to GUEST zone.

**Implementation**:
- DHCP assigns IP from guest pool (10.42.0.200-249)
- Firewall rules block access to LAN and RFC1918
- Internet access allowed (filtered through IDS)

**Attack Scenario Blocked**:
```
Attacker brings rogue device → Auto-assigned guest IP
→ Cannot scan LAN → Cannot access IoT devices
→ Detected by IDS → Isolated
```

### 2. Lateral Movement Prevention

**Guarantee**: IoT devices cannot attack each other.

**Implementation**:
```bash
iptables -A RAKSHAK_ZONE_IOT \
  -s 10.42.0.100/25 -d 10.42.0.100/25 -j DROP
```

**Attack Scenario Blocked**:
```
Compromised Camera (10.42.0.101)
→ Tries to SSH to Smart Lock (10.42.0.102)
→ BLOCKED by firewall → Attack fails
```

### 3. Internal Traffic Inspection

**Guarantee**: All device-to-device traffic analyzed by IDS.

**Implementation**:
- ARP interception positions gateway as MITM
- Packets aggregated into flows
- CICIDS2017-compatible feature extraction
- XGBoost classifier detects attacks

**Attack Scenario Blocked**:
```
Compromised device attempts SSH brute force internally
→ Flow aggregated → IDS detects → Device isolated
```

### 4. Attack Chain Detection

**Guarantee**: Multi-hop attacks detected and fully isolated.

**Implementation**:
- Graph-based tracking (device A → device B → device C)
- Automatic chain detection
- Entire chain isolated, not just root

**Attack Scenario Blocked**:
```
Attacker compromises Camera → Camera attacks Smart TV
→ Smart TV attacks Laptop → CHAIN DETECTED
→ All 3 devices isolated
```

### 5. Reboot Persistence

**Guarantee**: Isolated devices remain isolated after gateway reboot.

**Implementation**:
- Isolation state saved to SQLite database
- On startup, gateway restores all isolations
- Includes expiration handling

---

## Components

### 1. Trust Manager (`core/trust_manager.py`)

**Purpose**: Device enrollment and zone assignment

**Key Functions**:
- `assign_to_default_zone()`: Auto-assign unknown devices to guest
- `initiate_enrollment()`: Mark device for approval
- `approve_enrollment()`: Assign device to zone after approval
- `get_zone_for_ip()`: Determine zone from IP address

### 2. Firewall Persistence (`core/firewall_persistence.py`)

**Purpose**: Persist isolation across reboots

**Key Functions**:
- `save_isolation_state()`: Save isolation to database
- `restore_isolations_on_startup()`: Restore on boot
- `expire_old_isolations()`: Remove expired entries

### 3. Flow Aggregator (`core/flow_aggregator.py`)

**Purpose**: Convert packets to flows for IDS

**Key Functions**:
- `add_packet()`: Add packet to flow
- `_extract_features()`: Extract CICIDS2017 features
- `cleanup_stale_flows()`: Remove old flows

### 4. Device Behavior Baseline (`core/device_behavior.py`)

**Purpose**: Behavioral anomaly detection

**Key Functions**:
- `update_profile()`: Update device baseline
- `_detect_anomalies()`: Detect deviations from baseline
- Anomaly types: NEW_PROTOCOL, SUSPICIOUS_PORT, NEW_INTERNAL_PEER

### 5. Attack Chain Tracker (`core/attack_chain_tracker.py`)

**Purpose**: Graph-based multi-hop attack detection

**Key Functions**:
- `record_compromise()`: Add edge to attack graph
- `_compute_chain_depth()`: Calculate chain length
- `get_dependent_devices()`: Get all downstream victims

### 6. Gateway (`core/gateway.py`)

**Purpose**: Firewall and network enforcement

**Key Functions**:
- `setup_firewall_chains()`: Create iptables chains
- `_apply_zone_rules()`: Apply zone-specific rules
- `isolate_device_enhanced()`: Multi-layer isolation

### 7. API Authentication (`core/api_auth.py`)

**Purpose**: JWT-based API security

**Key Functions**:
- `generate_token()`: Create JWT tokens
- `require_auth()`: Decorator for route protection
- Role hierarchy: Admin > Operator > Viewer

---

## Threat Model

### In-Scope Threats

✅ **Lateral Movement**: Compromised device attacking others
✅ **Unknown Device Join**: Attacker brings rogue device
✅ **Internal Port Scanning**: Device scanning LAN
✅ **Internal Brute Force**: SSH/Telnet attacks between devices
✅ **Multi-Hop Attacks**: Device A → B → C
✅ **Persistence Bypass**: Isolation removed by reboot
✅ **RFC1918 Access from Guest**: Guest trying to access private IPs

### Out-of-Scope Threats

❌ **Encrypted Traffic Inspection**: Cannot inspect HTTPS payloads
❌ **Zero-Day Attacks**: No signature-based detection
❌ **Physical Access**: Gateway compromise via physical access
❌ **WAN Attacks**: Focus is on internal threats
❌ **MAC Spoofing**: Mitigated by behavior baselines, not fully prevented

---

## Limitations

### 1. Single Subnet Limitation

**Limitation**: All devices on same Layer 2 broadcast domain

**Mitigation**:
- ARP interception prevents direct L2 communication
- Firewall enforces L3 segmentation

**Residual Risk**: Broadcast storms affect all devices

### 2. MAC-Based Identification

**Limitation**: MACs can be spoofed

**Mitigation**:
- Behavioral baselines detect anomalies
- Device re-enrollment required if MAC changes

**Residual Risk**: Sophisticated attackers may bypass

### 3. Learning Period Vulnerability

**Limitation**: Behavioral baselines require 24h learning

**During Learning**:
- Anomaly detection disabled
- Device activity considered "normal"

**Mitigation**:
- Firewall rules still enforced during learning
- Manual monitoring recommended for critical devices

### 4. IDS False Positives

**Limitation**: ML-based IDS may generate false positives

**Mitigation**:
- Confidence thresholds tuned to reduce FPs
- Manual override available
- Logging for forensic review

---

## Future Enhancements

1. **mTLS Authentication**: Device certificate-based auth
2. **HMAC Command Signing**: Prevent command replay attacks
3. **Anomaly-Based IDS**: ML model for zero-day detection
4. **SIEM Integration**: Forward logs to centralized system
5. **Hardware Token Support**: Admin access via hardware tokens
6. **VLAN Support**: Optional VLAN for physical isolation

---

## References

- NIST Zero Trust Architecture (SP 800-207)
- MITRE ATT&CK: Lateral Movement (TA0008)
- CICIDS2017 Dataset Documentation
- iptables man pages

---

**Document Version**: 1.0
**Last Updated**: 2026-01-17
**Author**: Team RAKSHAK

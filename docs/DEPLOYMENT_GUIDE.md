# Zero Trust Deployment Guide
## RAKSHAK Zero Trust Security Architecture

---

## Prerequisites

### Hardware Requirements

- **Linux Gateway**: Ubuntu 20.04+ or Debian 11+ (laptop, Jetson Xavier NX, or Raspberry Pi 4)
- **RAM**: Minimum 4GB (8GB recommended)
- **Storage**: 32GB minimum
- **Network Interfaces**: 2 NICs
  - WAN: WiFi or Ethernet (internet connection)
  - LAN: USB Ethernet adapter (for devices)

### Software Requirements

```bash
# System packages
sudo apt update
sudo apt install -y \
    python3.10 \
    python3-pip \
    iptables \
    dnsmasq \
    bridge-utils \
    net-tools \
    sqlite3 \
    git

# Python dependencies
pip3 install -r requirements.txt
```

---

## Installation Steps

### Step 1: Clone Repository

```bash
cd ~
git clone https://github.com/your-org/e-raksha.git
cd e-raksha
```

### Step 2: Database Migration

**IMPORTANT**: Backup existing database before migration.

```bash
# Backup current database
cp data/rakshak.db data/rakshak.db.backup

# Run database migration
python3 scripts/migrate_database_v2.py
```

**Manual Migration** (if script unavailable):

```bash
sqlite3 data/rakshak.db < sql/zero_trust_migration.sql
```

### Step 3: Configuration

Edit `config/config.yaml`:

```yaml
# Enable Zero Trust
zero_trust:
  enabled: true
  default_zone: "guest"

# Configure network interfaces
gateway:
  wan_interface: "wlo1"      # Your WiFi/WAN interface
  lan_interface: "enx207bd51a6a7d"  # Your USB Ethernet
  lan_ip: "10.42.0.1"
  lan_network: "10.42.0.0/24"

  # Disable DHCP if using NetworkManager
  dhcp_enabled: false
```

### Step 4: Firewall Rules Deployment

**Test firewall rules** (dry run):

```bash
sudo python3 -c "
from core.gateway import RakshakGateway
import yaml

with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

gw = RakshakGateway(full_config=config)
gw.setup_firewall_chains()
print('Firewall chains created successfully')
"
```

**Verify chains**:

```bash
sudo iptables -L RAKSHAK_ZONE_ENFORCE -n -v
sudo iptables -L RAKSHAK_ZONE_IOT -n -v
sudo iptables -L RAKSHAK_ZONE_GUEST -n -v
```

Expected output:
```
Chain RAKSHAK_ZONE_IOT (1 references)
 pkts bytes target     prot opt in     out     source               destination
    0     0 DROP       all  --  *      *       10.42.0.100/25       10.42.0.100/25
```

### Step 5: Persistence Configuration

Enable isolation persistence:

```python
# In main.py or orchestrator initialization
from core.firewall_persistence import FirewallPersistence

persistence = FirewallPersistence(db_path="data/rakshak.db")
gateway.firewall_persistence = persistence

# Restore isolations on startup
persistence.restore_isolations_on_startup(gateway)
```

### Step 6: Trust Manager Initialization

```python
from core.trust_manager import TrustManager

trust_manager = TrustManager(
    config=config,
    db_path="data/rakshak.db",
    gateway=gateway
)

# Assign unknown devices to guest zone automatically
orchestrator.trust_manager = trust_manager
```

### Step 7: Start RAKSHAK

```bash
# Start in foreground (for testing)
sudo python3 main.py

# Start as systemd service (production)
sudo systemctl start rakshak
sudo systemctl enable rakshak  # Auto-start on boot
```

---

## Post-Deployment Verification

### 1. Verify Zone Firewall Rules

```bash
# Check zone enforcement chain
sudo iptables -L RAKSHAK_ZONE_ENFORCE -n -v --line-numbers

# Expected: Rules dispatching to zone-specific chains
# Should see: -m iprange --src-range 10.42.0.100-10.42.0.199 -j RAKSHAK_ZONE_IOT
```

### 2. Test Unknown Device Isolation

**Test Procedure**:

1. Connect new device to network
2. Device should receive IP in guest range (10.42.0.200-249)
3. Verify internet access: `ping 8.8.8.8` ✅
4. Verify RFC1918 blocked: `ping 10.42.0.1` ❌
5. Verify LAN blocked: `ping 10.42.0.10` ❌

**Expected Results**:
```bash
# From guest device
$ ping 8.8.8.8
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms  ✅

$ ping 10.42.0.1
From 10.42.0.200 icmp_seq=1 Destination Net Unreachable  ❌

$ ping 192.168.1.1
From 10.42.0.200 icmp_seq=1 Destination Net Unreachable  ❌
```

### 3. Test Lateral Movement Blocking

**Test Procedure**:

1. Assign two devices to IOT zone (e.g., 10.42.0.100, 10.42.0.101)
2. From device 1, try to SSH to device 2: `ssh user@10.42.0.101`
3. Connection should be **BLOCKED** by firewall

**Expected Results**:
```bash
$ ssh user@10.42.0.101
ssh: connect to host 10.42.0.101 port 22: Connection refused  ❌
```

**Verify in logs**:
```bash
sudo iptables -L RAKSHAK_ZONE_IOT -n -v
# Should show packets dropped in IoT-to-IoT rule
```

### 4. Test Isolation Persistence

**Test Procedure**:

1. Isolate a device:
   ```python
   gateway.isolate_device_enhanced("10.42.0.50", persist_across_reboot=True)
   ```

2. Reboot gateway:
   ```bash
   sudo reboot
   ```

3. After reboot, verify isolation is restored:
   ```bash
   sudo iptables -L RAKSHAK_ISOLATED -n -v | grep 10.42.0.50
   ```

**Expected Results**:
```bash
DROP       all  --  *      *       10.42.0.50       0.0.0.0/0
DROP       all  --  *      *       0.0.0.0/0        10.42.0.50
```

### 5. Test Attack Chain Detection

**Test Procedure** (requires 3 devices):

1. Assign devices: A (10.42.0.100), B (10.42.0.101), C (10.42.0.102)
2. Simulate attack: A → B (SSH brute force)
3. Simulate propagation: B → C (SSH brute force)
4. Check attack chain tracker

**Expected Results**:
```python
>>> attack_tracker.get_active_chains()
[{
  'chain_id': 'CHAIN-ABCD1234',
  'root_device_ip': '10.42.0.100',
  'compromised_devices': ['10.42.0.100', '10.42.0.101', '10.42.0.102'],
  'chain_length': 3,
  'severity': 'critical'
}]
```

---

## Troubleshooting

### Issue 1: Firewall Rules Not Applied

**Symptoms**: Zone rules missing in `iptables -L`

**Diagnosis**:
```bash
sudo iptables -L RAKSHAK_ZONE_ENFORCE -n -v
# If empty, rules not applied
```

**Solution**:
```python
# Force re-apply zone rules
gateway.setup_firewall_chains()
gateway._apply_zone_rules()
```

### Issue 2: Devices Not Getting Guest IPs

**Symptoms**: New devices get IPs from wrong range

**Diagnosis**:
```bash
# Check DHCP configuration
cat /etc/dnsmasq.d/rakshak.conf

# Should contain guest pool:
# dhcp-range=10.42.0.200,10.42.0.249,24h
```

**Solution**:
```bash
# If NetworkManager is managing DHCP, update its config
sudo nmcli connection modify "Shared Connection" \
  ipv4.dhcp-range "10.42.0.200 10.42.0.249"

sudo systemctl restart NetworkManager
```

### Issue 3: Isolation Not Persisting

**Symptoms**: Isolated devices regain access after reboot

**Diagnosis**:
```bash
# Check database for persistent isolations
sqlite3 data/rakshak.db "SELECT * FROM persistent_isolations;"
```

**Solution**:
```python
# Ensure persistence is enabled
gateway.firewall_persistence = FirewallPersistence("data/rakshak.db")

# Manually restore
gateway.firewall_persistence.restore_isolations_on_startup(gateway)
```

### Issue 4: False Positives from IDS

**Symptoms**: Legitimate devices flagged and isolated

**Diagnosis**:
```bash
# Check anomaly log
sqlite3 data/rakshak.db "SELECT * FROM device_anomalies WHERE device_ip='10.42.0.50';"
```

**Solution**:
```python
# Adjust anomaly detection thresholds
# In device_behavior.py, modify _detect_anomalies():

# Less sensitive suspicious ports
suspicious_ports = {22: 'SSH', 3389: 'RDP'}  # Removed 23, 445

# Higher volume threshold
if deviation_ratio > 20:  # Was 10
    # Flag as anomaly
```

### Issue 5: Dashboard Not Accessible

**Symptoms**: Cannot access web dashboard

**Diagnosis**:
```bash
# Check if API is running
curl http://localhost:5000/api/status

# Check firewall
sudo iptables -L INPUT -n -v | grep 5000
```

**Solution**:
```bash
# Allow dashboard port
sudo iptables -I INPUT -p tcp --dport 5000 -j ACCEPT

# Or start with 0.0.0.0 binding
python3 main.py --host 0.0.0.0 --port 5000
```

---

## Rollback Procedures

### Emergency Rollback

If Zero Trust causes network issues:

```bash
# 1. Disable Zero Trust in config
sed -i 's/enabled: true/enabled: false/' config/config.yaml

# 2. Flush zone chains
sudo iptables -F RAKSHAK_ZONE_ENFORCE
sudo iptables -F RAKSHAK_ZONE_IOT
sudo iptables -F RAKSHAK_ZONE_GUEST

# 3. Remove zone chain jumps
sudo iptables -D FORWARD -j RAKSHAK_ZONE_ENFORCE

# 4. Restart RAKSHAK
sudo systemctl restart rakshak
```

### Database Rollback

```bash
# Restore from backup
cp data/rakshak.db data/rakshak.db.broken
cp data/rakshak.db.backup data/rakshak.db

# Restart
sudo systemctl restart rakshak
```

### Full System Restore

```bash
# 1. Stop RAKSHAK
sudo systemctl stop rakshak

# 2. Restore original network config
sudo nmcli connection modify "Shared Connection" \
  ipv4.method shared \
  ipv4.address "10.42.0.1/24"

# 3. Flush all iptables rules
sudo iptables -F
sudo iptables -X

# 4. Restart NetworkManager
sudo systemctl restart NetworkManager
```

---

## Performance Tuning

### For High-Traffic Networks

**Increase flow aggregator timeout**:
```python
flow_aggregator = FlowAggregator(
    flow_timeout=60,  # Reduce from 120
    min_packets=5     # Reduce from 10
)
```

**Disable behavioral baselines** (if too many false positives):
```yaml
zero_trust:
  behavior_baselines:
    enabled: false
```

### For Resource-Constrained Devices

**Reduce IDS frequency**:
```python
# Only analyze every 10th flow
if flow_complete and flow_count % 10 == 0:
    ids_classifier.classify(flow_data)
```

**Disable attack chain tracking**:
```yaml
zero_trust:
  attack_chain_tracking:
    enabled: false
```

---

## Monitoring

### Key Metrics to Monitor

```bash
# 1. Active isolations
sqlite3 data/rakshak.db "SELECT COUNT(*) FROM persistent_isolations WHERE is_active=1;"

# 2. Zone distribution
sqlite3 data/rakshak.db "SELECT zone, COUNT(*) FROM devices GROUP BY zone;"

# 3. Recent anomalies
sqlite3 data/rakshak.db "SELECT * FROM device_anomalies WHERE timestamp > datetime('now', '-1 hour');"

# 4. Attack chains
sqlite3 data/rakshak.db "SELECT * FROM attack_chains WHERE is_active=1;"
```

### Log Files

```bash
# RAKSHAK logs
tail -f data/logs/rakshak.log | grep -E "ISOLATION|ANOMALY|CHAIN"

# iptables dropped packets
sudo iptables -L RAKSHAK_ZONE_IOT -n -v | grep DROP

# System logs
journalctl -u rakshak -f
```

---

## Maintenance

### Weekly Tasks

- Review anomaly logs for false positives
- Check zone assignment for new devices
- Verify backup database integrity

### Monthly Tasks

- Cleanup old isolation records (>30 days)
- Review attack chain history
- Update behavioral baselines for devices

### Quarterly Tasks

- Review and update zone communication matrix
- Test disaster recovery procedures
- Audit user access logs

---

## Support

For issues, questions, or feature requests:

- **GitHub Issues**: https://github.com/your-org/e-raksha/issues
- **Documentation**: https://rakshak-docs.example.com
- **Email**: support@rakshak.example.com

---

**Document Version**: 1.0
**Last Updated**: 2026-01-17
**Author**: Team RAKSHAK

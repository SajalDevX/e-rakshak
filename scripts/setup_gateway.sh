#!/bin/bash
# =============================================================================
# RAKSHAK Gateway Setup Script
# =============================================================================
# This script configures the Jetson Xavier NX as an inline security gateway.
#
# Usage:
#   sudo ./setup_gateway.sh --start    # Start gateway mode
#   sudo ./setup_gateway.sh --stop     # Stop gateway mode
#   sudo ./setup_gateway.sh --status   # Check status
#   sudo ./setup_gateway.sh --check    # Check prerequisites only
#
# Network Topology:
#   Internet -> Modem -> [Jetson eth0] <-> [Jetson eth1] -> Router (AP) -> IoT
#
# =============================================================================

set -e

# Configuration (can be overridden by environment variables)
WAN_INTERFACE="${WAN_INTERFACE:-eth0}"
LAN_INTERFACE="${LAN_INTERFACE:-eth1}"
LAN_IP="${LAN_IP:-192.168.100.1}"
LAN_NETMASK="${LAN_NETMASK:-255.255.255.0}"
DHCP_RANGE_START="${DHCP_RANGE_START:-192.168.100.10}"
DHCP_RANGE_END="${DHCP_RANGE_END:-192.168.100.250}"
DHCP_LEASE_TIME="${DHCP_LEASE_TIME:-24h}"
DNS_SERVER_1="${DNS_SERVER_1:-8.8.8.8}"
DNS_SERVER_2="${DNS_SERVER_2:-1.1.1.1}"

# Paths
DNSMASQ_CONFIG="/etc/dnsmasq.d/rakshak.conf"
SYSCTL_CONFIG="/etc/sysctl.d/99-rakshak.conf"
IPTABLES_RULES="/etc/iptables/rakshak.rules"
LOG_FILE="/var/log/rakshak-gateway.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Platform detection
JETSON_PLATFORM=false
IS_ARM=false

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SUCCESS: $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

print_banner() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "     RAKSHAK INLINE SECURITY GATEWAY"
    echo "     India's First Agentic AI Cyber Guardian for Home IoT"
    echo "============================================================"
    echo -e "${NC}"
}

# -----------------------------------------------------------------------------
# Jetson Detection
# -----------------------------------------------------------------------------
detect_jetson() {
    log_info "Detecting platform..."

    # Check for ARM architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
        IS_ARM=true
        log_info "ARM64 architecture detected"
    fi

    # Check for Jetson platform
    if [ -f /etc/nv_tegra_release ]; then
        JETSON_PLATFORM=true
        log_success "Jetson platform detected"

        # Read Jetson info
        JETSON_INFO=$(cat /etc/nv_tegra_release | head -1)
        log_info "Jetson info: $JETSON_INFO"

        # Check for Jetson Xavier NX specifically
        if [ -f /sys/devices/soc0/family ]; then
            SOC_FAMILY=$(cat /sys/devices/soc0/family)
            log_info "SoC Family: $SOC_FAMILY"
        fi

        # Check current power mode
        if command -v nvpmodel &> /dev/null; then
            POWER_MODE=$(nvpmodel -q 2>/dev/null | grep "Power Mode" | awk '{print $NF}')
            log_info "Current power mode: ${POWER_MODE:-unknown}"
        fi
    else
        log_info "Non-Jetson platform (standard Linux)"
        JETSON_PLATFORM=false
    fi
}

# -----------------------------------------------------------------------------
# Interface Detection
# -----------------------------------------------------------------------------
detect_interfaces() {
    log_info "Detecting network interfaces..."

    # Get all network interfaces (excluding lo, docker, veth, etc.)
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^eth|^enp|^enx|^ens' | grep -v '@' | sort)

    log_info "Found interfaces: $INTERFACES"

    # Count interfaces
    IFACE_COUNT=$(echo "$INTERFACES" | wc -w)

    if [ "$IFACE_COUNT" -lt 2 ]; then
        log_warning "Need 2 network interfaces, found: $IFACE_COUNT"
        log_info "Attempting to detect USB ethernet adapter..."

        # Try to detect USB ethernet
        detect_usb_ethernet
        return $?
    fi

    # Auto-detect WAN and LAN
    # eth0 is typically the built-in NIC (WAN)
    # eth1/enx*/enp*s*u* are typically USB adapters (LAN)
    if echo "$INTERFACES" | grep -q "eth0"; then
        WAN_INTERFACE="eth0"
    else
        WAN_INTERFACE=$(echo "$INTERFACES" | head -1)
    fi

    # LAN is the other interface (prefer USB adapter naming)
    for iface in $INTERFACES; do
        if [ "$iface" != "$WAN_INTERFACE" ]; then
            # Prefer USB adapter patterns
            if [[ "$iface" =~ ^enx ]] || [[ "$iface" =~ ^enp.*u ]] || [[ "$iface" == "eth1" ]]; then
                LAN_INTERFACE="$iface"
                break
            fi
        fi
    done

    # Fallback: use any available interface that's not WAN
    if [ -z "$LAN_INTERFACE" ]; then
        for iface in $INTERFACES; do
            if [ "$iface" != "$WAN_INTERFACE" ]; then
                LAN_INTERFACE="$iface"
                break
            fi
        done
    fi

    log_success "WAN Interface: $WAN_INTERFACE"
    log_success "LAN Interface: $LAN_INTERFACE"

    return 0
}

detect_usb_ethernet() {
    log_info "Scanning for USB ethernet adapters..."

    # USB ethernet adapter patterns
    USB_PATTERNS=(
        "eth1"
        "eth2"
        "enx[0-9a-f]*"      # MAC-based naming (enx001122334455)
        "enp*s*u*"          # USB path naming (enp0s20u1)
        "ens*u*"            # Alternative USB naming
    )

    # Check each pattern
    for pattern in "${USB_PATTERNS[@]}"; do
        FOUND=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E "^${pattern}$" | head -1)
        if [ -n "$FOUND" ]; then
            log_success "Found USB ethernet adapter: $FOUND"
            LAN_INTERFACE="$FOUND"
            return 0
        fi
    done

    # Check lsusb for USB network adapters
    if command -v lsusb &> /dev/null; then
        if lsusb | grep -qi "ethernet\|network\|lan\|realtek\|asix\|ax88"; then
            log_warning "USB network adapter detected but interface not found"
            log_info "Try: sudo dmesg | grep -i eth"
            log_info "Or unplug and replug the USB adapter"
        fi
    fi

    log_error "No USB ethernet adapter detected"
    log_info "Please connect a USB-to-Ethernet adapter for the second interface"
    return 1
}

# -----------------------------------------------------------------------------
# Prerequisite Checks
# -----------------------------------------------------------------------------
check_prerequisites() {
    log_info "Checking prerequisites..."

    ERRORS=0

    # Check root
    if [ "$EUID" -ne 0 ]; then
        log_error "Must run as root (use: sudo $0)"
        ERRORS=$((ERRORS + 1))
    fi

    # Check required tools
    REQUIRED_TOOLS="iptables dnsmasq ip sysctl"
    for tool in $REQUIRED_TOOLS; do
        if ! command -v $tool &> /dev/null; then
            log_error "Missing required tool: $tool"
            ERRORS=$((ERRORS + 1))
        else
            log_info "Found: $tool"
        fi
    done

    # Check for iptables modules
    if ! lsmod | grep -q "ip_tables"; then
        log_warning "ip_tables module may not be loaded"
    fi

    # Check interfaces
    if ! detect_interfaces; then
        ERRORS=$((ERRORS + 1))
    fi

    # Check if WAN has connectivity
    if ip link show "$WAN_INTERFACE" &> /dev/null; then
        if ip addr show "$WAN_INTERFACE" | grep -q "inet "; then
            WAN_IP=$(ip addr show "$WAN_INTERFACE" | grep "inet " | awk '{print $2}' | head -1)
            log_success "WAN interface $WAN_INTERFACE has IP: $WAN_IP"
        else
            log_warning "WAN interface $WAN_INTERFACE has no IP (will get via DHCP)"
        fi
    else
        log_error "WAN interface $WAN_INTERFACE not found"
        ERRORS=$((ERRORS + 1))
    fi

    # Check LAN interface exists
    if [ -n "$LAN_INTERFACE" ]; then
        if ip link show "$LAN_INTERFACE" &> /dev/null; then
            log_success "LAN interface $LAN_INTERFACE found"
        else
            log_error "LAN interface $LAN_INTERFACE not found"
            ERRORS=$((ERRORS + 1))
        fi
    else
        log_error "No LAN interface detected"
        ERRORS=$((ERRORS + 1))
    fi

    # Summary
    if [ $ERRORS -eq 0 ]; then
        log_success "All prerequisites met"
        return 0
    else
        log_error "Prerequisites check failed with $ERRORS errors"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Enable IP Forwarding
# -----------------------------------------------------------------------------
enable_ip_forwarding() {
    log_info "Enabling IP forwarding..."

    # Enable immediately
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Make persistent
    mkdir -p "$(dirname "$SYSCTL_CONFIG")"
    cat > "$SYSCTL_CONFIG" << EOF
# RAKSHAK Gateway - IP Forwarding
# Generated: $(date)

# Enable IPv4 forwarding (MANDATORY for gateway mode)
net.ipv4.ip_forward=1

# Disable IPv6 forwarding (not needed)
net.ipv6.conf.all.forwarding=0

# Security settings
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# Ignore ICMP broadcasts (Smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts=1

# Log martians (packets with impossible addresses)
net.ipv4.conf.all.log_martians=1
EOF

    sysctl -p "$SYSCTL_CONFIG" > /dev/null 2>&1

    # Verify
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
        log_success "IP forwarding enabled"
        return 0
    else
        log_error "Failed to enable IP forwarding"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Configure LAN Interface
# -----------------------------------------------------------------------------
configure_lan_interface() {
    log_info "Configuring LAN interface $LAN_INTERFACE..."

    # Calculate prefix from netmask
    PREFIX=$(echo "$LAN_NETMASK" | awk -F. '{
        split($0, a, ".");
        b=0;
        for(i=1;i<=4;i++) {
            n=a[i];
            while(n>0) {
                b+=n%2;
                n=int(n/2);
            }
        }
        print b
    }')

    # Bring interface up first
    ip link set "$LAN_INTERFACE" up

    # Flush existing configuration
    ip addr flush dev "$LAN_INTERFACE" 2>/dev/null || true

    # Set static IP
    ip addr add "$LAN_IP/$PREFIX" dev "$LAN_INTERFACE"

    # Verify
    if ip addr show "$LAN_INTERFACE" | grep -q "$LAN_IP"; then
        log_success "LAN interface configured: $LAN_IP/$PREFIX"
        return 0
    else
        log_error "Failed to configure LAN interface"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Setup NAT Rules
# -----------------------------------------------------------------------------
setup_nat() {
    log_info "Setting up NAT and firewall rules..."

    # Flush existing rules (preserve INPUT/OUTPUT for local services)
    iptables -t nat -F
    iptables -F FORWARD

    # Create RAKSHAK-specific chains
    # These chains allow organized rule management
    log_info "Creating RAKSHAK firewall chains..."

    # Create chains (ignore error if they already exist)
    iptables -N RAKSHAK_FORWARD 2>/dev/null || iptables -F RAKSHAK_FORWARD
    iptables -N RAKSHAK_ISOLATED 2>/dev/null || iptables -F RAKSHAK_ISOLATED
    iptables -N RAKSHAK_RATELIMIT 2>/dev/null || iptables -F RAKSHAK_RATELIMIT
    iptables -t nat -N RAKSHAK_HONEYPOT 2>/dev/null || iptables -t nat -F RAKSHAK_HONEYPOT

    # Insert jumps to RAKSHAK chains at the beginning of FORWARD
    # Order matters: ISOLATED -> RATELIMIT -> FORWARD
    iptables -I FORWARD 1 -j RAKSHAK_ISOLATED
    iptables -I FORWARD 2 -j RAKSHAK_RATELIMIT
    iptables -I FORWARD 3 -j RAKSHAK_FORWARD

    # NAT PREROUTING: Jump to honeypot chain for potential redirections
    iptables -t nat -I PREROUTING 1 -j RAKSHAK_HONEYPOT

    # NAT: Masquerade outgoing traffic on WAN (this is the core NAT rule)
    iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE

    # FORWARD: Allow LAN -> WAN (outgoing traffic)
    iptables -A RAKSHAK_FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT

    # FORWARD: Allow established/related connections WAN -> LAN (return traffic)
    iptables -A RAKSHAK_FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT

    # INPUT: Allow DHCP requests
    iptables -A INPUT -i "$LAN_INTERFACE" -p udp --dport 67:68 -j ACCEPT

    # INPUT: Allow DNS requests
    iptables -A INPUT -i "$LAN_INTERFACE" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$LAN_INTERFACE" -p tcp --dport 53 -j ACCEPT

    # INPUT: Allow RAKSHAK dashboard
    iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

    # INPUT: Allow honeypot ports
    iptables -A INPUT -p tcp --dport 2222 -j ACCEPT  # SSH honeypot
    iptables -A INPUT -p tcp --dport 2323 -j ACCEPT  # Telnet honeypot
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT  # HTTP honeypot

    # Block known malicious ports in FORWARD chain
    log_info "Adding malicious port blocks..."
    MALICIOUS_PORTS="4444 5555 6667 31337"
    for port in $MALICIOUS_PORTS; do
        iptables -A RAKSHAK_FORWARD -p tcp --dport "$port" -j DROP \
            -m comment --comment "rakshak-block-$port"
    done

    # Set default FORWARD policy to DROP (secure by default)
    # All allowed traffic must explicitly match a rule
    iptables -P FORWARD DROP

    # Save rules
    mkdir -p /etc/iptables
    iptables-save > "$IPTABLES_RULES"

    log_success "NAT and firewall rules configured"
    log_info "  - RAKSHAK_FORWARD chain created"
    log_info "  - RAKSHAK_ISOLATED chain created (for device isolation)"
    log_info "  - RAKSHAK_HONEYPOT chain created (for traffic redirection)"
}

# -----------------------------------------------------------------------------
# Configure DHCP Server
# -----------------------------------------------------------------------------
configure_dhcp() {
    log_info "Configuring DHCP server (dnsmasq)..."

    # Stop dnsmasq if running
    systemctl stop dnsmasq 2>/dev/null || true

    # Create configuration directory
    mkdir -p /etc/dnsmasq.d

    # Create RAKSHAK-specific configuration
    cat > "$DNSMASQ_CONFIG" << EOF
# =============================================================================
# RAKSHAK Gateway - DHCP/DNS Configuration
# Generated: $(date)
# =============================================================================

# Interface to serve DHCP on (LAN only)
interface=$LAN_INTERFACE
bind-interfaces

# Don't use /etc/resolv.conf
no-resolv

# Upstream DNS servers
server=$DNS_SERVER_1
server=$DNS_SERVER_2

# DHCP range
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_LEASE_TIME

# Gateway (this device - RAKSHAK)
dhcp-option=option:router,$LAN_IP

# DNS server (this device - provides DNS filtering)
dhcp-option=option:dns-server,$LAN_IP

# Domain
domain=rakshak.local
local=/rakshak.local/

# DHCP lease file (important for device tracking)
dhcp-leasefile=/var/lib/misc/dnsmasq.leases

# Log DHCP transactions (helps with device discovery)
log-dhcp

# Expand hostnames with domain
expand-hosts

# Set short lease for IoT devices (helps detect offline devices faster)
# Uncomment for more responsive device tracking:
# dhcp-option=option:lease-time,3600

# =============================================================================
# DNS Blocking (optional - uncomment to enable)
# =============================================================================
# Block known malicious domains (sinkhole to 0.0.0.0)
# address=/malware-domain.com/0.0.0.0
# address=/botnet-c2.net/0.0.0.0

# =============================================================================
# Static DHCP assignments (optional)
# =============================================================================
# Assign static IPs to known devices for easier management
# dhcp-host=AA:BB:CC:DD:EE:FF,192.168.100.100,smart-tv
# dhcp-host=11:22:33:44:55:66,192.168.100.101,camera

EOF

    # Create lease file directory
    mkdir -p /var/lib/misc
    touch /var/lib/misc/dnsmasq.leases
    chmod 644 /var/lib/misc/dnsmasq.leases

    # Start dnsmasq
    systemctl enable dnsmasq
    systemctl start dnsmasq

    # Verify
    sleep 1
    if systemctl is-active --quiet dnsmasq; then
        log_success "DHCP server started"
        log_info "  DHCP Range: $DHCP_RANGE_START - $DHCP_RANGE_END"
        log_info "  Gateway IP: $LAN_IP"
        log_info "  DNS: $DNS_SERVER_1, $DNS_SERVER_2"
        return 0
    else
        log_error "Failed to start DHCP server"
        systemctl status dnsmasq
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Start Gateway
# -----------------------------------------------------------------------------
start_gateway() {
    print_banner
    echo ""

    log_info "Starting RAKSHAK Inline Security Gateway..."
    echo ""

    # Detect platform
    detect_jetson

    # Check prerequisites
    if ! check_prerequisites; then
        log_error "Cannot start gateway - prerequisites not met"
        echo ""
        echo "Troubleshooting steps:"
        echo "  1. Ensure you have 2 network interfaces"
        echo "  2. Connect a USB-to-Ethernet adapter if needed"
        echo "  3. Run as root: sudo $0 --start"
        exit 1
    fi

    echo ""

    # Enable IP forwarding
    if ! enable_ip_forwarding; then
        exit 1
    fi

    # Configure LAN interface
    if ! configure_lan_interface; then
        exit 1
    fi

    # Setup NAT and firewall
    if ! setup_nat; then
        exit 1
    fi

    # Configure DHCP
    if ! configure_dhcp; then
        exit 1
    fi

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}     RAKSHAK GATEWAY ACTIVE${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "  Network Topology:"
    echo "  Internet -> Modem -> [$WAN_INTERFACE] JETSON [$LAN_INTERFACE] -> Router (AP) -> IoT"
    echo ""
    echo "  WAN Interface: $WAN_INTERFACE"
    echo "  LAN Interface: $LAN_INTERFACE"
    echo "  Gateway IP:    $LAN_IP"
    echo "  DHCP Range:    $DHCP_RANGE_START - $DHCP_RANGE_END"
    echo "  DNS Servers:   $DNS_SERVER_1, $DNS_SERVER_2"
    if [ "$JETSON_PLATFORM" = true ]; then
        echo "  Platform:      Jetson (optimized)"
    fi
    echo ""
    echo "  Next steps:"
    echo "    1. Connect modem ethernet to $WAN_INTERFACE"
    echo "    2. Connect router (in AP mode) to $LAN_INTERFACE"
    echo "    3. Run RAKSHAK: sudo python main.py"
    echo ""
    echo -e "${GREEN}============================================================${NC}"

    log_success "RAKSHAK Gateway started successfully"
}

# -----------------------------------------------------------------------------
# Stop Gateway
# -----------------------------------------------------------------------------
stop_gateway() {
    log_info "Stopping RAKSHAK Gateway..."

    # Stop dnsmasq
    systemctl stop dnsmasq 2>/dev/null || true

    # Remove RAKSHAK firewall chains
    log_info "Removing RAKSHAK firewall rules..."

    # Remove jumps to RAKSHAK chains
    for i in $(seq 1 10); do
        iptables -D FORWARD -j RAKSHAK_ISOLATED 2>/dev/null || true
        iptables -D FORWARD -j RAKSHAK_RATELIMIT 2>/dev/null || true
        iptables -D FORWARD -j RAKSHAK_FORWARD 2>/dev/null || true
        iptables -t nat -D PREROUTING -j RAKSHAK_HONEYPOT 2>/dev/null || true
    done

    # Flush and delete RAKSHAK chains
    iptables -F RAKSHAK_FORWARD 2>/dev/null || true
    iptables -X RAKSHAK_FORWARD 2>/dev/null || true
    iptables -F RAKSHAK_ISOLATED 2>/dev/null || true
    iptables -X RAKSHAK_ISOLATED 2>/dev/null || true
    iptables -F RAKSHAK_RATELIMIT 2>/dev/null || true
    iptables -X RAKSHAK_RATELIMIT 2>/dev/null || true
    iptables -t nat -F RAKSHAK_HONEYPOT 2>/dev/null || true
    iptables -t nat -X RAKSHAK_HONEYPOT 2>/dev/null || true

    # Flush NAT rules
    iptables -t nat -F

    # Reset FORWARD policy to ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -F FORWARD

    # Disable IP forwarding
    echo 0 > /proc/sys/net/ipv4/ip_forward

    # Remove configuration files
    rm -f "$DNSMASQ_CONFIG" 2>/dev/null || true
    rm -f "$SYSCTL_CONFIG" 2>/dev/null || true

    log_success "RAKSHAK Gateway stopped"
}

# -----------------------------------------------------------------------------
# Show Status
# -----------------------------------------------------------------------------
show_status() {
    echo ""
    echo "============================================================"
    echo "     RAKSHAK GATEWAY STATUS"
    echo "============================================================"
    echo ""

    # Platform
    detect_jetson
    echo "Platform:"
    if [ "$JETSON_PLATFORM" = true ]; then
        echo -e "  ${GREEN}Jetson Platform Detected${NC}"
    else
        echo "  Standard Linux"
    fi

    # IP forwarding
    echo ""
    echo "IP Forwarding:"
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
        echo -e "  ${GREEN}Enabled${NC}"
    else
        echo -e "  ${RED}Disabled${NC}"
    fi

    # DHCP Server
    echo ""
    echo "DHCP Server (dnsmasq):"
    if systemctl is-active --quiet dnsmasq; then
        echo -e "  ${GREEN}Running${NC}"
    else
        echo -e "  ${RED}Not running${NC}"
    fi

    # Network Interfaces
    echo ""
    echo "Network Interfaces:"
    echo "  WAN ($WAN_INTERFACE):"
    if ip link show "$WAN_INTERFACE" &> /dev/null; then
        WAN_IP=$(ip addr show "$WAN_INTERFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        WAN_STATE=$(ip link show "$WAN_INTERFACE" | grep -o "state [A-Z]*" | awk '{print $2}')
        echo "    IP: ${WAN_IP:-none}"
        echo "    State: $WAN_STATE"
    else
        echo -e "    ${RED}Not found${NC}"
    fi

    echo "  LAN ($LAN_INTERFACE):"
    if ip link show "$LAN_INTERFACE" &> /dev/null; then
        LAN_ACTUAL_IP=$(ip addr show "$LAN_INTERFACE" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
        LAN_STATE=$(ip link show "$LAN_INTERFACE" | grep -o "state [A-Z]*" | awk '{print $2}')
        echo "    IP: ${LAN_ACTUAL_IP:-none}"
        echo "    State: $LAN_STATE"
    else
        echo -e "    ${RED}Not found${NC}"
    fi

    # DHCP Leases
    echo ""
    echo "DHCP Leases (Connected Devices):"
    if [ -f /var/lib/misc/dnsmasq.leases ]; then
        LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases)
        echo "  Active leases: $LEASE_COUNT"
        if [ "$LEASE_COUNT" -gt 0 ]; then
            echo "  Devices:"
            while read -r line; do
                LEASE_TIME=$(echo "$line" | awk '{print $1}')
                MAC=$(echo "$line" | awk '{print $2}')
                IP=$(echo "$line" | awk '{print $3}')
                HOST=$(echo "$line" | awk '{print $4}')
                echo "    $IP - $MAC - ${HOST:-unknown}"
            done < /var/lib/misc/dnsmasq.leases
        fi
    else
        echo "  No lease file found"
    fi

    # RAKSHAK Firewall Chains
    echo ""
    echo "RAKSHAK Firewall Chains:"
    if iptables -L RAKSHAK_FORWARD -n &> /dev/null; then
        echo -e "  RAKSHAK_FORWARD: ${GREEN}Active${NC}"
        FORWARD_RULES=$(iptables -L RAKSHAK_FORWARD -n 2>/dev/null | tail -n +3 | wc -l)
        echo "    Rules: $FORWARD_RULES"
    else
        echo -e "  RAKSHAK_FORWARD: ${YELLOW}Not created${NC}"
    fi

    if iptables -L RAKSHAK_ISOLATED -n &> /dev/null; then
        echo -e "  RAKSHAK_ISOLATED: ${GREEN}Active${NC}"
        ISOLATED_RULES=$(iptables -L RAKSHAK_ISOLATED -n 2>/dev/null | tail -n +3 | wc -l)
        echo "    Rules: $ISOLATED_RULES (isolated devices)"
    else
        echo -e "  RAKSHAK_ISOLATED: ${YELLOW}Not created${NC}"
    fi

    if iptables -t nat -L RAKSHAK_HONEYPOT -n &> /dev/null; then
        echo -e "  RAKSHAK_HONEYPOT: ${GREEN}Active${NC}"
        HONEYPOT_RULES=$(iptables -t nat -L RAKSHAK_HONEYPOT -n 2>/dev/null | tail -n +3 | wc -l)
        echo "    Rules: $HONEYPOT_RULES (redirections)"
    else
        echo -e "  RAKSHAK_HONEYPOT: ${YELLOW}Not created${NC}"
    fi

    # NAT Rules
    echo ""
    echo "NAT MASQUERADE:"
    if iptables -t nat -L POSTROUTING -n -v 2>/dev/null | grep -q "MASQUERADE"; then
        echo -e "  ${GREEN}Active on $WAN_INTERFACE${NC}"
    else
        echo -e "  ${RED}Not configured${NC}"
    fi

    echo ""
    echo "============================================================"
}

# -----------------------------------------------------------------------------
# Install Dependencies
# -----------------------------------------------------------------------------
install_dependencies() {
    log_info "Installing dependencies..."

    # Detect package manager
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y dnsmasq iptables iproute2 net-tools
    elif command -v dnf &> /dev/null; then
        dnf install -y dnsmasq iptables iproute net-tools
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm dnsmasq iptables iproute2 net-tools
    else
        log_error "Unsupported package manager"
        return 1
    fi

    # Stop dnsmasq for now (will configure later)
    systemctl stop dnsmasq 2>/dev/null || true
    systemctl disable dnsmasq 2>/dev/null || true

    log_success "Dependencies installed"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
case "$1" in
    --start)
        start_gateway
        ;;
    --stop)
        if [ "$EUID" -ne 0 ]; then
            log_error "Must run as root (use: sudo $0 --stop)"
            exit 1
        fi
        stop_gateway
        ;;
    --status)
        show_status
        ;;
    --check)
        print_banner
        detect_jetson
        check_prerequisites
        ;;
    --install-deps)
        if [ "$EUID" -ne 0 ]; then
            log_error "Must run as root (use: sudo $0 --install-deps)"
            exit 1
        fi
        install_dependencies
        ;;
    --help|-h)
        print_banner
        echo "Usage: sudo $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --start         Start gateway mode"
        echo "  --stop          Stop gateway mode"
        echo "  --status        Show gateway status"
        echo "  --check         Check prerequisites only"
        echo "  --install-deps  Install required dependencies"
        echo "  --help          Show this help"
        echo ""
        echo "Environment Variables (optional):"
        echo "  WAN_INTERFACE      WAN interface (default: eth0)"
        echo "  LAN_INTERFACE      LAN interface (default: eth1 or auto-detect)"
        echo "  LAN_IP             Gateway IP (default: 192.168.100.1)"
        echo "  DHCP_RANGE_START   DHCP start (default: 192.168.100.10)"
        echo "  DHCP_RANGE_END     DHCP end (default: 192.168.100.250)"
        echo ""
        echo "Example:"
        echo "  sudo ./setup_gateway.sh --start"
        echo "  sudo LAN_INTERFACE=enx001122334455 ./setup_gateway.sh --start"
        echo ""
        ;;
    *)
        print_banner
        detect_jetson
        detect_interfaces
        echo ""
        echo "Use --start to start gateway mode"
        echo "Use --status to show current status"
        echo "Use --help for more options"
        echo ""
        ;;
esac

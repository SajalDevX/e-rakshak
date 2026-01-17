#!/bin/bash
# =============================================================================
# RAKSHAK Bridge Verification Script
# =============================================================================
# Convenience wrapper to verify bridge mode is working correctly.
#
# Usage:
#   sudo ./verify_bridge.sh
#
# Checks:
#   1. Bridge br0 exists
#   2. Bridge has correct IP
#   3. Member interface attached
#   4. bridge-nf-call-iptables enabled
#   5. IP forwarding enabled
#   6. dnsmasq running and bound to bridge
#   7. RAKSHAK firewall chains exist
#   8. NAT MASQUERADE configured
#   9. ARP entries (no incomplete)
#   10. Device visibility
#
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Call the main setup script with --verify
exec "$SCRIPT_DIR/setup_bridge.sh" --verify

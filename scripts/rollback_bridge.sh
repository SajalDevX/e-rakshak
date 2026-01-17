#!/bin/bash
# =============================================================================
# RAKSHAK Bridge Rollback Script
# =============================================================================
# Convenience wrapper to revert bridge mode back to direct interface mode.
#
# Usage:
#   sudo ./rollback_bridge.sh
#
# This script:
#   1. Removes br0 bridge
#   2. Restores IP to original LAN interface
#   3. Updates dnsmasq configuration
#   4. Cleans up kernel settings
#
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Must run as root (use: sudo $0)"
    exit 1
fi

# Call the main setup script with --stop
exec "$SCRIPT_DIR/setup_bridge.sh" --stop

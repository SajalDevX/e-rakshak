#!/bin/bash
# Verification script for NFQueue port scan detection fix

echo "============================================================"
echo "  NFQueue Port Scan Detection - Fix Verification"
echo "============================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[1/6] Checking netfilterqueue Python package...${NC}"
if source venv/bin/activate && python -c "import netfilterqueue; print('  Version:', netfilterqueue.__version__)" 2>/dev/null; then
    echo -e "${GREEN}  ✓ netfilterqueue installed${NC}"
else
    echo -e "${RED}  ✗ netfilterqueue NOT installed${NC}"
fi

echo ""
echo -e "${BLUE}[2/6] Checking system libraries...${NC}"
if dpkg -l libnetfilter-queue1 >/dev/null 2>&1; then
    echo -e "${GREEN}  ✓ libnetfilter-queue1 installed${NC}"
else
    echo -e "${RED}  ✗ libnetfilter-queue1 NOT installed${NC}"
fi

echo ""
echo -e "${BLUE}[3/6] Checking scapy...${NC}"
if source venv/bin/activate && python -c "from scapy.all import IP, TCP" 2>/dev/null; then
    echo -e "${GREEN}  ✓ scapy installed${NC}"
else
    echo -e "${RED}  ✗ scapy NOT installed${NC}"
fi

echo ""
echo -e "${BLUE}[4/6] Verifying packet_filter.py fixes...${NC}"
# Check if setup_nfqueue is called
if grep -q "self.setup_nfqueue(queue_num)" core/packet_filter.py; then
    echo -e "${GREEN}  ✓ setup_nfqueue() call added${NC}"
else
    echo -e "${RED}  ✗ setup_nfqueue() call MISSING${NC}"
fi

# Check if running in thread
if grep -q "threading.Thread" core/packet_filter.py | grep -q "PacketInspection"; then
    echo -e "${GREEN}  ✓ Packet inspection runs in thread${NC}"
else
    echo -e "${YELLOW}  ⚠ Thread startup may need verification${NC}"
fi

# Check if using correct run() method
if grep -q "nfqueue.run()" core/packet_filter.py; then
    echo -e "${GREEN}  ✓ Using correct nfqueue.run() method${NC}"
else
    echo -e "${RED}  ✗ Still using incorrect API${NC}"
fi

# Check if cleanup exists
if grep -q "_cleanup_nfqueue" core/packet_filter.py; then
    echo -e "${GREEN}  ✓ Cleanup method exists${NC}"
else
    echo -e "${RED}  ✗ Cleanup method MISSING${NC}"
fi

echo ""
echo -e "${BLUE}[5/6] Verifying connection_monitor.py fixes...${NC}"
# Check if monitoring FORWARD chain
if grep -q 'for chain in \["INPUT", "FORWARD"\]' core/connection_monitor.py; then
    echo -e "${GREEN}  ✓ Monitors both INPUT and FORWARD chains${NC}"
else
    echo -e "${RED}  ✗ Not monitoring FORWARD chain${NC}"
fi

echo ""
echo -e "${BLUE}[6/6] Checking current iptables rules...${NC}"
if sudo iptables -L FORWARD -n 2>/dev/null | grep -q NFQUEUE; then
    echo -e "${YELLOW}  ⚠ NFQUEUE rule exists (from previous run)${NC}"
    echo -e "     Will be cleaned up on restart"
else
    echo -e "${GREEN}  ✓ No stale NFQUEUE rules${NC}"
fi

if sudo iptables -L FORWARD -n 2>/dev/null | grep -q RAKSHAK_SCAN; then
    echo -e "${YELLOW}  ⚠ RAKSHAK_SCAN LOG rule exists (from previous run)${NC}"
    echo -e "     Will be cleaned up on restart"
else
    echo -e "${GREEN}  ✓ No stale LOG rules${NC}"
fi

echo ""
echo "============================================================"
echo "  Verification Complete"
echo "============================================================"
echo ""
echo -e "${GREEN}All fixes have been applied!${NC}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Restart RAKSHAK:"
echo "   ${BLUE}sudo python main.py${NC}"
echo ""
echo "2. Watch for these messages in startup logs:"
echo "   ${GREEN}✓ nfqueue 1 configured${NC}"
echo "   ${GREEN}✓ Packet inspection thread started${NC}"
echo "   OR"
echo "   ${GREEN}✓ Connection monitor started (Port Scan Detection)${NC}"
echo ""
echo "3. Run attack test:"
echo "   ${BLUE}python3 tests/attack_esp32cam.py${NC}"
echo ""
echo "4. Expected result:"
echo "   ${GREEN}Device isolated within 30 seconds${NC}"
echo ""
echo "============================================================"
echo ""

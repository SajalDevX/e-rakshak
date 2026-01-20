#!/bin/bash
# Check if everything is ready for ESP32-CAM attack testing

echo "============================================================"
echo "  RAKSHAK Attack Testing Readiness Check"
echo "============================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Target device
TARGET_IP="10.42.0.103"
TARGET_MAC="94:b9:7e:fa:e3:58"

# Check 1: RAKSHAK running
echo -n "1. RAKSHAK Dashboard: "
if curl -s http://localhost:5000/api/status > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Running${NC}"
else
    echo -e "${RED}✗ Not running${NC}"
    echo "   Start with: ./start_monitoring.sh"
fi

# Check 2: ESP32-CAM reachable
echo -n "2. ESP32-CAM (${TARGET_IP}): "
if ping -c 1 -W 1 ${TARGET_IP} > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Reachable${NC}"
else
    echo -e "${RED}✗ Not reachable${NC}"
    echo "   Check if ESP32-CAM is powered on and connected"
fi

# Check 3: Camera stream accessible
echo -n "3. Camera HTTP Service: "
if curl -s -m 2 http://${TARGET_IP}/ > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Accessible${NC}"
else
    echo -e "${YELLOW}⚠ Not accessible${NC}"
    echo "   Camera may need restart or check ESP32 code"
fi

# Check 4: Device in RAKSHAK
echo -n "4. Device in RAKSHAK: "
DEVICE_STATUS=$(curl -s http://localhost:5000/api/devices/${TARGET_IP} 2>/dev/null | jq -r '.data.status' 2>/dev/null)
if [ ! -z "$DEVICE_STATUS" ] && [ "$DEVICE_STATUS" != "null" ]; then
    echo -e "${GREEN}✓ Found (status: ${DEVICE_STATUS})${NC}"

    # Check if already isolated
    if [ "$DEVICE_STATUS" == "isolated" ]; then
        echo -e "   ${YELLOW}⚠ Device is currently ISOLATED${NC}"
        echo "   Un-isolate before testing: curl -X POST http://localhost:5000/api/devices/${TARGET_IP}/unisolate"
    fi
else
    echo -e "${YELLOW}⚠ Not found${NC}"
    echo "   Wait for device discovery or trigger scan"
fi

# Check 5: nmap installed
echo -n "5. nmap tool: "
if command -v nmap > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Installed ($(nmap --version | head -1))${NC}"
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "   Install with: sudo apt install nmap"
fi

# Check 6: Python dependencies
echo -n "6. Python requests: "
if python3 -c "import requests" 2>/dev/null; then
    echo -e "${GREEN}✓ Installed${NC}"
else
    echo -e "${RED}✗ Not installed${NC}"
    echo "   Install with: pip install requests"
fi

# Check 7: PortScanDetector enabled
echo -n "7. PortScanDetector: "
if grep -q '"enabled": true' config/config.yaml 2>/dev/null; then
    echo -e "${GREEN}✓ Enabled${NC}"
else
    echo -e "${YELLOW}⚠ Check config${NC}"
fi

echo ""
echo "============================================================"
echo "Ready to test? Run:"
echo "  python3 tests/attack_esp32cam.py"
echo "  or with root for full tests:"
echo "  sudo python3 tests/attack_esp32cam.py"
echo "============================================================"

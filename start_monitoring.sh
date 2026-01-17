#!/bin/bash
# e-raksha Real-Time Monitoring Setup
# Opens multiple terminal windows to monitor all aspects of attack detection

RAKSHAK_DIR="/home/sajal/Desktop/Hackathons/e-raksha"
TARGET_IP="10.42.0.103"

echo "=========================================="
echo "e-raksha Real-Time Monitoring Setup"
echo "=========================================="
echo "Target Camera: $TARGET_IP"
echo ""

# Check if e-raksha is running
if ! pgrep -f "python.*main.py" > /dev/null; then
    echo "⚠️  WARNING: e-raksha is not running!"
    echo ""
    echo "Start it first with:"
    echo "  cd $RAKSHAK_DIR"
    echo "  sudo python main.py"
    echo ""
    read -p "Press Enter to continue anyway or Ctrl+C to exit..."
fi

# Function to open terminal with command
open_terminal() {
    local title="$1"
    local command="$2"

    # Try gnome-terminal first
    if command -v gnome-terminal &> /dev/null; then
        gnome-terminal --title="$title" -- bash -c "$command; exec bash" &
    # Try xterm
    elif command -v xterm &> /dev/null; then
        xterm -T "$title" -e bash -c "$command; exec bash" &
    # Try konsole (KDE)
    elif command -v konsole &> /dev/null; then
        konsole --title "$title" -e bash -c "$command; exec bash" &
    else
        echo "❌ No terminal emulator found (tried: gnome-terminal, xterm, konsole)"
        echo "Run this command manually in a new terminal:"
        echo "  $command"
    fi
    sleep 0.5
}

echo "Opening monitoring terminals..."
echo ""

# Terminal 1: Threat Detection Log
echo "[1/5] Opening threat detection log..."
open_terminal "e-raksha: Threat Detection" \
    "cd $RAKSHAK_DIR && echo '=== e-raksha Threat Detection Log ===' && tail -f data/logs/rakshak.log | grep --line-buffered -E 'Threat|Port Scan|Response Engine|ISOLATE'"

# Terminal 2: Port Scan Detection
echo "[2/5] Opening port scan detector..."
open_terminal "e-raksha: Port Scan Detector" \
    "cd $RAKSHAK_DIR && echo '=== Port Scan Detection ===' && tail -f data/logs/rakshak.log | grep --line-buffered -E 'Port Scan|SYN scan|ports scanned'"

# Terminal 3: Response Engine Decisions
echo "[3/5] Opening response engine log..."
open_terminal "e-raksha: Response Decisions" \
    "cd $RAKSHAK_DIR && echo '=== Response Engine Decisions ===' && tail -f data/logs/rakshak.log | grep --line-buffered -E 'Response Engine|Response Decision|escalating|Response Level'"

# Terminal 4: Device Status Monitor
echo "[4/5] Opening device status monitor..."
open_terminal "e-raksha: Device Status" \
    "cd $RAKSHAK_DIR && echo '=== Device Status Monitor ===' && watch -n 2 'sqlite3 data/rakshak.db \"SELECT ip, device_type, status, risk_score, zone FROM devices WHERE ip=\\\"$TARGET_IP\\\"\"'"

# Terminal 5: Live Threat Count
echo "[5/5] Opening threat counter..."
open_terminal "e-raksha: Live Threats" \
    "cd $RAKSHAK_DIR && echo '=== Live Threat Feed ===' && watch -n 1 'sqlite3 data/rakshak.db \"SELECT timestamp, type, severity, source_ip, action_taken FROM threats ORDER BY timestamp DESC LIMIT 10\"'"

echo ""
echo "✅ Monitoring terminals opened!"
echo ""
echo "=========================================="
echo "Now you can perform attacks:"
echo "=========================================="
echo ""
echo "Quick Attack Commands:"
echo ""
echo "1. Port Scan:"
echo "   nmap -T4 $TARGET_IP"
echo ""
echo "2. HTTP Enumeration:"
echo "   for i in {1..20}; do curl -s http://$TARGET_IP/ > /dev/null; sleep 0.3; done"
echo ""
echo "3. Stream Access:"
echo "   for i in {1..15}; do timeout 2s curl http://$TARGET_IP/stream -o /dev/null 2>&1; sleep 0.5; done"
echo ""
echo "4. Command Injection:"
echo "   curl 'http://$TARGET_IP/?cmd=;ls'"
echo "   curl 'http://$TARGET_IP/stream?debug=\`whoami\`'"
echo ""
echo "5. Full Attack Sequence:"
echo "   See: REAL_ATTACK_GUIDE.md"
echo ""
echo "=========================================="
echo "Dashboard: http://10.42.0.1:5000"
echo "=========================================="
echo ""
echo "Watch the monitoring terminals for real-time detection!"
echo ""

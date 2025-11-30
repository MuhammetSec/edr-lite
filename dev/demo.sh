#!/bin/bash
# Demo Script - Sample scenarios to test the EDR system

echo "🎬 EDR Process Monitor Demo"
echo "=============================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

show_menu() {
    echo ""
    echo "What would you like to try?"
    echo ""
    echo -e "  ${GREEN}1)${NC} Quick Simulation Test (no psutil required)"
    echo -e "  ${BLUE}2)${NC} Review Tool Demo (with sample data)"
    echo -e "  ${YELLOW}3)${NC} Real Monitoring (requires psutil - background 30 seconds)"
    echo -e "  ${RED}4)${NC} Clean Logs"
    echo -e "  ${GREEN}5)${NC} Show Statistics"
    echo "  0) Exit"
    echo ""
}

simulate_test() {
    echo ""
    echo -e "${BLUE}📊 Running simulation test...${NC}"
    echo ""
    python3 dev/_test_simulated_run.py
    echo ""
    echo -e "${GREEN}✓${NC} Simulation completed!"
    echo ""
    echo "Generated logs:"
    echo "  - logs/test_alerts.jsonl"
    echo ""
    echo "To see the last alert:"
    echo -e "  ${YELLOW}tail -1 logs/test_alerts.jsonl | python3 -m json.tool${NC}"
}

demo_review() {
    echo ""
    echo -e "${BLUE}🔍 Preparing sample data for review tool...${NC}"
    
    # Create sample review data
    cat > logs/review_queue.jsonl << 'DEMOEOF'
{"pid": 3001, "severity": "MEDIUM", "risk_score": 50, "matches": ["curl(25)", "https://(25)"], "event": {"pid": 3001, "name": "curl", "exe": "/usr/bin/curl", "cmdline": "curl https://api.github.com/repos/python/cpython", "username": "developer", "create_time": 1701350000}, "timestamp": "2025-11-30T14:00:00Z", "status": "NEEDS_REVIEW", "reviewed": false}
{"pid": 3002, "severity": "MEDIUM", "risk_score": 45, "matches": ["http://(35)"], "event": {"pid": 3002, "name": "wget", "exe": "/usr/bin/wget", "cmdline": "wget http://releases.ubuntu.com/22.04/ubuntu-22.04-desktop-amd64.iso", "username": "user", "create_time": 1701350100}, "timestamp": "2025-11-30T14:05:00Z", "status": "NEEDS_REVIEW", "reviewed": false}
{"pid": 3003, "severity": "MEDIUM", "risk_score": 60, "matches": ["bash -c(60)", "sh -c(60)"], "event": {"pid": 3003, "name": "bash", "exe": "/bin/bash", "cmdline": "bash -c 'echo hello world'", "username": "admin", "create_time": 1701350200}, "timestamp": "2025-11-30T14:10:00Z", "status": "NEEDS_REVIEW", "reviewed": false}
DEMOEOF
    
    echo -e "${GREEN}✓${NC} 3 sample records prepared"
    echo ""
    echo "To launch the review tool:"
    echo -e "  ${YELLOW}python3 review_tool.py${NC}"
    echo ""
    echo "To see statistics:"
    echo -e "  ${YELLOW}python3 review_tool.py --stats${NC}"
    echo ""
    read -p "Would you like to run the review tool now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        python3 review_tool.py --stats
    fi
}

real_monitor() {
    echo ""
    echo -e "${YELLOW}⚠️  Real system monitoring mode${NC}"
    echo ""
    
    # psutil check
    if ! python3 -c "import psutil" 2>/dev/null; then
        echo -e "${RED}✗${NC} psutil is not available in the current environment!"
        echo ""
        
        # Check if virtualenv exists
        if [ -d .venv ]; then
            echo "Found .venv - activating it now..."
            echo ""
            source .venv/bin/activate
            
            # Re-check after activation
            if ! python3 -c "import psutil" 2>/dev/null; then
                echo -e "${RED}✗${NC} psutil not found even in .venv!"
                echo ""
                echo "To install:"
                echo -e "  ${BLUE}source .venv/bin/activate${NC}"
                echo -e "  ${BLUE}pip install -r requirements.txt${NC}"
                return 1
            fi
            echo -e "${GREEN}✓${NC} psutil found in .venv"
        else
            echo "To install:"
            echo -e "  ${BLUE}python3 -m venv .venv${NC}"
            echo -e "  ${BLUE}source .venv/bin/activate${NC}"
            echo -e "  ${BLUE}pip install -r requirements.txt${NC}"
            echo ""
            return 1
        fi
    fi
    
    echo -e "${GREEN}✓${NC} psutil found"
    echo ""
    echo "The monitor will run in the background for 30 seconds..."
    echo "During this time you can run commands in other terminal windows."
    echo ""
    read -p "Press Enter to start (or Ctrl-C to cancel)..." 
    
    # Run in background for 30 seconds
    # Use a cross-platform approach (timeout may not exist on macOS)
    python3 main.py &
    PID=$!
    
    echo ""
    echo -e "${BLUE}Monitor started (PID: $PID)${NC}"
    echo ""
    echo "Now you can open another terminal window and try these:"
    echo -e "  ${YELLOW}curl https://example.com${NC}"
    echo -e "  ${YELLOW}python3 -m http.server 9000${NC} (then stop with Ctrl-C)"
    echo -e "  ${YELLOW}bash -c 'ls -la'${NC}"
    echo ""
    
    # Wait 30 seconds
    for i in {30..1}; do
        echo -ne "\rTime remaining: $i seconds  "
        sleep 1
    done
    
    # Stop the monitor
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    
    echo ""
    echo ""
    echo -e "${GREEN}✓${NC} Monitoring completed!"
    echo ""
    
    # Show results
    if [ -f logs/alerts.jsonl ]; then
        ALERT_COUNT=$(wc -l < logs/alerts.jsonl)
        echo "🚨 Alerts: $ALERT_COUNT records"
    fi
    
    if [ -f logs/process_log.jsonl ]; then
        PROCESS_COUNT=$(wc -l < logs/process_log.jsonl)
        echo "📝 Processes logged: $PROCESS_COUNT (--log-all was enabled)"
    fi
    
    echo ""
    echo "To see details:"
    echo -e "  ${YELLOW}python3 review_tool.py --stats${NC}"
}

clean_logs() {
    echo ""
    read -p "All log files will be deleted. Are you sure? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf logs/*.jsonl
        echo -e "${GREEN}✓${NC} Logs cleaned"
    else
        echo "Cancelled"
    fi
}

show_stats() {
    echo ""
    if [ ! -d logs ] || [ -z "$(ls -A logs 2>/dev/null)" ]; then
        echo -e "${YELLOW}⚠${NC}  No log files yet. Run a test first."
        return
    fi
    
    python3 review_tool.py --stats
}

# Main loop
while true; do
    show_menu
    read -p "Your choice: " choice
    
    case $choice in
        1) simulate_test ;;
        2) demo_review ;;
        3) real_monitor ;;
        4) clean_logs ;;
        5) show_stats ;;
        0) echo ""; echo "👋 See you later!"; exit 0 ;;
        *) echo -e "${RED}Invalid choice!${NC}" ;;
    esac
done

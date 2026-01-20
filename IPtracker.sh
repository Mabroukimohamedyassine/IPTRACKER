#!/bin/bash

# ==========================================
# SHIELD SERVER - FORENSIC TRACKER CONTROLLER
# ==========================================

# 1. Configuration
# Get the directory where this script is stored
TOOL_DIR=$(dirname "$(readlink -f "$0")")
SRC_DIR="$TOOL_DIR/src"
MAIN_SCRIPT="$SRC_DIR/main.py"
DB_DIR="$TOOL_DIR/data"
REQUIREMENTS="$TOOL_DIR/requirements.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 2. Root Privilege Check
# We need root to sniff network traffic and run Nmap OS detection
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] ERROR: This tool requires ROOT privileges.${NC}"
  echo -e "${YELLOW}Please run: sudo ./IPtracker.sh${NC}"
  exit 1
fi

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE}   SHIELD SERVER - FORENSIC TRACKER       ${NC}"
echo -e "${BLUE}==========================================${NC}"

# 3. Environment Setup
echo -e "${YELLOW}[*] Checking system environment...${NC}"

# Check/Install Python3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Installing...${NC}"
    apt-get update && apt-get install -y python3 python3-pip
fi

# Check/Install Nmap (The System Binary)
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}[!] Nmap binary not found. Installing...${NC}"
    apt-get install -y nmap
fi

# Install Python Dependencies from requirements.txt
if [ -f "$REQUIREMENTS" ]; then
    echo -e "${YELLOW}[*] Verifying Python libraries...${NC}"
    # We use --break-system-packages on newer Kali versions if needed, 
    # but standard pip install usually works. 
    pip3 install -r "$REQUIREMENTS" --quiet
else
    echo -e "${RED}[!] Warning: requirements.txt not found!${NC}"
fi

# 4. Directory Setup
# We ensure the 'data' folder exists for the database
if [ ! -d "$DB_DIR" ]; then
    echo -e "${YELLOW}[*] Creating data directory: $DB_DIR${NC}"
    mkdir -p "$DB_DIR"
fi

# 5. Execution
echo -e "${GREEN}[+] Initialization complete.${NC}"
echo -e "${GREEN}[+] Starting Surveillance Engine...${NC}"
echo -e "${YELLOW}[i] Press Ctrl+C to stop the tracker safely.${NC}"
echo -e "------------------------------------------"

# Run the Python Brain
# We pass the arguments to the python script just in case
python3 "$MAIN_SCRIPT" "$@"

# 6. Cleanup
echo -e "\n${YELLOW}[*] Tracker stopped. Goodbye.${NC}"
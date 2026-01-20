# 🛡️ Shield Server - Network Forensic Tracker

**A Hybrid Network Surveillance & Active Defense System for Linux.**

> **⚠️ LEGAL DISCLAIMER:** This tool performs **active network scanning** (Nmap) against incoming IP addresses. Ensure you have legal authorization to scan the networks interacting with your server. The author is not responsible for misuse.

---

## 📖 Overview

**IPTracker** is a Python-based forensic tool designed to turn a Linux server into a defensive monitoring node. It combines **Passive Sniffing** with **Active Scanning** to identify and profile potential intruders in real-time.

Unlike standard firewalls that simply block or log packets, Shield Server:
1.  **Detects** the packet silently (Passive).
2.  **Analyzes** the source IP against a history database.
3.  **Counter-Scans** the intruder using Nmap to identify their OS, open ports, and vulnerabilities.

### 🚀 Key Features

* **🕵️ Passive Sniffing:** Captures TCP/UDP traffic without interfering with latency (using `Scapy`).
* **⚡ Active Defense:** Automatically launches a background **Nmap Stealth Scan** (`-sS -O`) against new visitors.
* **🧵 Multi-Threaded:** Uses a Producer-Consumer model to handle high-speed traffic without blocking the scanner.
* **🧠 Smart Caching:** Implements a "Cooldown" system (default: 10 mins) to prevent re-scanning the same IP and exhausting resources.
* **📂 Forensic Database:** Stores all packet logs and suspect profiles in a thread-safe SQLite database (`forensics.db`).

---

## ⚙️ Architecture

The system operates on two parallel tracks to ensure performance:

```mermaid
graph TD
    A[Incoming Packet] -->|Sniffer Thread| B(Parse Headers)
    B -->|Log Data| C[(Packet Logs DB)]
    B -->|Check Cache| D{New IP?}
    D -- Yes --> E[Spawn Scanner Thread]
    D -- No --> F[Ignore]
    E -->|Nmap Scan| G[Attacker IP]
    G -->|Result| H[(Suspects DB)]
🛠️ Installation
This tool is optimized for Kali Linux, Ubuntu, and Debian.

1. Clone the Repository
Bash

git clone [https://github.com/YOUR_USERNAME/IPTRACKER.git](https://github.com/YOUR_USERNAME/IPTRACKER.git)
cd IPTRACKER
2. Fix Line Endings (Critical for Windows users)
If the code was uploaded from Windows, you must fix the script format:

Bash

sudo apt-get install dos2unix
dos2unix IPtracker.sh
chmod +x IPtracker.sh
3. Install Dependencies
The script attempts to install dependencies automatically, but on modern Kali Linux (2024+), you may need to force-install the Nmap library:

Bash

sudo pip3 install python-nmap --break-system-packages
🖥️ Usage
1. Start the Tracker
You must run the tool as root to access the raw network interface.

Bash

sudo ./IPtracker.sh
The tool will initialize the database and start listening. Keep this terminal open.

2. View Intelligence (Forensics)
Open a new terminal window to query the database while the tool runs.

View Live Packet Logs:

Bash

python3 src/viewer.py logs
Shows: Timestamp | Source IP | Destination Port | Protocol

View Suspect Profiles (Nmap Results):

Bash

python3 src/viewer.py suspects
Shows: IP Address | OS Guess (Windows/Linux) | Open Ports | Scan Status

📂 Project Structure
Plaintext

IPTRACKER/
├── IPtracker.sh            # Main Controller (Entry Point)
├── requirements.txt        # Python Dependencies
├── data/                   # Auto-generated storage
│   └── forensics.db        # SQLite Database
└── src/
    ├── main.py             # Sniffer Core (Scapy)
    ├── scanner.py          # Nmap Logic & Threading
    ├── database.py         # Thread-safe SQLite Manager
    └── viewer.py           # CLI Data Viewer
🔧 Troubleshooting
Error: ModuleNotFoundError: No module named 'nmap'

Fix: Run sudo pip3 install python-nmap --break-system-packages.

Error: /bin/bash^M: bad interpreter

Fix: This means the file has Windows line endings. Run dos2unix IPtracker.sh.

Error: Database Locked

Fix: The system handles this automatically with a 10-second timeout. If it persists, ensure no other program has the .db file open in "Write" mode.

📜 License
Open Source. strictly for educational and defensive forensic usage.

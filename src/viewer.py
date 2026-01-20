import sqlite3
import os
import sys

# Connect to the database
DB_PATH = os.path.join("data", "forensics.db")

def view_suspects():
    """Prints a formatted table of all scanned suspects."""
    if not os.path.exists(DB_PATH):
        print("[!] No database found. Run the tracker first.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT ip_address, os_info, open_ports, last_scan FROM suspects")
    rows = cursor.fetchall()
    conn.close()

    print("\n" + "="*80)
    print(f"{'IP ADDRESS':<20} | {'OS GUESS':<20} | {'LAST SCAN':<20} | {'PORTS'}")
    print("="*80)
    
    for row in rows:
        ip, os_guess, last_scan, ports = row
        # Truncate ports if too long for display
        if len(ports) > 30:
            ports = ports[:27] + "..."
        print(f"{ip:<20} | {os_guess:<20} | {last_scan:<20} | {ports}")
    print("="*80 + "\n")

def view_logs(limit=20):
    """Prints the last N packet logs."""
    if not os.path.exists(DB_PATH):
        print("[!] No database found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT timestamp, src_ip, dst_port, protocol FROM packet_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    print("\n" + "-"*60)
    print(f"{'TIMESTAMP':<25} | {'SOURCE IP':<20} | {'PORT':<10} | {'PROTO'}")
    print("-"*60)
    
    for row in rows:
        ts, ip, port, proto = row
        print(f"{ts:<25} | {ip:<20} | {port:<10} | {proto}")
    print("-"*60 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 src/viewer.py [suspects|logs]")
    elif sys.argv[1] == "suspects":
        view_suspects()
    elif sys.argv[1] == "logs":
        view_logs()
    else:
        print("Unknown command. Use 'suspects' or 'logs'.")
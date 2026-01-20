import nmap
import threading
import database
from datetime import datetime, timedelta

# Initialize Nmap PortScanner
nm = nmap.PortScanner()

# Local memory cache to reduce Database reads (Speed Optimization)
# Format: {'192.168.1.50': datetime_object}
scan_cache = {}

def run_nmap(ip_address):
    """
    Runs the actual Nmap scan. 
    This is CPU intensive, so it runs in a separate thread.
    """
    print(f"[!] Launching Counter-Scan on: {ip_address}")
    
    try:
        # STEALTH MODIFICATIONS:
        # -sS: Stealth SYN Scan (Half-open, harder to log)
        # -O: OS Detection (We keep this for forensics, though it adds some noise)
        # --top-ports 50: Only scan top 50 common ports (Drastic noise reduction vs 1000)
        # -T2: "Polite" timing template (Slows down to avoid flooding the network)
        
        nm.scan(ip_address, arguments='-sS -O --top-ports 50 -T2')
        
        # Extract Results
        if ip_address in nm.all_hosts():
            # Get OS Guess
            if 'osmatch' in nm[ip_address] and nm[ip_address]['osmatch']:
                os_info = nm[ip_address]['osmatch'][0]['name']
            else:
                os_info = "Unknown OS"

            # Get Open Ports
            open_ports = []
            if 'tcp' in nm[ip_address]:
                for port in nm[ip_address]['tcp']:
                    if nm[ip_address]['tcp'][port]['state'] == 'open':
                        open_ports.append(str(port))
            
            ports_str = ", ".join(open_ports) if open_ports else "None"
            
            # Save to Database
            database.update_suspect_scan(ip_address, ports_str, os_info)
            print(f"[+] Scan Complete for {ip_address}: OS={os_info}, Ports={ports_str}")
        else:
            print(f"[-] Scan Failed: Host {ip_address} appears down or blocked our scan.")

    except Exception as e:
        print(f"[ERROR] Nmap failed for {ip_address}: {e}")

def process_suspect(ip_address):
    """
    Decides whether to scan the IP or ignore it based on the 10-minute rule.
    """
    current_time = datetime.now()

    # 1. Check Cache (Fastest)
    if ip_address in scan_cache:
        last_scan_time = scan_cache[ip_address]
        if current_time - last_scan_time < timedelta(minutes=10):
            # Less than 10 mins since last scan -> Ignore
            return

    # 2. Check Database (If not in cache, maybe we restarted the tool)
    suspect_row = database.get_suspect_info(ip_address)
    
    should_scan = False
    if suspect_row is None:
        should_scan = True # Brand new suspect
    else:
        # Database returns string, convert to datetime
        # suspect_row[2] is 'last_scan' column
        try:
            last_db_scan = datetime.strptime(suspect_row[2], "%Y-%m-%d %H:%M:%S")
            if current_time - last_db_scan > timedelta(minutes=10):
                should_scan = True
        except ValueError:
            # If DB has invalid time format, force rescan
            should_scan = True

    # 3. Trigger Scan if needed
    if should_scan:
        # Update cache immediately to prevent duplicate scans while Nmap runs
        scan_cache[ip_address] = current_time
        
        # Run Nmap in a separate thread so we don't block the Sniffer
        t = threading.Thread(target=run_nmap, args=(ip_address,))
        t.daemon = True # Kills thread if main program exits
        t.start()

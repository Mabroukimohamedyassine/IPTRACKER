import sys
import logging
from scapy.all import sniff, IP, TCP, UDP, Ether
import database
import scanner

# Configure Logging (Optional: To see output in terminal)
logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

def packet_callback(packet):
    """
    This function runs for EVERY single packet captured.
    It must be fast.
    """
    try:
        # We only care about IP packets
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # protocol mapping
            proto_num = packet[IP].proto
            protocol = ""
            dst_port = 0
            payload_size = len(packet)

            # Determine Protocol and Port
            if TCP in packet:
                protocol = "TCP"
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                dst_port = packet[UDP].dport
            else:
                return # Ignore ICMP or other types for now to save space

            # Get MAC Address (Layer 2)
            src_mac = "Unknown"
            if Ether in packet:
                src_mac = packet[Ether].src

            # 1. Log to Database
            # We print a small summary to the console
            print(f"[*] Packet: {src_ip} -> {dst_port}/{protocol} | Size: {payload_size}")
            
            database.log_packet(src_ip, src_mac, dst_port, protocol, payload_size)

            # 2. Trigger Counter-Intel (Nmap)
            # We do NOT scan ourselves (loopback)
            if src_ip != "127.0.0.1": 
                scanner.process_suspect(src_ip)

    except Exception as e:
        # Don't crash the sniffer on a bad packet
        print(f"[ERROR] Parsing packet: {e}")

def start_sniffing(interface=None):
    """
    Starts the packet capture loop.
    """
    print("==========================================")
    print(f"[*] INTELLIGENCE TRACKER STARTED")
    print(f"[*] Database: Initialized")
    print(f"[*] Interface: {interface if interface else 'Default'}")
    print("==========================================")
    
    # Initialize DB (Create tables if they don't exist)
    database.init_db()

    try:
        # sniff() is the main loop. 
        # store=0 prevents Scapy from keeping packets in RAM (Memory leak prevention)
        if interface:
            sniff(iface=interface, prn=packet_callback, store=0)
        else:
            sniff(prn=packet_callback, store=0)
            
    except KeyboardInterrupt:
        print("\n[!] Stopping Tracker...")
        sys.exit(0)

if __name__ == "__main__":
    # You can pass the interface as an argument (e.g., eth0)
    # If not provided, Scapy picks the default one.
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    start_sniffing(iface)
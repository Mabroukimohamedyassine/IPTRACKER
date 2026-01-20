import sqlite3
import os
from datetime import datetime

DB_FOLDER = "data"
DB_FILE = os.path.join(DB_FOLDER, "forensics.db")

def get_db_connection():
    """Establishes a connection with a timeout to handle locking."""
    # check_same_thread=False allows sharing if needed, 
    # but we use new connections per thread for safety.
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def init_db():
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                src_mac TEXT,
                dst_port INTEGER,
                protocol TEXT,
                payload_size INTEGER
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspects (
                ip_address TEXT PRIMARY KEY,
                first_seen TEXT,
                last_scan TEXT,
                open_ports TEXT,
                os_info TEXT,
                scan_status TEXT
            )
        ''')
        conn.commit()

def log_packet(src_ip, src_mac, dst_port, protocol, payload_size):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                INSERT INTO packet_logs (timestamp, src_ip, src_mac, dst_port, protocol, payload_size)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, src_mac, dst_port, protocol, payload_size))
            conn.commit()
    except sqlite3.OperationalError as e:
        print(f"[ERROR] Database Locked or Busy: {e}")

def update_suspect_scan(ip_address, open_ports, os_info):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.execute('''
                INSERT OR IGNORE INTO suspects (ip_address, first_seen, last_scan, scan_status)
                VALUES (?, ?, ?, 'Pending')
            ''', (ip_address, now, "1970-01-01 00:00:00"))

            cursor.execute('''
                UPDATE suspects
                SET last_scan = ?, open_ports = ?, os_info = ?, scan_status = 'Scanned'
                WHERE ip_address = ?
            ''', (now, open_ports, os_info, ip_address))
            conn.commit()
    except Exception as e:
        print(f"[ERROR] Failed to update suspect intel: {e}")

# Note: get_suspect_info reads data, so it creates a connection, 
# reads, and closes it automatically via the helper function structure.
def get_suspect_info(ip_address):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM suspects WHERE ip_address = ?', (ip_address,))
            row = cursor.fetchone()
            return row
    except:
        return None
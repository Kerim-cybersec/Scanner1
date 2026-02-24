import socket
import threading
from queue import Queue
import time
import sys

# --- CONFIG ---
TARGET = "127.0.0.1" 
THREADS = 100 
PORT_RANGE = range(1, 10001) 
TOTAL_PORTS = len(PORT_RANGE)

# (I've abbreviated the DB here for space, keep your full 100+ port list in your version!)
VULN_DB = {
    21: {"s": "FTP", "r": "HIGH", "n": "Cleartext creds."},
    22: {"s": "SSH", "r": "LOW", "n": "Secure remote access."},
    80: {"s": "HTTP", "r": "MEDIUM", "n": "Unencrypted web."},
    443: {"s": "HTTPS", "r": "SAFE", "n": "Encrypted web."},
    7: {"s": "Echo", "r": "INFO", "n": "Old testing service, rarely used."},
    20: {"s": "FTP-Data", "r": "MEDIUM", "n": "Unencrypted file transfer data."},
    21: {"s": "FTP-Control", "r": "HIGH", "n": "Cleartext credentials; prone to sniffing."},
    22: {"s": "SSH", "r": "LOW", "n": "Secure; check for outdated OpenSSH versions."},
    23: {"s": "Telnet", "r": "CRITICAL", "n": "Zero encryption. Remote admin nightmare."},
    25: {"s": "SMTP", "r": "MEDIUM", "n": "Mail server; check for open relay config."},
    53: {"s": "DNS", "r": "LOW", "n": "Check for zone transfer vulnerabilities."},
    67: {"s": "DHCP", "r": "INFO", "n": "IP assignment service."},
    69: {"s": "TFTP", "r": "HIGH", "n": "No auth; often used to leak config files."},
    80: {"s": "HTTP", "r": "MEDIUM", "n": "Unencrypted web; check for sensitive dirs."},
    88: {"s": "Kerberos", "r": "MEDIUM", "n": "Auth protocol; target for 'AS-REP' roasting."},
    110: {"s": "POP3", "r": "HIGH", "n": "Cleartext email retrieval."},
    111: {"s": "RPCBind", "r": "MEDIUM", "n": "Often used to map NFS shares."},
    119: {"s": "NNTP", "r": "INFO", "n": "Old newsgroup protocol."},
    123: {"s": "NTP", "r": "LOW", "n": "Time sync; can be used in DDoS amplification."},
    135: {"s": "MS-RPC", "r": "MEDIUM", "n": "Windows endpoint mapper."},
    137: {"s": "NetBIOS-NS", "r": "MEDIUM", "n": "Target for NBNS poisoning (Responder)."},
    139: {"s": "NetBIOS-SSN", "r": "MEDIUM", "n": "Legacy Windows file sharing."},
    143: {"s": "IMAP", "r": "MEDIUM", "n": "Email access; check if STARTTLS is forced."},
    161: {"s": "SNMP", "r": "HIGH", "n": "Check for default 'public' community strings."},
    179: {"s": "BGP", "r": "INFO", "n": "Routing protocol for the internet."},
    389: {"s": "LDAP", "r": "MEDIUM", "n": "Identity management; check for anonymous bind."},
    443: {"s": "HTTPS", "r": "SAFE", "n": "Encrypted web traffic."},
    445: {"s": "SMB", "r": "HIGH", "n": "Windows sharing; critical for lateral movement."},
    465: {"s": "SMTPS", "r": "LOW", "n": "Secure mail submission."},
    500: {"s": "ISAKMP", "r": "MEDIUM", "n": "IPSec VPN negotiation."},
    514: {"s": "Syslog", "r": "INFO", "n": "Central logging service."},
    515: {"s": "LPD", "r": "INFO", "n": "Legacy line printer service."},
    548: {"s": "AFP", "r": "MEDIUM", "n": "Apple Filing Protocol."},
    554: {"s": "RTSP", "r": "INFO", "n": "Real Time Streaming (often IP cameras)."},
    587: {"s": "SMTP-Msg", "r": "LOW", "n": "Modern secure mail submission."},
    631: {"s": "CUPS", "r": "INFO", "n": "Common Unix Printing System."},
    636: {"s": "LDAPS", "r": "LOW", "n": "Secure LDAP."},
    873: {"s": "Rsync", "r": "MEDIUM", "n": "File sync; check for unauth access."},
    993: {"s": "IMAPS", "r": "LOW", "n": "Secure IMAP."},
    995: {"s": "POP3S", "r": "LOW", "n": "Secure POP3."},
    1025: {"s": "NFS-OR-RPC", "r": "MEDIUM", "n": "Generic Windows RPC/NFS."},
    1433: {"s": "MSSQL", "r": "HIGH", "n": "Microsoft SQL; check for 'sa' account brute force."},
    1521: {"s": "Oracle", "r": "HIGH", "n": "Oracle Database listener."},
    1723: {"s": "PPTP", "r": "MEDIUM", "n": "Legacy VPN protocol (weak)."},
    1812: {"s": "RADIUS", "r": "INFO", "n": "Authentication service."},
    2049: {"s": "NFS", "r": "MEDIUM", "n": "Network File System; check export permissions."},
    2375: {"s": "Docker", "r": "CRITICAL", "n": "Unauth Docker API = Instant Root access."},
    3306: {"s": "MySQL", "r": "MEDIUM", "n": "Common database; check user permissions."},
    3389: {"s": "RDP", "r": "HIGH", "n": "Remote Desktop; common ransomware entry point."},
    4786: {"s": "SmartInstall", "r": "HIGH", "n": "Cisco Smart Install (often exploitable)."},
    4848: {"s": "GlassFish", "r": "INFO", "n": "Java App Server admin."},
    5000: {"s": "Flask/UPnP", "r": "INFO", "n": "Commonly used for dev web servers."},
    5432: {"s": "PostgreSQL", "r": "MEDIUM", "n": "Postgres database."},
    5632: {"s": "PCAnywhere", "r": "HIGH", "n": "Old remote access (vulnerable)."},
    5900: {"s": "VNC", "r": "HIGH", "n": "Virtual Network Computing; check for no-pass."},
    5985: {"s": "WinRM-HTTP", "r": "MEDIUM", "n": "Windows Remote Management."},
    5986: {"s": "WinRM-HTTPS", "r": "LOW", "n": "Secure Windows Remote Management."},
    6379: {"s": "Redis", "r": "HIGH", "n": "In-memory DB; check for bind without pass."},
    8000: {"s": "HTTP-Alt", "r": "INFO", "n": "Often used for dev/API environments."},
    8080: {"s": "HTTP-Proxy", "r": "MEDIUM", "n": "Commonly used for web admin panels."},
    8443: {"s": "HTTPS-Alt", "r": "LOW", "n": "Common for secure admin consoles."},
    9000: {"s": "Portainer", "r": "INFO", "n": "Docker management UI."},
    9200: {"s": "Elasticsearch", "r": "HIGH", "n": "Database; check for unauth data leak."},
    10000: {"s": "Webmin", "r": "MEDIUM", "n": "Linux web-based admin."},
    27017: {"s": "MongoDB", "r": "HIGH", "n": "NoSQL DB; check for default no-password."},
}

print_lock = threading.Lock()
queue = Queue()
final_results = []
processed_count = 0 # Track how many ports we've finished

def update_progress():
    """Calculates and prints a manual progress bar to the terminal."""
    global processed_count
    with print_lock:
        processed_count += 1
        percent = (processed_count / TOTAL_PORTS) * 100
        # Create a bar like: [##########..........] 50%
        bar_length = 30
        filled_length = int(bar_length * processed_count // TOTAL_PORTS)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        # \r moves the cursor back to the start of the line so it overwrites itself
        sys.stdout.write(f'\r[*] Progress: |{bar}| {percent:.1f}% Complete')
        sys.stdout.flush()

def scan_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0) 
    try:
        result = s.connect_ex((TARGET, port))
        if result == 0:
            data = VULN_DB.get(port, {"s": "Unknown", "r": "INFO", "n": "Service detected."})
            res = (port, data['s'], data['r'], data['n'])
            final_results.append(res)
            # We don't print "HIT" immediately anymore to avoid breaking the progress bar
    except:
        pass
    finally:
        s.close()
        update_progress() # Update the bar after every port attempt

def threader():
    while True:
        p = queue.get()
        scan_port(p)
        queue.task_done()

def main():
    print(f"[*] Initialising scan on {TARGET}...")
    print(f"[*] Total ports: {TOTAL_PORTS} | Threads: {THREADS}")
    
    start = time.time()

    # Launch threads
    for _ in range(THREADS):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    # Fill queue
    for port in PORT_RANGE:
        queue.put(port)

    # Wait for completion
    queue.join()

    # Clear the progress bar line for the final report
    print("\n\n" + "="*85)
    print(f" AUDIT SUMMARY - {TARGET}")
    print("="*85)
    
    if final_results:
        final_results.sort()
        print(f"{'PORT':<7} | {'SERVICE':<12} | {'RISK':<10} | {'SECURITY NOTE'}")
        print("-" * 85)
        for r in final_results:
            print(f"{r[0]:<7} | {r[1]:<12} | {r[2]:<10} | {r[3]}")
    else:
        print("[!] No open ports detected in scanned range.")
    
    print("="*85)
    print(f"Scan duration: {round(time.time() - start, 2)}s")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] User aborted.")
        sys.exit()
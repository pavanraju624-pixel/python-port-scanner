import socket
import sys
import concurrent.futures
from datetime import datetime

# Common ports to scan
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS", 3389: "RDP"
}

def banner_grab(s):
    """Attempts to grab a banner safely with dual-mode detection."""
    s.settimeout(2.0)
    try:
        # Mode 1: Wait for service-first banners (like SSH/FTP)
        banner = s.recv(1024).decode(errors='ignore').strip()
        if banner:
            return banner
        
        # Mode 2: If silent, try to trigger a response (like HTTP)
        s.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = s.recv(1024).decode(errors='ignore').strip()
        return banner if banner else "No banner response"
    except Exception:
        return "Connected (No banner available)"

def scan_port(target_ip, port, service):
    """Worker function to scan a single port."""
    try:
        # Using 'with' automatically closes the socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((target_ip, port))
            
            if result == 0:
                banner = banner_grab(s)
                
                # Simple vulnerability logic
                report = f"{banner}"
                if port in [21, 23]:
                    report += " -> [VULN: Plaintext Protocol]"
                elif "Apache/2.4.41" in banner:
                    report += " -> [WARN: Outdated Apache]"
                
                return f"{port:<10}{service:<10}{'OPEN':<10}{report}"
    except Exception:
        pass
    return None

def run_scanner():
    target_host = input("Enter host to scan (default: localhost): ").strip() or "localhost"
    
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print("\n[!] Error: Could not resolve hostname.")
        return

    print("-" * 70)
    print(f"Scanning: {target_ip} ({target_host})")
    print(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 70)
    print(f"{'PORT':<10}{'SERVICE':<10}{'STATUS':<10}{'REPORT'}")
    print("-" * 70)

    # Use ThreadPoolExecutor to scan ports in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Map the scan_port function across our dictionary
        futures = [executor.submit(scan_port, target_ip, p, s) for p, s in COMMON_PORTS.items()]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(result)

if __name__ == "__main__":
    try:
        run_scanner()
        print("-" * 70)
        print("Scan Completed.")
    except KeyboardInterrupt:
        print("\n[!] Scan stopped by user.")
        sys.exit()

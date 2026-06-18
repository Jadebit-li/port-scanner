import socket
import threading
from concurrent.futures import ThreadPoolExecutor

lock = threading.Lock()
results = []

SERVICE_SIGNATURES = {
    "SSH": "SSH",
    "HTTP": "HTTP",
    "FTP": "FTP",
    "SMTP": "SMTP",
    "MySQL": "MySQL",
    "Apache": "Apache",
}

def scan_port(host, port_number):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(1)
        s.connect((host, port_number))
        try: 
            banner = s.recv(1024)
        except socket.timeout:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            try:
                banner = s.recv(1024)
            except socket.timeout:
                banner = b"open but no banner"
        decoded = banner.decode('utf-8', errors='ignore').split('\n')[0].strip()
        service = identify_service(decoded)
        return f" | open | {service} | {decoded}"
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    finally:
        s.close()

def identify_service(banner):
    for key, value in SERVICE_SIGNATURES.items():
        if key in banner:
            return value
    return "Unknown"

def scan_and_store(port):
    result = scan_port("scanme.nmap.org", port)
    if "open" in result:
        with lock:
            results.append(f"Port {port} {result}")


# for i in range (1, 101):
#     c = scan_port("scanme.nmap.org", i)
#     print(c)
#instead of this, we use:

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(scan_and_store, range(1,1001))

for r in sorted(results):
    print(r)

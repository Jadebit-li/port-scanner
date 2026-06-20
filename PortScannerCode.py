import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import re
with open("cve_database.json") as f:
    CVE_DB = json.load(f)

lock = threading.Lock()
results = []

SERVICE_SIGNATURES = {
    "OpenSSH": "OpenSSH",
    "Apache": "Apache",
    "nginx": "nginx",
    "FTP": "FTP",
    "SMTP": "SMTP",
    "MySQL": "MySQL",
    "HTTP": "HTTP",
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
        decoded_full = banner.decode('utf-8', errors='ignore')
        decoded = decoded_full.split('\n')[0].strip()
        service = identify_service(decoded_full)
        version = extract_version(decoded_full)
        CVE = check_cve(service, version)
        return f" | open | {service} | {decoded} | CVEs: {CVE}"
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

def extract_version(banner):
    match = re.search(r"\d+\.\d+\.\d+[a-zA-Z0-9]*", banner)
    if match:
        version = match.group()
    else:
        version = "unknown"
    return version


def check_cve(service, version): # takes two separate strings
    #service is like the name of the person and version like phone number, and thats how we saved them in the database
    key = service + " " + version    # glue them into one string matching dict format
    return CVE_DB.get(key, [])   # look it up safely, empty list if not found


# for i in range (1, 101):
#     c = scan_port("scanme.nmap.org", i)
#     print(c)
#instead of this, we use:

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(scan_and_store, range(1,1001))

for r in sorted(results):
    print(r)

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import json
import re
import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument("--host", required=True)
parser.add_argument("--ports", required=True)
args = parser.parse_args()

try:
    socket.gethostbyname(args.host)
except socket.gaierror:
    print(f"Error: could not resolve host '{args.host}'. Check the spelling or your connection.")
    exit()

try:
    sports = args.ports.split('-')
    start = int(sports[0])
    end = int(sports[1]) + 1
except ValueError:
    print("Error: --ports must be in the format START-END, e.g. 1-1000")
    exit()


try:
    with open("cve_database.json") as f:
        CVE_DB = json.load(f)
except FileNotFoundError:
    print("Error: cve_database.json not found. Make sure it's in the same folder as this script.")
    exit()

lock = threading.Lock()
results = []
filtered_ports = []
closed_count = 0

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
    except socket.gaierror:
        return "invalid host"
    finally:
        s.close()


def identify_service(banner):
    for key, value in SERVICE_SIGNATURES.items():
        if key in banner:
            return value
    return "Unknown"

def scan_and_store(port):
    global closed_count
    result = scan_port(args.host, port)
    if "open" in result:
        with lock:
            results.append(f"Port {port} {result}")
    elif "filtered" in result:
        with lock:
            filtered_ports.append(f"Port {port}")
    elif "closed" in result:
        with lock:
            closed_count = closed_count + 1

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

start_time = time.time()
# ... scan happens ...



# for i in range (1, 101):
#     c = scan_port("scanme.nmap.org", i)
#     print(c)
#instead of this, we use:

with ThreadPoolExecutor(max_workers=50) as executor:
    executor.map(scan_and_store, range(start,end))

end_time = time.time()
duration = end_time - start_time

# for r in sorted(results):
#     print(r) 
# now we do this in html file

total_scanned = end - start
total_open = len(results)
total_filtered = len(filtered_ports)

html = """
<html>
<head>
<link href="https://fonts.googleapis.com/css2?family=Quicksand:wght@500;700&display=swap" rel="stylesheet">
<style>
body { background-color: #fdfdf8; color: #234f3f; font-family: 'Quicksand', sans-serif; font-size: 16px; padding: 30px; }
h1 { color: #234f3f; font-size: 32px; font-weight: 700; }
h2 { color: #234f3f; font-size: 22px; font-weight: 700; margin-top: 40px; }
table { border-collapse: separate; border-spacing: 0; width: 100%; margin-bottom: 30px; border: 3px solid #5da789; border-radius: 16px; overflow: hidden; box-shadow: 4px 4px 0px rgba(93, 167, 137, 0.3); }
td, th { padding: 14px 18px; text-align: left; font-size: 15px; border-bottom: 2px solid #c9e0d2; }
th { background-color: #82b89c; color: #fff; font-size: 14px; font-weight: 700; letter-spacing: 0.5px; }
.summary-table td { background-color: #e8f2eb; color: #234f3f; }
.summary-table th { background-color: #5da789; }
.open-row td { background-color: #cde8d8; }
.filtered-row td { background-color: #fdf6dc; }
</style>
</head>
<body>
<h1>Port Scan Report</h1>
<table class="summary-table">
<tr><th>Target</th><td>""" + args.host + """</td></tr>
<tr><th>Port Range</th><td>""" + str(start) + "-" + str(end - 1) + """</td></tr>
<tr><th>Scan Time</th><td>""" + str(round(duration, 2)) + """ seconds</td></tr>
<tr><th>Total Ports Scanned</th><td>""" + str(end - start) + """</td></tr>
<tr><th>Open</th><td>""" + str(len(results)) + """</td></tr>
<tr><th>Closed</th><td>""" + str(closed_count) + """</td></tr>
<tr><th>Filtered</th><td>""" + str(len(filtered_ports)) + """</td></tr>
</table>

<h2>Open and Filtered Ports</h2>
<table>
<tr><th>Result</th></tr>
"""

for r in results:
    html += '<tr class="open-row"><td>' + r + '</td></tr>'
for r in filtered_ports:
    html += '<tr class="filtered-row"><td>' + r + ' | filtered</td></tr>'

html += "</table></body></html>"

with open("report.html", "w", encoding="utf-8") as f:
    f.write(html)
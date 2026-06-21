# Port Scanner with CVE Vulnerability Matching
A multi-threaded Python port scanner that identifies open ports, grabs service banners, and cross-references detected service versions against a local database of known CVEs. Outputs a clean, styled HTML report.

## Features
* Concurrent port scanning using ThreadPoolExecutor (1000 ports in ~6-7 seconds)
* Service detection and version extraction from raw banners
* Local CVE database lookup with verified, real CVE references
* Command-line interface with configurable host and port range
* Open / closed / filtered port classification
* Styled HTML report with scan summary and color-coded results
* Graceful error handling for invalid hosts, malformed input, and missing files

## Sample report


## Tech Stack
* Python 3
* socket — TCP connections and banner grabbing
* threading / concurrent.futures — concurrent scanning
* re — version extraction from banners
* argparse — CLI interface
* json — local CVE database

## Usage
python3 scanner.py --host scanme.nmap.org --ports 1-1000
This scans the specified host across the given port range and generates report.html in the same directory.

Arguments:
--host — target hostname or IP address (required)
--ports — port range in START-END format, e.g. 1-1000 (required)

## How It Works

* Scanning — Opens a TCP socket to each port in the specified range using a thread pool of 50 concurrent workers.
* Banner grabbing — For open ports, attempts to read the service banner immediately. If the service doesn't respond first (e.g. HTTP), sends a probe request to trigger a response.
* Service identification — Matches the banner against known service signatures (OpenSSH, Apache, nginx, etc.).
* Version extraction — Uses regex to pull the exact version string from the banner.
* CVE matching — Looks up the service and version combination against a local JSON database of verified CVEs.
* Reporting — Compiles all results into a styled HTML report showing a scan summary and detailed port-by-port breakdown.


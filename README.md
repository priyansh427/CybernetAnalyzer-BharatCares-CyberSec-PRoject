# CyberNetAnalyzer

**Python Cybersecurity Network Analysis Tool — for authorized security testing and education.**

> ⚠️ **Legal Notice:** Only scan networks and devices you own or have **explicit written
> authorization** to test. Unauthorized network scanning is illegal in most jurisdictions.
> This tool is for **educational purposes only**.

---

## Table of Contents

1. [Features](#features)
2. [Project Structure](#project-structure)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Running the Application](#running-the-application)
6. [Usage Guide](#usage-guide)
7. [Sample Data](#sample-data)
8. [Sample Output](#sample-output)
9. [Testing Instructions](#testing-instructions)
10. [Troubleshooting](#troubleshooting)
11. [Security Design](#security-design)

---

## Features

| Feature | Description |
|---------|-------------|
| **Network Discovery** | ICMP ping + TCP probe fallback to find live hosts in a CIDR range |
| **Port Scanning** | Concurrent TCP connect scan across 65+ well-known ports (50-thread cap) |
| **Service Identification** | Maps open ports to human-readable service names |
| **Risk Assessment** | Rates open ports HIGH / MEDIUM / LOW with plain-English explanations and remediation steps |
| **Banner Grabbing** | Optional — reads the first line a service sends to identify version information |
| **Traffic Analysis** | Scapy-powered live capture and pcap/pcapng file analysis: protocol breakdown, top talkers, port stats |
| **Sample Data** | Built-in 6-host threat scenario — load instantly without a live scan to explore all UI features |
| **Reports** | CSV export + human-readable security report text file, saved to `reports/` |
| **Dark-Themed GUI** | Tkinter interface with real-time activity log, progress bar, colour-coded treeview, and detail panel |
| **Safety Controls** | Authorization confirmation gate, 1 024-host limit, graceful cancellation |

---

## Project Structure

```
CyberNetAnalyzer/
│
├── app.py                    # Main Tkinter GUI — entry point
│
├── core/
│   ├── __init__.py
│   ├── scanner.py            # Host discovery & TCP port scanning engine
│   ├── service_db.py         # 65+ port → service names, risk database
│   ├── traffic_analyzer.py   # Scapy live capture and pcap analysis
│   └── reporter.py           # CSV and plain-text report generation
│
├── reports/                  # Auto-created — scan outputs saved here
│
├── requirements.txt          # scapy>=2.5.0 (optional)
└── README.md
```

---

## Requirements

### Minimum — no optional features needed

- **Python 3.10+**
- Standard library only — no `pip install` required:
  `socket`, `ipaddress`, `subprocess`, `concurrent.futures`, `platform`,
  `csv`, `datetime`, `threading`, `tkinter`, `dataclasses`, `typing`, `collections`

Tkinter ships with CPython on Windows and macOS. On Linux it may need a separate install:

```bash
# Debian / Ubuntu
sudo apt install python3-tk

# Fedora / RHEL
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

### Optional — Traffic Analysis tab

| Dependency | Purpose |
|---|---|
| `scapy >= 2.5.0` | Live capture + pcap file analysis |
| [Npcap](https://npcap.com) *(Windows only)* | Low-level packet capture driver for Scapy |
| `libpcap-dev` *(Linux only)* | C library Scapy needs on Linux |

---

## Installation

### 1 — Get the project

```bash
git clone https://github.com/yourname/CyberNetAnalyzer.git
cd CyberNetAnalyzer
```

Or place the `CyberNetAnalyzer/` folder anywhere on your machine.

### 2 — (Recommended) Create a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3 — Install dependencies

#### Scanning + reporting only (no Traffic Analysis)

No installation needed — everything is standard library.

#### Full install (including Traffic Analysis)

**Windows:**
```bash
# 1. Install Npcap first: https://npcap.com
#    (tick "WinPcap API-compatible mode" during install)
# 2. Install Scapy
pip install scapy
```

**Linux (Ubuntu / Debian):**
```bash
sudo apt install libpcap-dev
pip install scapy
```

**macOS:**
```bash
brew install libpcap
pip install scapy
```

---

## Running the Application

```bash
# From the CyberNetAnalyzer/ directory:
python app.py
```

**Live capture requires elevated privileges:**

```bash
# Windows — right-click terminal → "Run as administrator", then:
python app.py

# Linux — grant capability once (survives reboots):
sudo setcap cap_net_raw+eip $(which python3)
python3 app.py

# Linux — or just run as root each time:
sudo python3 app.py

# macOS:
sudo python3 app.py
```

---

## Usage Guide

### Port Scan

1. Launch: `python app.py`
2. Enter a target in the **Target** field:
   - Single host: `192.168.1.1`
   - CIDR range: `192.168.1.0/24`
   - Multiple targets: `192.168.1.1, 192.168.1.5`
3. *(Optional)* Tick **Grab service banners** to capture version strings.
4. *(Optional)* Tick **Custom port list** and enter ports (comma-separated).
5. Click **▶ Start Scan** and confirm authorization in the dialog.
6. Watch progress in the **Activity Log** (left panel).
7. Results appear in **Scan Results** — click any row for full threat detail.
8. Switch to **Security Report** for the full narrative assessment.
9. Click **💾 Export Reports** to save `reports/scan_results_*.csv` and `reports/security_report_*.txt`.

### Traffic Analysis (requires Scapy)

**Analyse a pcap file:**
1. Go to the **Traffic Analysis** tab.
2. Click **Browse…** and select a `.pcap` or `.pcapng` file.
3. Click **Analyse File**.

**Live capture:**
1. Go to the **Traffic Analysis** tab.
2. Choose a network interface from the dropdown.
3. Set the capture duration (1–300 seconds).
4. Click **▶ Start Live Capture** (Administrator / root required).
5. Click **■ Stop** to end early.

---

## Sample Data

No network? No problem. Click **🧪 Load Sample Data** in the Controls panel to instantly
populate the UI with a realistic 6-host small-office LAN threat scenario — no scan, no
authorization dialog, no network access required.

| Host IP | Hostname | Notable Threats |
|---|---|---|
| `192.168.1.1` | `router.local` | Telnet admin (**HIGH**), SNMP v1 public community (**HIGH**), HTTP (**MEDIUM**) |
| `192.168.1.10` | `fileserver.local` | SMB/CIFS (**HIGH**), RDP (**HIGH**), MS-RPC (**MEDIUM**), NetBIOS (**MEDIUM**) |
| `192.168.1.20` | `dbserver.local` | Redis no-auth (**HIGH**), MongoDB (**HIGH**), MySQL (**MEDIUM**), PostgreSQL (**MEDIUM**) |
| `192.168.1.30` | `devbox.local` | Docker daemon port 2375 (**HIGH**), Jupyter Notebook (**MEDIUM**), dev HTTP (**MEDIUM**) |
| `192.168.1.40` | `webserver.local` | Elasticsearch port 9200 (**HIGH**), HTTP (**MEDIUM**), Prometheus metrics (**MEDIUM**) |
| `192.168.1.50` | `printer-iot.local` | FTP anonymous login (**HIGH**), Telnet (**HIGH**), SNMP v1 (**MEDIUM**) |

Rows are colour-coded in the treeview — **red** = HIGH, **yellow** = MEDIUM, **blue** = LOW.
Click any row to see the full explanation and remediation advice in the detail panel.

---

## Sample Output

### Scan Results treeview

```
IP              Hostname          Port   Service          Risk       Banner
──────────────────────────────────────────────────────────────────────────────
192.168.1.1     router.local       23    Telnet           ⚠ HIGH     Cisco IOS 15.x
192.168.1.1     router.local       80    HTTP             ⚡ MEDIUM   Cisco HTTP/1.1
192.168.1.10    fileserver.local  445    SMB/CIFS         ⚠ HIGH     —
192.168.1.10    fileserver.local 3389    RDP              ⚠ HIGH     Microsoft RDP
192.168.1.20    dbserver.local   6379    Redis            ⚠ HIGH     —
```

### Security Report (excerpt)

```
======================================================================
  CYBERSECURITY NETWORK ANALYSIS — SECURITY REPORT
======================================================================
  Generated  : 2024-01-15 14:23:07
  Target     : 192.168.1.0/24
  Hosts up   : 6 / 254
  Open ports : 26
  HIGH risks : 13
  MED risks  : 9
======================================================================

HOST: 192.168.1.10  (fileserver.local)
────────────────────────────────────────────────────────────────────

  ▸ Ports with security notes (review recommended):

    [⚠ HIGH]  Port 445/TCP — SMB/CIFS
      Why    : SMB has been the target of high-impact exploits (EternalBlue/WannaCry).
      Action : Block SMB at the perimeter. Ensure the host is fully patched.
               Disable SMBv1 on all systems.

    [⚠ HIGH]  Port 3389/TCP — RDP
      Why    : RDP exposed to the network is a frequent ransomware entry point.
      Action : Place RDP behind a VPN or jump host. Enable NLA. Restrict source IPs.
```

### CSV Export columns

```
ip, hostname, port, service, banner, risk_level, risk_label, explanation, remediation
```

### Traffic Analysis output (excerpt)

```
============================================================
NETWORK TRAFFIC ANALYSIS
============================================================
Source         : Wi-Fi
Duration       : 30.0s
Total packets  : 1,847
Total bytes    : 284.3 KB

--- Protocol Breakdown ---
  TCP              1,203 packets
  UDP                421 packets
  DNS                180 packets
  ARP                 43 packets

--- Top Source IPs ---
  192.168.1.5          847 packets
  192.168.1.1          423 packets

--- Observations ---
  • Captured 1,847 packets (284.3 KB) in 30.0s — avg 61.6 pkt/s.
  • 180 DNS packet(s) observed.
  • Top source IP: 192.168.1.5 (847 packets).
============================================================
```

---

## Testing Instructions

### Smoke tests (no network required)

```bash
python -c "from core.scanner import resolve_targets; print(resolve_targets('127.0.0.1'))"
python -c "from core.service_db import get_service_name, get_risk; print(get_service_name(22)); print(get_risk(23))"
python -c "from core.reporter import export_csv; print('reporter OK')"
python -c "import core.scanner, core.service_db, core.reporter, core.traffic_analyzer; print('All imports OK')"
```

### Scapy availability check

```bash
python -c "from core.traffic_analyzer import SCAPY_AVAILABLE; print('Scapy available:', SCAPY_AVAILABLE)"
```

### Sample data test (no network required)

1. Launch `python app.py`.
2. Click **🧪 Load Sample Data**.
3. Verify the treeview populates with colour-coded rows.
4. Click a HIGH-risk row — confirm the detail panel shows explanation + remediation.
5. Switch to **Security Report** — confirm all 6 hosts appear.
6. Confirm **💾 Export Reports** is now enabled.

### Localhost scan test (safe — scans your own machine)

1. Launch `python app.py`.
2. Enter `127.0.0.1` as the target.
3. Tick **Custom port list** and enter `22, 80, 443, 8080`.
4. Click **▶ Start Scan** and confirm authorization.
5. Verify results appear in the treeview and report.

### CIDR range test

- Target: `192.168.1.0/24` (your own LAN — ensure you have authorization)
- Expected: discovers live hosts, shows open ports, generates report

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'tkinter'` | `sudo apt install python3-tk` (Linux) or reinstall Python with Tk support |
| Scan finds no hosts | Check the target range; try `127.0.0.1` first |
| All ports show closed on localhost | A local firewall may be blocking; try a port you know is open |
| `PermissionError` during live capture | Run as Administrator (Windows) or root / with `cap_net_raw` (Linux) |
| Scapy import error on Windows | Install [Npcap](https://npcap.com) **before** `pip install scapy` |
| `libpcap not found` on Linux | `sudo apt install libpcap-dev` |
| Scan is slow | Normal for large ranges; use `/28` or `/29` for quick tests |
| Banner grab shows `—` | Many services don't send banners unprompted; disable for faster scans |
| `ValueError: range exceeds 1024 hosts` | Use a smaller CIDR (e.g. `/22` instead of `/16`) |
| GUI does not start | Confirm `python --version` ≥ 3.10 |

---

## Security Design

| Principle | Implementation |
|-----------|----------------|
| **Authorization gate** | Every scan requires explicit confirmation that the operator owns / has permission to scan the target |
| **Host limit** | Hard cap of 1 024 hosts per session enforced before any scanning begins |
| **TCP connect only** | Uses `socket.connect_ex()` — no raw packet crafting, SYN stealth, or OS fingerprinting |
| **No exploitation** | Never authenticates against, exploits, or modifies any service |
| **No credential storage** | The application never handles or stores passwords |
| **Advisory risk labels** | Risk flags are port-number based only — they do **not** confirm vulnerability; human review required |
| **Concurrency cap** | `MAX_WORKERS = 50` threads per host; prevents network flooding |
| **Timeouts** | `CONNECT_TIMEOUT = 1.0 s` per port, `BANNER_TIMEOUT = 2.0 s` |

---

*CyberNetAnalyzer — Chaudhari Priyansh · Educational project · Not for commercial use.*

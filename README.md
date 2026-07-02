# PVS (Personal Vulnerability Scanner)

```text
  ██████╗ ██╗   ██╗███████╗
  ██╔══██╗██║   ██║██╔════╝    Personal Vulnerability Scanner
  ██████╔╝██║   ██║███████╗    v1.1.0
  ██╔═══╝ ╚██╗ ██╔╝╚════██║
  ██║      ╚████╔╝ ███████║    Ethical Security Testing
  ╚═╝       ╚═══╝  ╚══════╝
```

**PVS** is a high-performance network scanner that discovers active devices, identifies their open ports (services), and matches them with known security vulnerabilities. 

*Developed by **Mohamed Essam Elsadany**.*

---

## 🖥️ Showcases & Reports

### 1. Interactive Command Line Interface (CLI)
The console handles network discovery, async sockets progress, and displays structured tables of open ports and CVEs:
![PVS Scanner Logo and Warnings](docs/screenshots/pvs_full_scan_1.png)
![Asynchronous Scan Progress](docs/screenshots/pvs_full_scan_2.png)
![TCP Port Auditing Table](docs/screenshots/pvs_full_scan_3.png)

### 2. HTML Scan Dashboard
PVS automatically generates beautiful, responsive slate-cyan HTML dashboards summarizing overall vulnerability findings:
![HTML Report Dashboard Header](docs/screenshots/html_report_2.png)
![HTML Report Services Table](docs/screenshots/html_report_1.png)

---

## 🚀 Quick Start

### What does PVS do?
If you are new to cybersecurity tools, here is how PVS helps you:
1. **Finds Active Devices:** It checks if target computers/devices on your network are online.
2. **Checks Open Doors (Ports):** It scans for open communication ports and identifies what software/service is running on them.
3. **Finds Security Bugs (Vulnerabilities):** It automatically checks if those software versions contain known security issues (called **CVEs**).
4. **Generates Pretty Reports:** It writes a colored, interactive report page detailing the findings that you can open in any web browser.

### 📥 Installation
Ensure you have [Python 3.10+](https://www.python.org/downloads/) installed, then open PowerShell or Command Prompt:

```bash
git clone https://github.com/MElsadany2165/PVS.git
cd PVS
pip install .
```

That's it. The `pvs` command is now available system-wide.

> [!TIP]
> **For developers** who want code changes to take effect immediately without reinstalling, use `pip install -e .` instead.

### 🏃 Running Your First Scan
```bash
pvs scan 127.0.0.1
```

Scan with CVE vulnerability lookup:
```bash
pvs scan 127.0.0.1 --cve
```

> [!TIP]
> After the scan completes, check the `reports/` folder. Double-click the generated `.html` file to open a beautiful dashboard in your browser!

---

## ⚙️ Advanced & Technical Guide

### 🏗️ Technical Architecture
PVS utilizes Python's `asyncio` framework to handle multiple simultaneous network queries efficiently.

```
                  ┌────────────────────────────────┐
                  │          PVS Core CLI          │
                  └───────────────┬────────────────┘
                                  │
                  ┌───────────────▼────────────────┐
                  │      Host Ping Discovery       │
                  └───────────────┬────────────────┘
                                  │ (Only Live Hosts)
                  ┌───────────────▼────────────────┐
                  │    Asynchronous Port Scanner   │
                  │   - Connection Semaphore Lock  │
                  │   - Service Banner Grabbing    │
                  └───────────────┬────────────────┘
                                  │
                  ┌───────────────▼────────────────┐
                  │     Parallel NVD API Client    │
                  │   - Local Cache Lookup         │
                  │   - NVD Rate-Limit Semaphores  │
                  └───────────────┬────────────────┘
                                  │
                  ┌───────────────▼────────────────┐
                  │     Report Generation Engine   │
                  │      (HTML, JSON, CSV)         │
                  └────────────────────────────────┘
```
- **Asynchronous Semaphores:** Caps socket descriptors using `asyncio.Semaphore` to prevent OS resource exhaustion or firewall blocks.
- **NVD API Integration:** Connects asynchronously to the NIST NVD API v2.0 with a local cache wrapper to store results and avoid API throttling.

### ⚡ Technical Scan Examples

- **Scan a specific custom port list:**
  ```bash
  pvs scan 192.168.1.1 -p 22,80,443 --cve
  ```

- **Perform a full subnet scan at high speed:**
  Scans all 65,535 TCP ports across a class C subnet using 500 concurrent connections, timeouts of 1.5 seconds, and exports all output formats (JSON, CSV, HTML):
  ```bash
  pvs scan 192.168.1.0/24 -p all --cve -c 500 -t 1.5 -f all
  ```

### 🎛️ Port Presets
Instead of custom numbers, you can use these preset shortcuts for the `-p` or `--ports` flag:
- `top20` (Scans top 20 standard ports)
- `top100` (Scans top 100 common services)
- `common` (Scans 1,000 standard ports)
- `enterprise` (Scans 5,000 corporate network ports)
- `all` (Scans full 1 to 65,535 TCP range)

### 📋 CLI Command Options
| Option | Short Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `--ports` | `-p` | Ports to scan (presets, numbers, or ranges e.g. `1-1024`) | `top100` |
| `--cve` | | Enable CVE vulnerability correlation from NIST NVD | Disabled |
| `--nvd-api-key`| | API Key for NIST NVD to increase API speed limit | None |
| `--max-cves` | | Maximum CVEs to return per service | `5` |
| `--concurrency`| `-c` | Maximum concurrent async socket connections | `100` |
| `--timeout` | `-t` | Max socket response wait time in seconds | `2.0` |
| `--format` | `-f` | Export reports formats (`html`, `json`, `csv`, `all`) | `html` |
| `--output` | `-o` | Custom filepath prefix to write the scan reports | Auto-generated |
| `--quiet` | `-q` | Silent execution (runs scan without prints) | Disabled |
| `--no-ping` | | Skip host discovery ping sweep (forces scanning all hosts) | Disabled |
| `--no-banner-grab`| | Disable service version/banner extraction | Disabled |

---

### 🔑 NIST NVD API Key Integration
The NIST NVD API throttles unauthenticated requests. For large scans, you should register for a free API key to speed up CVE checks:
1. Request a free API Key from the [NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key).
2. Set it in your environment before running scans:
   - **Windows PowerShell:**
     ```powershell
     $env:NVD_API_KEY="your_api_key"
     ```
   - **Linux/macOS Bash:**
     ```bash
     export NVD_API_KEY="your_api_key"
     ```
   Alternatively, pass it directly with the `--nvd-api-key` argument.

---

### 🛠️ Developer & Test Guide
If you want to run tests or modify the scanner code:

1. **Install with dev dependencies (editable mode):**
   ```bash
   pip install -e ".[dev]"
   ```

2. **Execute the pytest suite:**
   ```bash
   python -m pytest
   ```

---

## ⚖️ Authorized Use Policy
**WARNING:** This tool is strictly intended for **authorized network audits, ethical security testing, and educational purposes**.
- Do not scan networks or hosts you do not own or lack explicit authorization to audit.
- Misuse of this software may violate computer crime laws (such as the US CFAA or local equivalents). The developers assume zero liability for any damages or policy violations.

---

## 📄 License
MIT License - Copyright (c) 2026 Mohamed Essam Elsadany

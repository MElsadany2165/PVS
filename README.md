# PVS (Personal Vulnerability Scanner)

```text
  ██████╗ ██╗   ██╗███████╗
  ██╔══██╗██║   ██║██╔════╝    Personal Vulnerability Scanner
  ██████╔╝██║   ██║███████╗    v1.0.0
  ██╔═══╝ ╚██╗ ██╔╝╚════██║
  ██║      ╚████╔╝ ███████║    Ethical Security Testing
  ╚═╝       ╚═══╝  ╚══════╝
```

**PVS** is a high-performance, asynchronous command-line tool designed for network reconnaissance and vulnerability assessment. It streamlines the process of discovering open ports, identifying running services, and correlating them with known security vulnerabilities using the NIST National Vulnerability Database (NVD).

*Developed by **Mohamed Essam Elsadany**.*

PVS is designed to be accessible for beginners (requiring zero setup using the pre-compiled binary) while providing the speed, architecture depth, and parameter controls required by cybersecurity experts.

---

## 🖥️ Interface Showcase

### 1. Interactive Command Line Interface
The PVS terminal interface features host discovery status logs, target profile summaries, connection progress tracking, and structured live port service tables:
![PVS Interactive CLI Terminal](docs/screenshots/cli_terminal.png)

### 2. Polished HTML Scan Dashboard
The generated HTML report provides a high-level threat recon assessment dashboard highlighting overall scan statistics, host summaries, and CVE severities:
![PVS HTML Scan Dashboard](docs/screenshots/html_report_dashboard.png)

### 3. Vulnerability Correlation Panel
An audit panel displaying matching NVD exploits with real-time CVSS scores, threat descriptions, and severity indicators for exposed ports:
![PVS HTML Vulnerability Correlation](docs/screenshots/html_report_vulnerabilities.png)

---

## 🛠️ Key Capabilities

- **Asynchronous Port Scanning:** Rapidly probes network ports using Python's `asyncio` framework for high-concurrency TCP connection management.
- **Intelligent Host Discovery:** Automatically performs ICMP ping sweeps before running subnet scans to drop unresponsive hosts, saving execution time.
- **Deep Service Detection:** Performs Banner Grabbing and socket header extraction to accurately identify underlying service names and version signatures.
- **Automated CVE Correlation:** Integrates with the NIST NVD API v2.0 to locate real-world Common Vulnerabilities and Exposures (CVEs) matching discovered services.
- **Multi-Format Reporting:** Automatically archives scan results into modern HTML web reports, machine-readable JSON files, and CSV spreadsheets.

---

## 🏗️ Technical Architecture (For Experts)

PVS relies on a modern asynchronous architecture to optimize network I/O:

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

- **I/O Concurrency:** Leverages `asyncio.Semaphore` to cap socket descriptors, preventing OS resource exhaustion and firewall rate-limiting blocks.
- **NVD Query Optimizations:** Implements an internal rate-limiter wrapper and local caching to respect the NIST API constraints while maintaining high query performance.

---

## 📥 Installation

### Option 1: Standalone Pre-compiled Binary (Recommended for Beginners)
No Python installation is required. This single binary runs directly out of your terminal:

1. Locate the pre-compiled `pvs.exe` inside the `dist/` folder.
2. Open PowerShell or Command Prompt.
3. Navigate to the folder.
4. Execute the tool:
   ```powershell
   .\pvs.exe scan 127.0.0.1
   ```
   *(Note: Remember the `.\` prefix in Windows PowerShell when executing local binaries).*

### Option 2: Python Source Installation (For Linux, macOS, and Developers)
For Linux, macOS, or custom testing environments, install from source (requires Python 3.10+):

```bash
# 1. Clone the repository
git clone https://github.com/MElsadany2165/PVS.git
cd PVS

# 2. Set up virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# 3. Install required libraries
pip install -r requirements.txt

# 4. Make execution entry point executable
chmod +x pvs_cli.py
```
You can run it directly:
```bash
python pvs_cli.py scan scanme.nmap.org
```

---

## 🚀 Quick Start Guide

### 1. Basic Local/Host Discovery Scan
Scan the top 20 ports of a target to discover open ports:
```powershell
# Using Standalone Binary
.\pvs.exe scan 127.0.0.1 -p top20

# Using Python Source
python pvs_cli.py scan 127.0.0.1 -p top20
```

### 2. Deep Vulnerability Scan
Grab service banners, identify application versions, and automatically check them against the NIST CVE database:
```powershell
.\pvs.exe scan 192.168.1.1 -p top100 --cve
```

### 3. Exhaustive Subnet Network Audit
Audit a whole subnet range for all 65,535 TCP ports with high speed (500 parallel workers), perform CVE checks, and export all report formats (`reports/PVS-*`):
```powershell
.\pvs.exe scan 192.168.1.0/24 -p all --cve -c 500 -t 1.5 -f all
```

---

## 🎛️ Port Presets & Options Reference

### Port Scan Presets
Specify ports using ranges (e.g., `-p 22,80,443` or `-p 1-1024`) or the following built-in preset shortcuts:
- `top20` (Scans top 20 standard ports)
- `top100` (Scans top 100 common services)
- `common` (Scans 1,000 standard ports)
- `enterprise` (Scans 5,000 corporate network ports)
- `all` (Scans full 1 to 65,535 TCP range)

### CLI Command Options Table
| Option | Short Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `--ports` | `-p` | Set target port numbers, ranges, or presets | `top100` |
| `--cve` | | Enable CVE vulnerability correlation from NIST NVD | Disabled |
| `--format` | `-f` | Export reports formats (`html`, `json`, `csv`, `all`) | `html` |
| `--concurrency`| `-c` | Maximum concurrent async socket connections | `100` |
| `--timeout` | `-t` | Max socket response wait time in seconds | `2.0` |
| `--quiet` | `-q` | Silent console execution (runs scan without prints) | Disabled |

---

## 🔑 NVD API Key Integration (For Experts)
To perform large subnet scans without getting rate-limited by the NIST API:
1. Request a free API Key from the [NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key).
2. Export the API Key in your terminal session before starting your scans:
   * **PowerShell:**
     ```powershell
     $env:NVD_API_KEY="your_api_key_here"
     ```
   * **Linux/macOS Bash:**
     ```bash
     export NVD_API_KEY="your_api_key_here"
     ```
PVS will automatically detect the key, increasing rate limits by **10x** for fast, high-volume CVE lookups.

---

## 📊 Report Outputs

Each scan creates detailed summaries in your project root `reports/` folder:
- **Interactive UI:** Console printouts managed by Rich, featuring clear, formatted status cards.
- **HTML Report:** Styled Web dashboard optimized with a premium cybersecurity Cyan-Slate layout, complete with threat severity metrics and CVE exploit details.
- **JSON & CSV:** Standard outputs for scripting, database logging, or automated dashboard integrations.

---

## 🛠️ Troubleshooting & OS Policies

### Windows AppLocker / SmartScreen Blocks
If you try to run the compiled binary on Windows and see this error:
`Program 'pvs.exe' failed to run: An Application Control policy has blocked this file`

This is caused by Group Policies blocking custom unsigned executables. You can bypass this by running the tool directly through the Python interpreter:
```powershell
.\venv\Scripts\python pvs_cli.py scan <target> [OPTIONS]
```

---

## 🛠️ Developer & Build Guide

If you want to modify code and build the executable yourself:
1. Set up dependencies:
   ```powershell
   pip install -r requirements.txt
   pip install pyinstaller pytest
   ```
2. Run pytest suite:
   ```powershell
   python -m pytest
   ```
3. Compile the standalone binary:
   ```powershell
   pyinstaller pvs.spec --noconfirm
   ```
   The compiled standalone binary will be written directly to the `dist/` directory.

---

## ⚖️ Authorized Use Policy

**WARNING:** This tool is strictly intended for **authorized network audits, ethical security testing, and educational purposes**.
- Do not scan networks or hosts you do not own or lack explicit authorization to audit.
- Misuse of this software may violate computer crime laws (such as the US CFAA or local equivalents). The developers assume zero liability for any damages or policy violations.

---

## 📄 License
MIT License - Copyright (c) 2026 Mohamed Essam Elsadany

<p align="center">
  <img src="docs/screenshots/pvs_full_scan_1.png" alt="PVS in action" width="700">
</p>

<h1 align="center">PVS — Personal Vulnerability Scanner</h1>

<p align="center">
  <strong>Scan networks. Detect services. Find vulnerabilities.</strong><br>
  <em>A fast, async Python CLI for port scanning, banner grabbing, and CVE lookup.</em>
</p>

<p align="center">
  <a href="#-installation"><img src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"></a>
  <a href="https://github.com/MElsadany2165/PVS/releases"><img src="https://img.shields.io/badge/version-1.1.0-cyan" alt="Version 1.1.0"></a>
  <a href="#%EF%B8%8F-legal-disclaimer"><img src="https://img.shields.io/badge/use-authorized%20only-red" alt="Authorized Use Only"></a>
</p>

---

## What is PVS?

PVS is a command-line tool that does three things:

1. **Discovers hosts** — Pings a target IP or entire subnet to find live devices.
2. **Scans ports & services** — Checks which ports are open, identifies the running service, and grabs version banners.
3. **Finds known vulnerabilities** — Looks up CVEs from the [NIST NVD](https://nvd.nist.gov/) database for every detected service.

Results are displayed in a rich terminal UI and exported as **HTML**, **JSON**, or **CSV** reports.

---

## 📥 Installation

**Requirements:** [Python 3.10+](https://www.python.org/downloads/) and pip.

```bash
git clone https://github.com/MElsadany2165/PVS.git
cd PVS
pip install .
```

Done. The `pvs` command is now available system-wide.

> [!TIP]
> Developers contributing to PVS should use `pip install -e ".[dev]"` instead — editable mode lets code changes take effect instantly without reinstalling.

---

## 🚀 Usage

### Basic Scan
```bash
pvs scan 192.168.1.1
```

### Scan with CVE Lookup
```bash
pvs scan 192.168.1.1 --cve
```

### Scan a Subnet
```bash
pvs scan 192.168.1.0/24
```

### Scan Specific Ports
```bash
pvs scan 192.168.1.1 -p 22,80,443,8080
```

### Full Audit (all ports, high speed, all report formats)
```bash
pvs scan 192.168.1.0/24 -p all --cve -c 500 -t 1.5 -f all
```

### Look Up a Port or Service
```bash
pvs info 443
pvs info ssh
```

> [!TIP]
> Reports are saved to the `reports/` folder automatically. Open the `.html` file in any browser for a visual dashboard.

---

## 📋 Command Reference

### Global Options

| Option | Description |
|:---|:---|
| `-V, --version` | Print PVS version |
| `-q, --quiet` | Suppress banner and non-essential output |
| `--log-level` | Set logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `--log-file` | Write logs to a file |

### `pvs scan` Options

| Option | Short | Description | Default |
|:---|:---|:---|:---|
| `target` | | IP, hostname, or CIDR range | *(required)* |
| `--ports` | `-p` | Ports to scan — numbers, ranges, or presets | `top100` |
| `--cve` | | Enable CVE vulnerability lookup via NIST NVD | off |
| `--timeout` | `-t` | Connection timeout in seconds | `2.0` |
| `--concurrency` | `-c` | Max simultaneous connections | `100` |
| `--format` | `-f` | Report format: `html`, `json`, `csv`, or `all` | `html` |
| `--output` | `-o` | Custom report file path | auto-generated |
| `--nvd-api-key` | | NVD API key for faster lookups | `$NVD_API_KEY` env var |
| `--max-cves` | | Max CVEs to return per service | `5` |
| `--no-ping` | | Skip ping sweep — force scan all IPs | off |
| `--no-banner-grab` | | Skip service version/banner detection | off |
| `--yes` | `-y` | Skip confirmation prompt on large scans | off |

### Port Presets

Use these with `-p` instead of manual port numbers:

| Preset | Ports |
|:---|:---|
| `top20` | Top 20 most common |
| `top100` | Top 100 services |
| `common` | 1,000 standard ports |
| `enterprise` | 5,000 enterprise ports |
| `all` | Full TCP range (1–65,535) |

---

## 🖥️ Screenshots

### CLI — Live Scan Progress
The terminal displays host discovery, async scan progress bars, and structured audit tables:

<p align="center">
  <img src="docs/screenshots/pvs_full_scan_2.png" alt="Scan progress bars" width="700">
</p>

### CLI — Port & Service Audit Results
Detailed per-host tables showing open ports, service names, versions, and captured banners:

<p align="center">
  <img src="docs/screenshots/pvs_full_scan_3.png" alt="Port audit results" width="700">
</p>

### HTML Report — Dashboard
Beautiful dark-themed report with scan summary and service breakdown:

<p align="center">
  <img src="docs/screenshots/html_report_2.png" alt="HTML report header" width="700">
</p>

<p align="center">
  <img src="docs/screenshots/html_report_1.png" alt="HTML report services table" width="700">
</p>

### HTML Report — CVE Vulnerability Cards
Each CVE includes severity rating, CVSS score, description, and attack vector:

<p align="center">
  <img src="docs/screenshots/html_report_4.png" alt="CVE vulnerability cards" width="700">
</p>

---

## 🔑 NVD API Key (Optional)

The NIST NVD throttles unauthenticated requests. For large scans, get a **free** API key to remove the rate limit:

1. Register at the [NVD Developer Portal](https://nvd.nist.gov/developers/request-an-api-key).
2. Set it before scanning:

   **Windows (PowerShell):**
   ```powershell
   $env:NVD_API_KEY="your_key_here"
   ```

   **Linux / macOS:**
   ```bash
   export NVD_API_KEY="your_key_here"
   ```

   Or pass it inline:
   ```bash
   pvs scan 192.168.1.1 --cve --nvd-api-key your_key_here
   ```

---

## 🏗️ Architecture

PVS is built on Python's `asyncio` for high-throughput network I/O:

```
┌──────────────────────────────────┐
│           PVS CLI Engine         │
└───────────────┬──────────────────┘
                │
┌───────────────▼──────────────────┐
│      ICMP Host Discovery         │
│      (Ping sweep for subnets)    │
└───────────────┬──────────────────┘
                │  Live hosts only
┌───────────────▼──────────────────┐
│    Async TCP Port Scanner        │
│  · Semaphore-limited connections │
│  · Service banner grabbing       │
│  · Version fingerprinting        │
└───────────────┬──────────────────┘
                │
┌───────────────▼──────────────────┐
│    NVD CVE Lookup Client         │
│  · Async HTTP with rate limiting │
│  · Local result caching          │
└───────────────┬──────────────────┘
                │
┌───────────────▼──────────────────┐
│    Report Generator              │
│  · HTML dashboard                │
│  · JSON structured data          │
│  · CSV spreadsheet export        │
└──────────────────────────────────┘
```

**Key design decisions:**
- **Semaphore-controlled concurrency** prevents OS socket exhaustion and firewall blocks.
- **Async NVD client** with local caching avoids redundant API calls and respects rate limits.
- **Zero external dependencies** beyond `rich` for terminal rendering — everything else is stdlib.

---

## 🛠️ Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run the test suite
python -m pytest

# Run with coverage
python -m pytest --cov=pvs
```

### Project Structure
```
PVS/
├── pvs/
│   ├── cli.py          # Argument parsing & command routing
│   ├── scanner.py      # Async TCP port scanner
│   ├── nvd_client.py   # NIST NVD API client with caching
│   ├── reporter.py     # HTML / JSON / CSV report generation
│   ├── display.py      # Rich terminal UI components
│   ├── services.py     # Well-known port/service mappings
│   └── logger.py       # Logging configuration
├── tests/              # Test suite
├── docs/               # Screenshots and demo reports
├── reports/            # Generated scan reports (git-ignored)
├── pyproject.toml      # Package configuration
└── README.md
```

---

## ⚖️ Legal Disclaimer

> [!CAUTION]
> **Authorized use only.** This tool is intended for ethical security testing, authorized network audits, and educational purposes.
>
> - **Do not** scan networks or systems you do not own or have explicit written permission to test.
> - Unauthorized scanning may violate laws such as the **US CFAA**, **UK CMA**, **EU NIS Directive**, or local equivalents.
> - The authors assume **no liability** for misuse, damages, or legal consequences.

---

## 📄 License

[MIT License](LICENSE) — Copyright © 2026 [Mohamed Essam Elsadany](https://github.com/MElsadany2165)

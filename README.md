<div align="center">

# 🛡️ PVS — Personal Vulnerability Scanner

**A powerful CLI tool for ethical security testing: port scanning, service detection, and CVE lookup.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

<img src="docs/demo.gif" alt="PVS Demo" width="700">

</div>

---

## ⚡ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Port Scanning** | High-speed async TCP connect scanning with configurable concurrency |
| 🏷️ **Service Detection** | Banner grabbing and protocol-aware service identification |
| 🛡️ **CVE Lookup** | Automatic vulnerability lookup via NIST NVD API v2.0 |
| 📊 **Rich Reports** | Export to JSON, CSV, and beautifully styled HTML reports |
| 🎯 **Flexible Targets** | Single IPs, CIDR ranges, IP ranges, and hostnames |
| 🎨 **Beautiful CLI** | Rich terminal output with progress bars and color-coded results |
| ⚡ **Fast** | Async I/O with semaphore-based concurrency control |
| 🔒 **Ethical** | Built-in legal disclaimers and authorization prompts |

---

## 📦 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/pvs.git
cd pvs

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate    # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -e .
```

### Dependencies

- **Python 3.10+** (uses modern type hints and `asyncio`)
- **[Rich](https://github.com/Textualize/rich)** — Beautiful terminal formatting
- No external scanning tools required (pure Python)

---

## 🚀 Usage

### Basic Port Scan

```bash
# Scan a host with top 100 ports
pvs scan 192.168.1.1

# Scan specific ports
pvs scan 192.168.1.1 -p 22,80,443,8080

# Scan a port range
pvs scan 192.168.1.1 -p 1-1024

# Use port presets
pvs scan 192.168.1.1 -p top20
pvs scan 192.168.1.1 -p common
```

### Network Range Scanning

```bash
# Scan a CIDR range
pvs scan 192.168.1.0/24 -p top20

# Scan an IP range
pvs scan 192.168.1.1-192.168.1.50 -p 22,80,443

# Scan a hostname
pvs scan example.com -p top100
```

### CVE Vulnerability Lookup

```bash
# Scan with CVE lookup (queries NVD API)
pvs scan 192.168.1.1 -p top100 --cve

# Use NVD API key for faster lookups (0.6s vs 6s rate limit)
pvs scan 192.168.1.1 --cve --nvd-api-key YOUR_KEY

# Set API key via environment variable
set NVD_API_KEY=your-api-key-here
pvs scan 192.168.1.1 --cve
```

> 💡 **Tip:** Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key

### Report Generation

```bash
# Save JSON report
pvs scan 192.168.1.1 -p top100 --cve -o report -f json

# Save HTML report (beautiful dark-themed report)
pvs scan 192.168.1.1 -p top100 --cve -o report -f html

# Save all formats at once
pvs scan 192.168.1.1 -p top100 --cve -o report -f all
```

### Other Commands

```bash
# Look up a port or service
pvs info 443
pvs info ssh

# Show version
pvs --version

# Quiet mode (no banner)
pvs -q scan 192.168.1.1
```

### Advanced Options

```bash
# Custom timeout and concurrency
pvs scan 10.0.0.1 -p 1-65535 -t 1.0 -c 500

# Disable banner grabbing (faster but less info)
pvs scan 10.0.0.1 -p top100 --no-banner-grab

# Skip confirmation for large scans
pvs scan 10.0.0.0/24 -p top100 -y

# Debug logging
pvs --log-level DEBUG scan 192.168.1.1
```

---

## 🏗️ Architecture

```
pvs/
├── __init__.py        # Package metadata
├── scanner.py         # Async port scanner & banner grabber
├── services.py        # Well-known services & port presets
├── nvd_client.py      # NIST NVD API v2.0 client
├── reporter.py        # JSON/CSV/HTML report generation
├── display.py         # Rich CLI display components
└── logger.py          # Logging configuration
pvs_cli.py             # Main CLI entry point
tests/
└── test_scanner.py    # Unit tests
```

### How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Target Input    │────▶│  Port Scanner    │────▶│ Service Detect   │
│  (IP/CIDR/Host)  │     │  (Async TCP)     │     │ (Banner Grab)    │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                           │
                         ┌──────────────────┐     ┌────────▼────────┐
                         │  Report Engine   │◀────│  NVD CVE API    │
                         │  (JSON/CSV/HTML) │     │  (Vuln Lookup)  │
                         └──────────────────┘     └─────────────────┘
```

1. **Target Resolution** — Parses IPs, CIDR ranges, hostnames into scan targets
2. **Port Scanning** — Async TCP connect scan with configurable concurrency
3. **Service Detection** — Banner grabbing with protocol-specific probes
4. **CVE Lookup** — Queries NVD API v2.0 for known vulnerabilities
5. **Reporting** — Generates structured reports in multiple formats

---

## 🔒 Security & Ethics

> **⚠️ IMPORTANT: This tool is for AUTHORIZED SECURITY TESTING ONLY.**

- ✅ Scan your own systems and networks
- ✅ Scan systems you have **written authorization** to test
- ✅ Use in CTF competitions and lab environments
- ❌ **NEVER** scan systems without explicit permission
- ❌ **NEVER** use this tool for unauthorized access

**Unauthorized port scanning is illegal in most jurisdictions.** The authors assume no liability for misuse.

### Responsible Disclosure

If you discover vulnerabilities using PVS, follow responsible disclosure practices:
1. Report to the system owner privately
2. Allow reasonable time for patching
3. Do not exploit or publicly disclose before a fix is available

---

## 🧪 Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=pvs --cov-report=html

# Format code
black pvs/ pvs_cli.py tests/

# Lint
ruff check pvs/ pvs_cli.py
```

---

## 📋 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║   ██████╗ ██╗   ██╗███████╗                                ║
║   ██╔══██╗██║   ██║██╔════╝    Personal Vulnerability      ║
║   ██████╔╝██║   ██║███████╗    Scanner v1.0.0              ║
║   ██╔═══╝ ╚██╗ ██╔╝╚════██║                                ║
║   ██║      ╚████╔╝ ███████║    Ethical Security Testing    ║
║   ╚═╝       ╚═══╝  ╚══════╝                                ║
╚══════════════════════════════════════════════════════════════╝

┌─ Scan Configuration ─────────────────────────────┐
│  Target:       scanme.nmap.org                   │
│  Ports:        100                               │
│  Timeout:      2.0s                              │
│  CVE Lookup:   Yes                               │
└──────────────────────────────────────────────────┘

🖥️  45.33.32.156 (scanme.nmap.org)
┌──────┬────────┬──────────┬───────────────────────┐
│ Port │ State  │ Service  │ Version               │
├──────┼────────┼──────────┼───────────────────────┤
│   22 │  open  │ ssh      │ OpenSSH_6.6.1p1       │
│   80 │  open  │ http     │ Apache/2.4.7          │
│ 9929 │  open  │ unknown  │                       │
└──────┴────────┴──────────┴───────────────────────┘

┌─ Scan Summary ───────────────────────────────────┐
│  ✅ Scan Complete                                │
│  Hosts scanned:  1                               │
│  Open ports:     3                               │
│  Total time:     4.82s                           │
└──────────────────────────────────────────────────┘
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
<strong>Built with ❤️ for the security community</strong>

⭐ Star this repo if you find it useful!

</div>

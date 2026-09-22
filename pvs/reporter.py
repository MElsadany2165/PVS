# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Report Generator - Creates scan reports in JSON, HTML, and CSV formats,
including CISA KEV exploit tags, Light/Dark theme switching, live search filtering,
and multi-OS (Linux, Windows, macOS) step-by-step remediation procedures.
"""

import json
import csv
import io
import html
from datetime import datetime
from typing import Optional

from .logger import get_logger
from pvs import __version__

logger = get_logger(__name__)


def generate_json_report(scan_data: dict, filepath: str):
    """Generate a JSON scan report with full vulnerability and multi-OS remediation details."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, default=str)
    logger.info(f"JSON report saved: {filepath}")


def generate_csv_report(scan_data: dict, filepath: str):
    """Generate a CSV scan report including KEV status and multi-OS remediation commands."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Host", "Port", "State", "Service", "Version", "Banner",
            "CVE ID", "Severity", "CVSS Score", "CISA KEV Exploited",
            "CVE Description", "Remediation Summary", "Linux Fix Command", "Windows Fix Command", "macOS Fix Command"
        ])
        for host in scan_data.get("hosts", []):
            ip = host.get("ip", "")
            for port in host.get("ports", []):
                cves = port.get("cves", [])
                if cves:
                    for cve in cves:
                        kev_str = "YES (EXPLOITED)" if cve.get("is_kev") else "NO"
                        rem = cve.get("remediation", {}) or {}
                        rem_sum = rem.get("summary", "")
                        cmd_lin, cmd_win, cmd_mac = "", "", ""
                        if rem.get("steps"):
                            for s in rem.get("steps", []):
                                if s.get("command_linux") and not cmd_lin:
                                    cmd_lin = s.get("command_linux").replace("\n", " ; ")
                                if s.get("command_windows") and not cmd_win:
                                    cmd_win = s.get("command_windows").replace("\n", " ; ")
                                if s.get("command_macos") and not cmd_mac:
                                    cmd_mac = s.get("command_macos").replace("\n", " ; ")
                        writer.writerow([
                            ip, port["port"], port["state"],
                            port.get("service", ""), port.get("version", ""),
                            port.get("banner", "")[:100],
                            cve.get("cve_id", ""), cve.get("severity", ""),
                            cve.get("score", 0.0), kev_str,
                            cve.get("description", "")[:200],
                            rem_sum, cmd_lin, cmd_win, cmd_mac
                        ])
                else:
                    writer.writerow([
                        ip, port["port"], port["state"],
                        port.get("service", ""), port.get("version", ""),
                        port.get("banner", "")[:100],
                        "", "", "", "", "", "", "", "", ""
                    ])
    logger.info(f"CSV report saved: {filepath}")


def generate_html_report(scan_data: dict, filepath: str):
    """Generate a state-of-the-art HTML scan report with Light/Dark mode, live search, and multi-OS fix tabs."""
    h = html.escape
    timestamp = scan_data.get("scan_time", datetime.now().isoformat())
    target = h(scan_data.get("target", "Unknown"))
    total_hosts = len(scan_data.get("hosts", []))
    total_open = sum(len(host.get("ports", [])) for host in scan_data.get("hosts", []))
    
    total_cves = 0
    total_kev = 0
    for host in scan_data.get("hosts", []):
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                total_cves += 1
                if cve.get("is_kev"):
                    total_kev += 1

    severity_colors = {
        "CRITICAL": "#f85149", "HIGH": "#da3633",
        "MEDIUM": "#d29922", "LOW": "#3fb950", "UNKNOWN": "#8b949e"
    }

    # Calculate severity counts
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for host in scan_data.get("hosts", []):
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                sev = cve.get("severity", "UNKNOWN").upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["UNKNOWN"] += 1

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PVS SECURITY THREAT & REMEDIATION REPORT - {target}</title>
<style>
:root {{
    --bg: #0d1117;
    --surface: #161b22;
    --surface-card: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --accent-hover: #79c0ff;
    --success: #3fb950;
    --warning: #d29922;
    --danger: #f85149;
    --kev: #ff7b72;
    --code-bg: #161b22;
    --code-border: #30363d;
    --code-text: #79c0ff;
    --shadow: rgba(0, 0, 0, 0.3);
}}

[data-theme="light"] {{
    --bg: #f6f8fa;
    --surface: #ffffff;
    --surface-card: #f6f8fa;
    --border: #d0d7de;
    --text: #1F2328;
    --muted: #656d76;
    --accent: #0969da;
    --accent-hover: #0550ae;
    --success: #1a7f37;
    --warning: #9a6700;
    --danger: #cf222e;
    --kev: #bc4c00;
    --code-bg: #f6f8fa;
    --code-border: #d0d7de;
    --code-text: #0550ae;
    --shadow: rgba(31, 35, 40, 0.08);
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
    padding-bottom: 3rem;
}}

.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}

/* Top Header Bar */
.top-bar {{
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 1.5rem;
}}

.theme-toggle-btn {{
    background: var(--surface-card); border: 1px solid var(--border);
    color: var(--text); padding: 0.4rem 0.9rem; border-radius: 6px;
    font-weight: 600; font-size: 0.85rem; cursor: pointer;
    display: flex; align-items: center; gap: 0.5rem;
}}
.theme-toggle-btn:hover {{ border-color: var(--accent); color: var(--accent); }}

.header {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px; padding: 1.75rem 2rem; margin-bottom: 1.5rem;
}}

.header h1 {{
    font-size: 1.6rem; font-weight: 600; color: var(--text);
    letter-spacing: -0.01em;
}}

.header .meta {{ color: var(--muted); margin-top: 0.4rem; font-size: 0.85rem; }}

/* Stats Section */
.stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem; margin-bottom: 1.5rem;
}}

.stat-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.25rem; text-align: left;
}}

.stat-card .value {{
    font-size: 2rem; font-weight: 600; color: var(--text);
}}

.stat-card .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; margin-top: 0.2rem; }}

/* Search & Filter Bar */
.filter-bar {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 0.85rem 1.25rem; margin-bottom: 1.5rem;
    display: flex; gap: 0.8rem; align-items: center; flex-wrap: wrap;
}}

.search-input {{
    flex: 1; min-width: 220px; background: var(--bg);
    border: 1px solid var(--border); color: var(--text);
    padding: 0.5rem 0.85rem; border-radius: 6px; font-size: 0.85rem;
    outline: none;
}}
.search-input:focus {{ border-color: var(--accent); }}

.filter-pill {{
    background: var(--surface-card); border: 1px solid var(--border);
    color: var(--muted); padding: 0.35rem 0.75rem; border-radius: 6px;
    font-size: 0.8rem; font-weight: 600; cursor: pointer; user-select: none;
}}
.filter-pill.active, .filter-pill:hover {{
    background: var(--accent); color: #0d1117; border-color: var(--accent);
}}

.section {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;
    box-shadow: 0 2px 8px var(--shadow);
}}

.section h2 {{
    font-size: 1.3rem; margin-bottom: 1rem;
    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border);
    color: var(--text);
}}

table {{ width: 100%; border-collapse: collapse; margin-bottom: 0.5rem; }}
th, td {{
    padding: 0.75rem 1rem; text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
}}
th {{ color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }}
.port-num {{ font-family: monospace; font-weight: 700; color: var(--accent); }}

.badge {{
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
}}
.badge-open {{ background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid var(--success); }}
.badge-kev {{ background: rgba(244, 63, 94, 0.2); color: var(--kev); border: 1px solid var(--kev); font-weight: 800; letter-spacing: 0.05em; }}

.cve-card {{
    background: var(--surface-card); border: 1px solid var(--border);
    border-radius: 10px; padding: 1.25rem; margin: 1rem 0;
}}
.cve-id {{ font-family: monospace; font-weight: 700; }}
.severity {{
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
}}

/* Multi-OS Remediation Accordion */
.remediation-box {{
    margin-top: 1rem; background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem;
}}
.remediation-title {{
    font-weight: 700; font-size: 0.95rem; color: var(--accent);
    display: flex; align-items: center; justify-content: space-between;
    cursor: pointer; user-select: none;
}}

.remediation-step {{
    background: var(--surface); border-left: 3px solid var(--accent);
    border-radius: 6px; padding: 0.9rem 1rem; margin-top: 0.75rem;
}}
.step-num {{ font-weight: 800; color: var(--accent); font-size: 0.85rem; text-transform: uppercase; margin-bottom: 0.2rem; }}

/* OS Tabs */
.os-tabs {{ display: flex; gap: 0.5rem; margin-top: 0.6rem; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }}
.os-tab {{
    background: var(--surface-card); border: 1px solid var(--border);
    color: var(--muted); padding: 0.25rem 0.7rem; border-radius: 4px;
    font-size: 0.75rem; font-weight: 600; cursor: pointer;
}}
.os-tab.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}

.code-block {{
    background: var(--code-bg); border: 1px solid var(--code-border); color: var(--code-text);
    padding: 0.75rem 0.8rem; border-radius: 6px; font-family: monospace;
    font-size: 0.85rem; white-space: pre-wrap; margin-top: 0.4rem; overflow-x: auto;
    position: relative; display: none;
}}
.code-block.active {{ display: block; }}

.copy-btn {{
    float: right; background: var(--border); color: var(--text); border: none;
    padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; cursor: pointer;
    margin-bottom: 0.3rem;
}}
.copy-btn:hover {{ background: var(--accent); color: #fff; }}

.footer {{ text-align: center; color: var(--muted); padding: 2.5rem; font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
</style>
<script>
function toggleTheme() {{
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('pvs_theme', next);
    document.getElementById('theme-btn-text').innerText = next === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
}}

function switchOs(stepId, osName, btn) {{
    const stepEl = document.getElementById(stepId);
    if (!stepEl) return;
    const tabs = stepEl.querySelectorAll('.os-tab');
    tabs.forEach(t => t.classList.remove('active'));
    btn.classList.add('active');

    const blocks = stepEl.querySelectorAll('.code-block');
    blocks.forEach(b => b.classList.remove('active'));
    const targetBlock = stepEl.querySelector('.code-block-' + osName);
    if (targetBlock) targetBlock.classList.add('active');
}}

function copyCode(btn) {{
    const codeBlock = btn.nextElementSibling;
    const code = codeBlock.innerText;
    navigator.clipboard.writeText(code);
    btn.innerText = 'Copied!';
    setTimeout(() => btn.innerText = 'Copy', 2000);
}}

function filterCards() {{
    const query = document.getElementById('vuln-search').value.toLowerCase();
    const cards = document.querySelectorAll('.cve-card');
    cards.forEach(card => {{
        const text = card.innerText.toLowerCase();
        if (text.includes(query)) {{
            card.style.display = 'block';
        }} else {{
            card.style.display = 'none';
        }}
    }});
}}

window.addEventListener('DOMContentLoaded', () => {{
    const saved = localStorage.getItem('pvs_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    document.getElementById('theme-btn-text').innerText = saved === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
}});
</script>
</head>
<body>
<div class="container">
<div class="top-bar">
    <div style="font-weight: 800; font-size: 1.1rem; color: var(--accent);">PVS THREAT AUDIT ENGINE</div>
    <button class="theme-toggle-btn" onclick="toggleTheme()">
        <span id="theme-btn-text">☀️ Light Mode</span>
    </button>
</div>

<div class="header">
    <h1>PVS Threat Recon & Multi-OS Remediation Audit</h1>
    <div class="meta">
        <strong>Target Matrix:</strong> {target} &nbsp;|&nbsp;
        <strong>Execution Time:</strong> {h(str(timestamp))} &nbsp;|&nbsp;
        <strong>Audit Engine:</strong> PVS v{h(__version__)}
    </div>
</div>

<div class="stats">
    <div class="stat-card"><div class="value">{total_hosts}</div><div class="label">Hosts Scanned</div></div>
    <div class="stat-card"><div class="value">{total_open}</div><div class="label">Open Ports</div></div>
    <div class="stat-card"><div class="value">{total_cves}</div><div class="label">CVEs Found</div></div>
    <div class="stat-card"><div class="value" style="color:var(--kev);">{total_kev}</div><div class="label">CISA KEV Exploited</div></div>
    <div class="stat-card">
        <div class="value" style="font-size: 1.5rem; display: flex; justify-content: center; gap: 0.5rem; margin-top: 0.8rem; margin-bottom: 0.8rem;">
            <span style="color:{severity_colors['CRITICAL']};" title="Critical">{sev_counts['CRITICAL']}</span>
            <span style="color:var(--muted)">/</span>
            <span style="color:{severity_colors['HIGH']};" title="High">{sev_counts['HIGH']}</span>
            <span style="color:var(--muted)">/</span>
            <span style="color:{severity_colors['MEDIUM']};" title="Medium">{sev_counts['MEDIUM']}</span>
            <span style="color:var(--muted)">/</span>
            <span style="color:{severity_colors['LOW']};" title="Low">{sev_counts['LOW']}</span>
        </div>
        <div class="label">Crit / High / Med / Low</div>
    </div>
</div>

<div class="filter-bar">
    <input type="text" id="vuln-search" class="search-input" placeholder="🔍 Search vulnerabilities, services, ports, or CVE IDs..." onkeyup="filterCards()">
</div>
"""

    step_counter = 0

    for host_data in scan_data.get("hosts", []):
        ip = h(host_data.get("ip", ""))
        hostname = h(host_data.get("hostname", ""))
        scan_time = host_data.get("scan_time", 0)
        ports = host_data.get("ports", [])

        html_content += f"""
<div class="section">
    <h2>Host: {ip}{f' ({hostname})' if hostname else ''}</h2>
    <p style="color:var(--muted);margin-bottom:1rem;">
        Scan completed in {scan_time:.2f}s — {len(ports)} open port(s)
    </p>
    <table>
        <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Captured Banner / Recon</th></tr></thead>
        <tbody>
"""
        for port in ports:
            pn = port.get("port", "")
            svc = h(port.get("service", ""))
            ver = h(port.get("version", ""))
            banner = port.get("banner", "")
            
            banner_html = ""
            if banner:
                banner_lines = [h(line.strip()) for line in banner.split('\n') if line.strip()]
                preview = banner_lines[0] if banner_lines else ""
                if len(banner_lines) > 1:
                    full_banner = "<br>".join(banner_lines)
                    banner_html = f"""
                    <details style="cursor: pointer; font-size: 0.8rem; color: var(--muted);">
                        <summary style="outline:none;">{preview[:50]}...</summary>
                        <pre style="background: var(--code-bg); border: 1px solid var(--border); padding: 0.5rem; border-radius: 6px; margin-top: 0.3rem; overflow-x: auto; white-space: pre-wrap; font-family: monospace; color: var(--code-text); text-align: left;">{full_banner}</pre>
                    </details>
                    """
                else:
                    banner_html = f'<span style="font-family: monospace; font-size: 0.8rem; color: var(--muted);">{preview[:60]}</span>'
            else:
                banner_html = '<span style="color: var(--muted); font-size: 0.8rem; font-style: italic;">None</span>'

            html_content += f"""
            <tr>
                <td class="port-num">{pn}</td>
                <td><span class="badge badge-open">open</span></td>
                <td>{svc}</td>
                <td>{ver if ver else '<span style="color: var(--muted); font-size: 0.8rem; font-style: italic;">-</span>'}</td>
                <td>{banner_html}</td>
            </tr>"""

        html_content += "</tbody></table>"

        # CVEs
        has_cves = any(port.get("cves") for port in ports)
        if has_cves:
            html_content += '<h3 style="margin-top:1.5rem;margin-bottom:0.5rem;">⚠️ Identified Vulnerabilities & Multi-OS Fix Procedures</h3>'
            for port in ports:
                for cve in port.get("cves", []):
                    sev = cve.get("severity", "UNKNOWN")
                    color = severity_colors.get(sev, "#6b7280")
                    vector = h(cve.get("vector", ""))
                    published = h(cve.get("published", ""))
                    is_kev = cve.get("is_kev", False)
                    kev_action = h(cve.get("kev_action", ""))
                    
                    kev_badge = '<span class="badge badge-kev" style="margin-left:0.5rem;">🚨 CISA KEV - EXPLOITED IN WILD</span>' if is_kev else ''
                    vector_html = f'<div style="font-family: monospace; font-size: 0.75rem; color: var(--muted); margin-top: 0.4rem; background: var(--bg); padding: 0.25rem 0.5rem; border-radius: 4px; display: inline-block;">CVSS Vector: {vector}</div>' if vector else ''
                    published_html = f'<span style="color: var(--muted); font-size: 0.75rem; margin-left: 1rem;">Published: {published}</span>' if published else ''

                    # Multi-OS Remediation steps rendering
                    remediation = cve.get("remediation") or {}
                    steps_html = ""
                    if remediation and remediation.get("steps"):
                        steps_list = remediation.get("steps", [])
                        steps_content = ""
                        for step in steps_list:
                            step_counter += 1
                            step_id = f"step-{step_counter}"
                            st_num = step.get("step_number", 1)
                            st_title = h(step.get("title", ""))
                            st_desc = h(step.get("description", ""))
                            st_cat = h(step.get("category", "patch")).upper()

                            cmd_lin = h(step.get("command_linux") or step.get("command", ""))
                            cmd_win = h(step.get("command_windows") or step.get("command", ""))
                            cmd_mac = h(step.get("command_macos") or step.get("command", ""))

                            steps_content += f"""
                            <div class="remediation-step" id="{step_id}">
                                <div class="step-num">Step {st_num}: {st_title} <span style="font-size:0.7rem; color:var(--muted); font-weight:normal;">[{st_cat}]</span></div>
                                <p style="font-size:0.85rem; color:var(--text);">{st_desc}</p>
                                
                                <div class="os-tabs">
                                    <div class="os-tab active" onclick="switchOs('{step_id}', 'linux', this)">🐧 Linux</div>
                                    <div class="os-tab" onclick="switchOs('{step_id}', 'windows', this)">🪟 Windows</div>
                                    <div class="os-tab" onclick="switchOs('{step_id}', 'macos', this)">🍏 macOS</div>
                                </div>

                                <div>
                                    <button class="copy-btn" onclick="copyCode(this)">Copy</button>
                                    <div class="code-block code-block-linux active"><code>{cmd_lin if cmd_lin else '# No specific Linux command required'}</code></div>
                                    <div class="code-block code-block-windows"><code>{cmd_win if cmd_win else '# No specific Windows command required'}</code></div>
                                    <div class="code-block code-block-macos"><code>{cmd_mac if cmd_mac else '# No specific macOS command required'}</code></div>
                                </div>
                            </div>
                            """

                        steps_html = f"""
                        <details class="remediation-box" open>
                            <summary class="remediation-title">
                                🛠️ Multi-OS Step-by-Step Remediation Procedure ({len(steps_list)} Steps)
                            </summary>
                            <p style="font-size:0.85rem; color:var(--muted); margin-top:0.4rem;">{h(remediation.get('summary', ''))}</p>
                            {steps_content}
                        </details>
                        """

                    html_content += f"""
<div class="cve-card" style="border-left: 4px solid {color};">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
        <div>
            <span class="cve-id" style="color:{color}; font-size: 1rem;">{h(cve['cve_id'])}</span>
            <span class="severity" style="background:{color}22;color:{color}; margin-left: 0.5rem;">{sev} ({cve.get('score', 0)})</span>
            {kev_badge}
        </div>
        <span style="color:var(--muted); font-size: 0.8rem;">Port {port['port']}/{h(port.get('service',''))} {published_html}</span>
    </div>
    <p style="font-size: 0.9rem; color: var(--text);">{h(cve.get('description', ''))}</p>
    {f'<p style="font-size: 0.85rem; color: var(--kev); margin-top: 0.4rem;"><strong>CISA KEV Required Action:</strong> {kev_action}</p>' if kev_action else ''}
    {vector_html}
    {steps_html}
</div>"""

        html_content += "</div>"

    html_content += f"""
<div class="footer">
    Generated by <strong>PVS - Personal Vulnerability Scanner</strong> v{h(__version__)}<br>
    Developed by <strong>Mohamed Essam Elsadany</strong> | Copyright &copy; 2026<br>
    WARNING: For authorized security testing only. Always obtain proper permission before scanning.
</div>
</div></body></html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"HTML report saved: {filepath}")


def build_scan_data(target, host_results, cve_results=None):
    """Build structured scan data dict from results."""
    hosts_data = []
    for hr in host_results:
        ports_data = []
        for pr in hr.ports:
            port_entry = {
                "port": pr.port, "state": pr.state,
                "service": pr.service, "version": pr.version,
                "banner": pr.banner,
            }
            # Attach CVEs if available
            key = f"{hr.ip}:{pr.port}"
            if cve_results and key in cve_results:
                cves_list = []
                for c in cve_results[key]:
                    if hasattr(c, "to_dict"):
                        cves_list.append(c.to_dict())
                    elif isinstance(c, dict):
                        cves_list.append(c)
                    else:
                        cves_list.append({
                            "cve_id": c.cve_id, "description": c.description,
                            "severity": c.severity, "score": c.score,
                            "vector": c.vector, "published": c.published,
                            "references": c.references,
                        })
                port_entry["cves"] = cves_list
            else:
                port_entry["cves"] = []
            ports_data.append(port_entry)
        hosts_data.append({
            "ip": hr.ip, "hostname": hr.hostname,
            "is_up": hr.is_up, "scan_time": hr.scan_time,
            "ports": ports_data,
        })
    return {
        "scanner": "PVS", "version": __version__,
        "scan_time": datetime.now().isoformat(),
        "target": target, "hosts": hosts_data,
    }

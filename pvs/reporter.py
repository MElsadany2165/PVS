"""
Report Generator - Creates scan reports in JSON, HTML, and CSV formats.
"""
import json
import csv
import io
import html
from datetime import datetime
from typing import Optional

from .logger import get_logger

logger = get_logger(__name__)


def generate_json_report(scan_data: dict, filepath: str):
    """Generate a JSON scan report."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, default=str)
    logger.info(f"JSON report saved: {filepath}")


def generate_csv_report(scan_data: dict, filepath: str):
    """Generate a CSV scan report."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Host", "Port", "State", "Service", "Version", "Banner",
            "CVE ID", "Severity", "CVSS Score", "Description"
        ])
        for host in scan_data.get("hosts", []):
            ip = host.get("ip", "")
            for port in host.get("ports", []):
                cves = port.get("cves", [])
                if cves:
                    for cve in cves:
                        writer.writerow([
                            ip, port["port"], port["state"],
                            port.get("service", ""), port.get("version", ""),
                            port.get("banner", "")[:100],
                            cve["cve_id"], cve["severity"],
                            cve["score"], cve["description"][:200]
                        ])
                else:
                    writer.writerow([
                        ip, port["port"], port["state"],
                        port.get("service", ""), port.get("version", ""),
                        port.get("banner", "")[:100],
                        "", "", "", ""
                    ])
    logger.info(f"CSV report saved: {filepath}")


def generate_html_report(scan_data: dict, filepath: str):
    """Generate a professional, detailed HTML scan report."""
    h = html.escape
    timestamp = scan_data.get("scan_time", datetime.now().isoformat())
    target = h(scan_data.get("target", "Unknown"))
    total_hosts = len(scan_data.get("hosts", []))
    total_open = sum(len(host.get("ports", [])) for host in scan_data.get("hosts", []))
    total_cves = sum(
        len(cve) for host in scan_data.get("hosts", [])
        for port in host.get("ports", [])
        for cve in [port.get("cves", [])]
    )

    severity_colors = {
        "CRITICAL": "#dc2626", "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04", "LOW": "#16a34a", "UNKNOWN": "#6b7280"
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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PVS THREAT ASSESSMENT AUDIT - {target}</title>
<style>
:root {{
    --bg: #07090e; --surface: #0f131a; --border: #1e293b;
    --text: #f8fafc; --muted: #94a3b8; --accent: #06b6d4;
    --success: #10b981; --warning: #ca8a04; --danger: #ef4444;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
}}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
.header {{
    background: linear-gradient(135deg, #0f172a 0%, #020617 100%);
    border: 1px solid var(--border); border-top: 4px solid var(--accent);
    border-radius: 16px; padding: 2.5rem; margin-bottom: 2rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}}
.header h1 {{
    font-size: 2.2rem; font-weight: 800;
    background: linear-gradient(135deg, #06b6d4, #3b82f6);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: -0.025em;
}}
.header .meta {{ color: var(--muted); margin-top: 0.5rem; font-size: 0.9rem; }}
.stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
}}
.stat-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem; text-align: center;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}}
.stat-card .value {{
    font-size: 2.5rem; font-weight: 700; color: var(--accent);
}}
.stat-card .label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }}
.section {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
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
.port-num {{ font-family: monospace; font-weight: 600; color: var(--accent); }}
.badge {{
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
}}
.badge-open {{ background: rgba(16, 185, 129, 0.15); color: var(--success); }}
.cve-card {{
    background: rgba(30, 41, 59, 0.3); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.25rem; margin: 0.75rem 0;
}}
.cve-id {{ font-family: monospace; font-weight: 700; }}
.severity {{
    display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
    font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
}}
.footer {{ text-align: center; color: var(--muted); padding: 2.5rem; font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
    <h1>PVS Threat Recon Report</h1>
    <div class="meta">
        <strong>Target Matrix:</strong> {target} &nbsp;|&nbsp;
        <strong>Execution Time:</strong> {h(str(timestamp))} &nbsp;|&nbsp;
        <strong>Audit Engine:</strong> PVS v1.0.0
    </div>
</div>
<div class="stats">
    <div class="stat-card"><div class="value">{total_hosts}</div><div class="label">Hosts Scanned</div></div>
    <div class="stat-card"><div class="value">{total_open}</div><div class="label">Open Ports</div></div>
    <div class="stat-card"><div class="value">{total_cves}</div><div class="label">CVEs Found</div></div>
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
"""

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
                        <pre style="background: rgba(0,0,0,0.3); border: 1px solid var(--border); padding: 0.5rem; border-radius: 6px; margin-top: 0.3rem; overflow-x: auto; white-space: pre-wrap; font-family: monospace; color: #a78bfa; text-align: left;">{full_banner}</pre>
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
            html_content += '<h3 style="margin-top:1.5rem;margin-bottom:0.5rem;">⚠️ Vulnerabilities</h3>'
            for port in ports:
                for cve in port.get("cves", []):
                    sev = cve.get("severity", "UNKNOWN")
                    color = severity_colors.get(sev, "#6b7280")
                    vector = h(cve.get("vector", ""))
                    published = h(cve.get("published", ""))
                    
                    vector_html = f'<div style="font-family: monospace; font-size: 0.75rem; color: var(--muted); margin-top: 0.4rem; background: rgba(0,0,0,0.15); padding: 0.25rem 0.5rem; border-radius: 4px; display: inline-block;">CVSS Vector: {vector}</div>' if vector else ''
                    published_html = f'<span style="color: var(--muted); font-size: 0.75rem; margin-left: 1rem;">Published: {published}</span>' if published else ''
                    
                    html_content += f"""
<div class="cve-card" style="border-left: 4px solid {color};">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
        <div>
            <span class="cve-id" style="color:{color}; font-size: 1rem;">{h(cve['cve_id'])}</span>
            <span class="severity" style="background:{color}22;color:{color}; margin-left: 0.5rem;">{sev} ({cve.get('score', 0)})</span>
        </div>
        <span style="color:var(--muted); font-size: 0.8rem;">Port {port['port']}/{h(port.get('service',''))} {published_html}</span>
    </div>
    <p style="font-size: 0.9rem; color: var(--text);">{h(cve.get('description', ''))}</p>
    {vector_html}
</div>"""

        html_content += "</div>"

    html_content += f"""
<div class="footer">
    Generated by <strong>PVS - Personal Vulnerability Scanner</strong> v1.0.0<br>
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
                port_entry["cves"] = [
                    {
                        "cve_id": c.cve_id, "description": c.description,
                        "severity": c.severity, "score": c.score,
                        "vector": c.vector, "published": c.published,
                        "references": c.references,
                    }
                    for c in cve_results[key]
                ]
            else:
                port_entry["cves"] = []
            ports_data.append(port_entry)
        hosts_data.append({
            "ip": hr.ip, "hostname": hr.hostname,
            "is_up": hr.is_up, "scan_time": hr.scan_time,
            "ports": ports_data,
        })
    return {
        "scanner": "PVS", "version": "1.0.0",
        "scan_time": datetime.now().isoformat(),
        "target": target, "hosts": hosts_data,
    }

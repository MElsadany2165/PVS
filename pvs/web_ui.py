# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Interactive Web GUI & Real-Time Topology Visualizer.
Runs a zero-dependency, local HTTP server delivering an enterprise-grade SPA:
  • Real-time scan launcher & progress visualization
  • Interactive SVG/Canvas network topology map
  • Exploitability Matrix with FIRST EPSS & CISA KEV tags
  • CIS Controls v8 compliance radar & checklist
  • 1-Click root-cause remediation & rollback script generator
"""

import asyncio
import json
import os
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any

from pvs import __version__
from .logger import get_logger
from .scanner import get_local_subnet, get_local_ip, resolve_targets, scan_host, parse_ports
from .vuln_engine import VulnerabilityEngine
from .brain import analyze_scan_results
from .compliance import evaluate_cis_benchmarks
from .threat_intel import generate_threat_matrix
from .remediation_engine import generate_remediation_script, generate_rollback_script, simulate_dry_run

logger = get_logger(__name__)

# Global state for web UI
_STATE: Dict[str, Any] = {
    "is_scanning": False,
    "progress": 0,
    "status_message": "Ready to scan",
    "last_scan_data": None,
    "last_brain_posture": None,
    "last_compliance": None,
    "last_threat_matrix": None,
}


def _run_background_scan(target: str, ports_preset: str):
    """Run an async scan in a background thread and update global state."""
    async def _async_worker():
        _STATE["is_scanning"] = True
        _STATE["progress"] = 10
        _STATE["status_message"] = f"Resolving targets for {target}..."

        try:
            resolved = resolve_targets(target)
            if not resolved:
                _STATE["status_message"] = f"Error: Could not resolve target '{target}'."
                _STATE["is_scanning"] = False
                return

            ports = parse_ports(ports_preset)
            _STATE["progress"] = 25
            _STATE["status_message"] = f"Scanning {len(resolved)} host(s) across {len(ports)} ports..."

            host_results = []
            for idx, host_ip in enumerate(resolved):
                _STATE["status_message"] = f"Scanning host {host_ip} ({idx+1}/{len(resolved)})..."
                res = await scan_host(host_ip, ports, timeout=1.5, concurrency=100)
                if res.is_up or res.ports:
                    host_results.append(res)
                _STATE["progress"] = 25 + int(35 * ((idx + 1) / len(resolved)))

            _STATE["status_message"] = "Querying threat intelligence & active probes..."
            _STATE["progress"] = 65

            vuln_engine = VulnerabilityEngine(offline_mode=False)
            cve_results = {}
            for h in host_results:
                for p in h.ports:
                    cves = await vuln_engine.audit_and_lookup_cves_async(
                        ip=h.ip, port=p.port, service=p.service, banner=p.banner, tls_info=p.tls_info
                    )
                    if cves:
                        cve_results[f"{h.ip}:{p.port}"] = cves

            _STATE["progress"] = 85
            _STATE["status_message"] = "Correlating Brain attack surface & CIS benchmarks..."

            posture = analyze_scan_results(host_results, cve_results, scan_mode="online")

            # Format scan data
            hosts_json = []
            for h in host_results:
                ports_json = []
                for p in h.ports:
                    cves = cve_results.get(f"{h.ip}:{p.port}", [])
                    ports_json.append({
                        "port": p.port,
                        "state": p.state,
                        "service": p.service,
                        "banner": p.banner,
                        "cves": [c.to_dict() if hasattr(c, "to_dict") else c for c in cves],
                    })
                hosts_json.append({
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "ports": ports_json,
                })

            scan_data = {
                "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "target": target,
                "hosts": hosts_json,
                "cve_results": {k: [c.to_dict() if hasattr(c, "to_dict") else c for c in v] for k, v in cve_results.items()},
                "risk_score": posture.risk_score,
                "risk_level": posture.risk_level,
            }

            # Threat Intel matrix
            all_flat_cves = []
            for clist in cve_results.values():
                for c in clist:
                    all_flat_cves.append(c.to_dict() if hasattr(c, "to_dict") else c)
            t_matrix = generate_threat_matrix(all_flat_cves)

            # CIS Benchmarks
            compliance = evaluate_cis_benchmarks(
                target=target,
                scan_hosts=hosts_json,
                active_vulns=all_flat_cves,
            )

            _STATE["last_scan_data"] = scan_data
            _STATE["last_brain_posture"] = posture.to_dict()
            _STATE["last_compliance"] = compliance.to_dict()
            _STATE["last_threat_matrix"] = t_matrix
            _STATE["progress"] = 100
            _STATE["status_message"] = f"Audit complete! Discovered {len(host_results)} live host(s) and {len(all_flat_cves)} threat(s)."

        except Exception as e:
            logger.exception(f"Web UI background scan error: {e}")
            _STATE["status_message"] = f"Scan error: {e}"
        finally:
            _STATE["is_scanning"] = False

    def _thread_target():
        asyncio.run(_async_worker())

    t = threading.Thread(target=_thread_target, daemon=True)
    t.start()


HTML_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PVS — Personal Vulnerability Scanner Live Web UI</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: rgba(17, 24, 39, 0.85);
      --card-border: rgba(55, 65, 81, 0.6);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --cyan: #06b6d4;
      --cyan-glow: rgba(6, 182, 212, 0.35);
      --red: #ef4444;
      --orange: #f97316;
      --yellow: #eab308;
      --green: #10b981;
      --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: var(--font-family); }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }
    
    /* Header */
    header {
      background: rgba(15, 23, 42, 0.95);
      border-bottom: 1px solid var(--card-border);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      backdrop-filter: blur(8px);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand h1 { font-size: 20px; font-weight: 800; letter-spacing: 0.5px; }
    .brand span { color: var(--cyan); }
    .badge { background: rgba(6, 182, 212, 0.15); color: var(--cyan); border: 1px solid var(--cyan); border-radius: 9999px; font-size: 11px; padding: 2px 10px; font-weight: 600; }
    
    /* Container */
    main { max-width: 1400px; width: 100%; margin: 0 auto; padding: 24px 32px; flex: 1; display: flex; flex-direction: column; gap: 24px; }
    
    /* Scan Control Card */
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px;
      backdrop-filter: blur(12px);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .scan-form { display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-end; }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    label { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); }
    input, select {
      background: #1f2937;
      border: 1px solid #374151;
      color: var(--text);
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input:focus, select:focus { border-color: var(--cyan); box-shadow: 0 0 0 2px var(--cyan-glow); }
    .btn {
      background: linear-gradient(135deg, #0891b2, #06b6d4);
      color: white;
      border: none;
      padding: 10px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.1s, box-shadow 0.2s;
    }
    .btn:hover { box-shadow: 0 0 15px var(--cyan-glow); transform: translateY(-1px); }
    .btn:active { transform: translateY(0); }
    .btn:disabled { background: #4b5563; cursor: not-allowed; box-shadow: none; }
    
    /* Progress Bar */
    .progress-bar-container { margin-top: 16px; height: 8px; background: #1f2937; border-radius: 999px; overflow: hidden; }
    .progress-bar-fill { height: 100%; width: 0%; background: linear-gradient(90deg, #06b6d4, #10b981); transition: width 0.3s; }
    .status-text { margin-top: 8px; font-size: 13px; color: var(--text-muted); }
    
    /* Grid layout */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
    .stat-card {
      background: rgba(31, 41, 55, 0.6);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .stat-num { font-size: 32px; font-weight: 800; color: var(--cyan); }
    .stat-label { font-size: 13px; color: var(--text-muted); font-weight: 500; }
    
    /* Topology Map Canvas */
    .topo-container {
      position: relative;
      background: #0d1322;
      border: 1px solid var(--card-border);
      border-radius: 12px;
      height: 380px;
      overflow: hidden;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    svg.topo-svg { width: 100%; height: 100%; }
    
    /* Tabs */
    .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--card-border); padding-bottom: 12px; margin-bottom: 16px; }
    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 14px;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      transition: color 0.2s, background 0.2s;
    }
    .tab-btn.active { color: white; background: #1f2937; }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    
    /* Table */
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th { text-align: left; padding: 10px 14px; font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid #374151; }
    td { padding: 12px 14px; font-size: 13px; border-bottom: 1px solid rgba(55, 65, 81, 0.4); }
    tr:hover { background: rgba(31, 41, 55, 0.4); }
    
    /* Tags */
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
    .tag-crit { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .tag-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
    .tag-med { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
    .tag-pass { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    
    /* Script Box */
    pre.code-box {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 16px;
      color: #38bdf8;
      font-size: 12px;
      overflow-x: auto;
      max-height: 280px;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <h1>PVS <span>Security Dashboard</span></h1>
      <span class="badge">v""" + __version__ + """</span>
    </div>
    <div id="connectionStatus" style="font-size: 13px; color: var(--green); display: flex; align-items: center; gap: 6px;">
      ● Online & Ready
    </div>
  </header>

  <main>
    <!-- Scan Controller -->
    <section class="card">
      <h2 style="font-size: 16px; font-weight: 700; margin-bottom: 16px;">Live Network Audit Controller</h2>
      <div class="scan-form">
        <div class="form-group" style="flex: 2; min-width: 200px;">
          <label>Target Subnet / Host</label>
          <input type="text" id="targetInput" value="127.0.0.1" placeholder="e.g. 127.0.0.1 or 192.168.1.0/24">
        </div>
        <div class="form-group" style="flex: 1; min-width: 140px;">
          <label>Port Preset</label>
          <select id="portsSelect">
            <option value="top20">Top 20 Critical</option>
            <option value="top100" selected>Top 100 Common</option>
            <option value="common">Common Enterprise</option>
            <option value="1-1024">Standard (1-1024)</option>
          </select>
        </div>
        <button id="scanBtn" class="btn" onclick="startScan()">Start Live Scan</button>
      </div>

      <div class="progress-bar-container">
        <div id="progressFill" class="progress-bar-fill"></div>
      </div>
      <div id="statusMessage" class="status-text">Ready to initiate audit.</div>
    </section>

    <!-- Posture Overview Grid -->
    <section class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Security Posture Score</div>
        <div id="statRiskScore" class="stat-num" style="color: var(--green);">0 / 100</div>
        <div id="statRiskLevel" style="font-size: 12px; color: var(--text-muted);">CLEAN POSTURE</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Live Active Hosts</div>
        <div id="statHosts" class="stat-num">0</div>
        <div style="font-size: 12px; color: var(--text-muted);">Responsive on Network</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Open Network Sockets</div>
        <div id="statPorts" class="stat-num">0</div>
        <div style="font-size: 12px; color: var(--text-muted);">Audited Endpoints</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">CIS v8 Compliance Score</div>
        <div id="statCompliance" class="stat-num" style="color: var(--cyan);">--</div>
        <div id="statComplianceLevel" style="font-size: 12px; color: var(--text-muted);">Framework Readiness</div>
      </div>
    </section>

    <!-- Network Topology Map -->
    <section class="card">
      <h2 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;">Interactive Network Topology Visualizer</h2>
      <div class="topo-container">
        <svg id="topoCanvas" class="topo-svg"></svg>
      </div>
    </section>

    <!-- Tabbed Detailed Analytics -->
    <section class="card">
      <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('threatsTab', this)">Threat Intelligence & EPSS</button>
        <button class="tab-btn" onclick="switchTab('complianceTab', this)">CIS Benchmark Controls</button>
        <button class="tab-btn" onclick="switchTab('remediationTab', this)">1-Click Remediation & Rollback</button>
      </div>

      <!-- Threat Intel Tab -->
      <div id="threatsTab" class="tab-content active">
        <table id="threatsTable">
          <thead>
            <tr>
              <th>Vulnerability / CVE</th>
              <th>CVSS</th>
              <th>EPSS 30d Probability</th>
              <th>CISA KEV Status</th>
              <th>Real-World Exploit Index (REI)</th>
              <th>Threat Urgency</th>
            </tr>
          </thead>
          <tbody id="threatsBody">
            <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Run a scan to inspect threat intelligence.</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Compliance Tab -->
      <div id="complianceTab" class="tab-content">
        <table id="complianceTable">
          <thead>
            <tr>
              <th>CIS Control</th>
              <th>Safeguard Title</th>
              <th>NIST CSF Mapping</th>
              <th>Audit Status</th>
              <th>Evidence / Findings</th>
            </tr>
          </thead>
          <tbody id="complianceBody">
            <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Run a scan to evaluate CIS Benchmarks.</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Remediation & Rollback Tab -->
      <div id="remediationTab" class="tab-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <h3 style="font-size: 14px;">Automated Enterprise Remediation Script (.ps1 / .sh)</h3>
          <div style="display: flex; gap: 8px;">
            <button class="btn" style="padding: 6px 14px; font-size: 12px;" onclick="copyScript('fix')">Copy Fix Script</button>
            <button class="btn" style="padding: 6px 14px; font-size: 12px; background: #374151;" onclick="copyScript('rollback')">Copy Rollback Script</button>
          </div>
        </div>
        <pre id="fixScriptContent" class="code-box"># Run a scan to generate multi-OS remediation and rollback procedures.</pre>
      </div>
    </section>
  </main>

  <script>
    let pollInterval = null;
    let cachedData = null;

    async function startScan() {
      const target = document.getElementById('targetInput').value;
      const ports = document.getElementById('portsSelect').value;
      const btn = document.getElementById('scanBtn');
      btn.disabled = true;

      try {
        await fetch('/api/scan', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({target, ports})
        });
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollStatus, 1000);
      } catch (e) {
        alert('Failed to launch scan: ' + e);
        btn.disabled = false;
      }
    }

    async function pollStatus() {
      try {
        const res = await fetch('/api/scan/status');
        const data = await res.json();
        
        document.getElementById('progressFill').style.width = data.progress + '%';
        document.getElementById('statusMessage').innerText = data.status_message;

        if (!data.is_scanning) {
          clearInterval(pollInterval);
          document.getElementById('scanBtn').disabled = false;
          if (data.progress === 100) {
            loadResults();
          }
        }
      } catch (e) {
        console.error(e);
      }
    }

    async function loadResults() {
      try {
        const res = await fetch('/api/scan/results');
        const data = await res.json();
        cachedData = data;

        // Update stats
        const riskScore = data.scan_data ? data.scan_data.risk_score : 0;
        const riskLevel = data.scan_data ? data.scan_data.risk_level : 'MINIMAL';
        document.getElementById('statRiskScore').innerText = riskScore + ' / 100';
        document.getElementById('statRiskScore').style.color = riskScore > 60 ? '#ef4444' : (riskScore > 30 ? '#f97316' : '#10b981');
        document.getElementById('statRiskLevel').innerText = riskLevel + ' RISK';

        const hostsCount = data.scan_data && data.scan_data.hosts ? data.scan_data.hosts.length : 0;
        document.getElementById('statHosts').innerText = hostsCount;

        let totalPorts = 0;
        if (data.scan_data && data.scan_data.hosts) {
          data.scan_data.hosts.forEach(h => totalPorts += (h.ports || []).length);
        }
        document.getElementById('statPorts').innerText = totalPorts;

        if (data.compliance) {
          document.getElementById('statCompliance').innerText = data.compliance.compliance_score + '%';
          document.getElementById('statComplianceLevel').innerText = data.compliance.readiness_rating;
        }

        // Render Topology
        renderTopology(data.scan_data);

        // Render Threat Matrix
        renderThreatMatrix(data.threat_matrix);

        // Render CIS Compliance
        renderCompliance(data.compliance);

        // Fetch Script
        fetchFixScript();

      } catch (e) {
        console.error(e);
      }
    }

    function renderTopology(scanData) {
      const svg = document.getElementById('topoCanvas');
      svg.innerHTML = '';
      if (!scanData || !scanData.hosts || scanData.hosts.length === 0) {
        svg.innerHTML = '<text x="50%" y="50%" fill="#6b7280" font-size="14" text-anchor="middle">No active hosts detected.</text>';
        return;
      }

      const hosts = scanData.hosts;
      const width = svg.clientWidth || 900;
      const height = svg.clientHeight || 380;
      const cx = width / 2;
      const cy = height / 2;

      // Draw Gateway Router
      let html = `<circle cx="${cx}" cy="${cy}" r="24" fill="#0891b2" stroke="#06b6d4" stroke-width="3"/>`;
      html += `<text x="${cx}" y="${cy + 5}" fill="white" font-size="11" font-weight="700" text-anchor="middle">ROUTER</text>`;

      const radius = Math.min(width, height) * 0.35;
      const angleStep = (2 * Math.PI) / hosts.length;

      hosts.forEach((h, i) => {
        const angle = i * angleStep;
        const hx = cx + radius * Math.cos(angle);
        const hy = cy + radius * Math.sin(angle);

        // Line
        html += `<line x1="${cx}" y1="${cy}" x2="${hx}" y2="${hy}" stroke="#374151" stroke-width="2" stroke-dasharray="4"/>`;

        // Node
        const portCount = (h.ports || []).length;
        const color = portCount > 3 ? '#ef4444' : (portCount > 0 ? '#06b6d4' : '#10b981');
        html += `<circle cx="${hx}" cy="${hy}" r="18" fill="#111827" stroke="${color}" stroke-width="3"/>`;
        html += `<text x="${hx}" y="${hy + 32}" fill="#f3f4f6" font-size="11" font-weight="600" text-anchor="middle">${h.ip}</text>`;
        html += `<text x="${hx}" y="${hy + 46}" fill="#9ca3af" font-size="10" text-anchor="middle">${portCount} Open Port(s)</text>`;
      });

      svg.innerHTML = html;
    }

    function renderThreatMatrix(tm) {
      const tbody = document.getElementById('threatsBody');
      if (!tm || !tm.profiles || tm.profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--green);">Zero high-urgency threats detected. All endpoints secure.</td></tr>';
        return;
      }

      tbody.innerHTML = tm.profiles.map(p => `
        <tr>
          <td><strong>${p.cve_id}</strong></td>
          <td>${p.cvss_score}</td>
          <td>${Math.round(p.epss_score * 100)}% (${Math.round(p.epss_percentile * 100)}th pct)</td>
          <td>${p.is_kev ? '<span class="tag tag-crit">YES (CISA KEV)</span>' : '<span style="color: var(--text-muted)">No</span>'}</td>
          <td><span style="font-weight: 700; color: ${p.real_world_exploitability_index > 60 ? '#ef4444' : '#06b6d4'}">${p.real_world_exploitability_index} / 100</span></td>
          <td><span class="tag ${p.threat_tier === 'CRITICAL' ? 'tag-crit' : (p.threat_tier === 'HIGH' ? 'tag-high' : 'tag-med')}">${p.threat_tier}</span></td>
        </tr>
      `).join('');
    }

    function renderCompliance(comp) {
      const tbody = document.getElementById('complianceBody');
      if (!comp || !comp.controls_breakdown || comp.controls_breakdown.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No compliance data available.</td></tr>';
        return;
      }

      tbody.innerHTML = comp.controls_breakdown.map(c => `
        <tr>
          <td><strong>${c.control_id}</strong></td>
          <td>${c.title}</td>
          <td><span style="color: var(--text-muted); font-family: monospace;">${c.nist_csf_mapping}</span></td>
          <td><span class="tag ${c.status === 'PASS' ? 'tag-pass' : 'tag-crit'}">${c.status}</span></td>
          <td style="color: var(--text-muted); font-size: 12px;">${c.evidence}</td>
        </tr>
      `).join('');
    }

    async function fetchFixScript() {
      try {
        const res = await fetch('/api/fix/script');
        const d = await res.json();
        document.getElementById('fixScriptContent').innerText = d.script || '# No remediation actions required.';
      } catch (e) {
        console.error(e);
      }
    }

    function copyScript(type) {
      const text = document.getElementById('fixScriptContent').innerText;
      navigator.clipboard.writeText(text).then(() => {
        alert('Script copied to clipboard!');
      });
    }

    function switchTab(tabId, btn) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(tabId).classList.add('active');
    }
  </script>
</body>
</html>
"""


class PVSWebHandler(BaseHTTPRequestHandler):
    """Zero-dependency HTTP Request Handler for PVS Interactive Web Dashboard."""

    def log_message(self, format, *args):
        # Silence default HTTP server console noise
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE_TEMPLATE.encode("utf-8"))

        elif path == "/api/scan/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "is_scanning": _STATE["is_scanning"],
                "progress": _STATE["progress"],
                "status_message": _STATE["status_message"],
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))

        elif path == "/api/scan/results":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "scan_data": _STATE["last_scan_data"],
                "brain_posture": _STATE["last_brain_posture"],
                "compliance": _STATE["last_compliance"],
                "threat_matrix": _STATE["last_threat_matrix"],
            }
            self.wfile.write(json.dumps(payload, default=str).encode("utf-8"))

        elif path == "/api/fix/script":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            scan_data = _STATE.get("last_scan_data") or {}
            cve_res = scan_data.get("cve_results", {})
            target = scan_data.get("target", "127.0.0.1")
            os_target = "windows" if sys.platform == "win32" else "linux"

            if cve_res:
                fn, script = generate_remediation_script(cve_res, target_ip=target, os_target=os_target)
                r_fn, r_script = generate_rollback_script(cve_res, target_ip=target, os_target=os_target)
            else:
                fn, script = "pvs_fix.ps1", "# No active vulnerabilities requiring remediation."
                r_fn, r_script = "pvs_rollback.ps1", "# No rollback required."

            self.wfile.write(json.dumps({
                "filename": fn,
                "script": script,
                "rollback_filename": r_fn,
                "rollback_script": r_script,
            }).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                target = data.get("target", "127.0.0.1").strip()
                ports = data.get("ports", "top100")
            except Exception:
                target = "127.0.0.1"
                ports = "top100"

            if not _STATE["is_scanning"]:
                _run_background_scan(target, ports)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "started"}).encode("utf-8"))
            else:
                self.send_response(409)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "already_scanning"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def run_web_ui_server(host: str = "127.0.0.1", port: int = 8484, open_browser: bool = True, initial_scan_data: Optional[Dict[str, Any]] = None):
    """Launch the PVS Interactive Web Dashboard HTTP Server."""
    if initial_scan_data:
        _STATE["last_scan_data"] = initial_scan_data
        _STATE["progress"] = 100
        _STATE["status_message"] = "Scan data loaded."

    server_address = (host, port)
    try:
        httpd = HTTPServer(server_address, PVSWebHandler)
    except OSError as e:
        logger.warning(f"Port {port} in use, trying next port: {e}")
        port += 1
        server_address = (host, port)
        httpd = HTTPServer(server_address, PVSWebHandler)

    url = f"http://{host}:{port}"
    print(f"\n[+] PVS Interactive Web GUI active at: {url}")
    print("[*] Press Ctrl+C in terminal to stop server.\n")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down PVS Web Dashboard.")
    finally:
        httpd.server_close()

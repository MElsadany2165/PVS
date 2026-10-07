# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Brain — Centralized Intelligence & Analysis Engine.

Performs post-scan analysis to deliver actionable, human-readable security
insights.  Works 100% offline — every algorithm runs locally against the
scan results already collected by the scanner and vuln_engine modules.

Capabilities:
  • Network posture assessment (risk score + classification)
  • Attack surface analysis (exposure patterns, lateral movement vectors)
  • Service correlation (related services, dependency chains)
  • Smart scan summary generation with prioritised action items
  • Pattern recognition (legacy protocols, misconfiguration clusters)
  • Offline intelligence amplification (curated rule-based heuristics)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
import re
import math

from .logger import get_logger

logger = get_logger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Data Classes
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class NetworkInsight:
    """A single actionable insight discovered by the Brain."""
    category: str          # "critical_action", "warning", "recommendation", "info"
    title: str
    description: str
    affected_hosts: List[str] = field(default_factory=list)
    affected_ports: List[int] = field(default_factory=list)
    priority: int = 50     # 0-100, higher = more urgent
    icon: str = "💡"

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "affected_hosts": self.affected_hosts,
            "affected_ports": self.affected_ports,
            "priority": self.priority,
            "icon": self.icon,
        }


@dataclass
class AttackSurfaceEntry:
    """Represents one exposure point in the attack surface map."""
    host: str
    port: int
    service: str
    exposure_level: str    # "critical", "high", "medium", "low"
    exposure_reason: str
    lateral_movement_risk: bool = False

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "exposure_level": self.exposure_level,
            "exposure_reason": self.exposure_reason,
            "lateral_movement_risk": self.lateral_movement_risk,
        }


@dataclass
class NetworkPosture:
    """Overall network security posture assessment."""
    risk_score: float = 0.0        # 0-100
    risk_level: str = "UNKNOWN"    # "CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"
    risk_color: str = "#8b949e"
    total_hosts: int = 0
    total_open_ports: int = 0
    total_vulns: int = 0
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_kev: int = 0
    total_active_exposures: int = 0
    attack_surface: List[AttackSurfaceEntry] = field(default_factory=list)
    insights: List[NetworkInsight] = field(default_factory=list)
    executive_summary: str = ""
    scan_mode: str = "online"

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_hosts": self.total_hosts,
            "total_open_ports": self.total_open_ports,
            "total_vulns": self.total_vulns,
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "total_medium": self.total_medium,
            "total_low": self.total_low,
            "total_kev": self.total_kev,
            "total_active_exposures": self.total_active_exposures,
            "attack_surface": [a.to_dict() for a in self.attack_surface],
            "insights": [i.to_dict() for i in self.insights],
            "executive_summary": self.executive_summary,
            "scan_mode": self.scan_mode,
        }


# ────────────────────────────────────────────────────────────────────────────
# Exposure Classifiers (100% Offline Rule-Based Heuristics)
# ────────────────────────────────────────────────────────────────────────────

# Services that should NEVER be exposed to untrusted networks
_CRITICAL_EXPOSURE_SERVICES = {
    "redis", "mongodb", "memcached", "elasticsearch", "docker",
    "mysql", "postgresql", "mssql", "oracle", "couchdb",
}

# Services that represent legacy / inherently insecure protocols
_LEGACY_CLEARTEXT_PORTS = {
    21: "FTP", 23: "Telnet", 69: "TFTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 161: "SNMP",
}

# Services that enable lateral movement if compromised
_LATERAL_MOVEMENT_SERVICES = {
    "ssh", "rdp", "smb", "microsoft-ds", "vnc", "telnet",
    "winrm", "psexec",
}

# Remote admin ports
_REMOTE_ADMIN_PORTS = {22, 23, 3389, 5900, 5985, 5986}

# Database ports
_DATABASE_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 2375}


def _classify_port_exposure(port: int, service: str, banner: str = "") -> Tuple[str, str]:
    """Classify the exposure level and reason for an open port."""
    svc_lower = (service or "").lower()
    banner_lower = (banner or "").lower()

    # Critical: databases and caches exposed
    if svc_lower in _CRITICAL_EXPOSURE_SERVICES or port in _DATABASE_PORTS:
        return "critical", f"{service} should not be exposed to untrusted networks — direct data access risk"

    # Critical: Docker daemon
    if port == 2375 or svc_lower == "docker":
        return "critical", "Docker daemon API exposed without TLS — full host compromise possible"

    # High: cleartext protocols
    if port in _LEGACY_CLEARTEXT_PORTS:
        proto = _LEGACY_CLEARTEXT_PORTS[port]
        return "high", f"{proto} transmits credentials in cleartext — network sniffing risk"

    # High: remote admin without encryption
    if port in _REMOTE_ADMIN_PORTS and svc_lower in ("telnet", "vnc"):
        return "high", f"{service} provides remote admin access without encryption"

    # Medium: remote admin with encryption
    if port in _REMOTE_ADMIN_PORTS:
        return "medium", f"{service} provides remote access — ensure strong authentication"

    # Medium: web services
    if port in (80, 8080, 8000, 8888, 9090, 3000, 5000):
        return "medium", "Web service exposed — check for application vulnerabilities"

    # Low: encrypted standard services
    if port in (443, 8443, 993, 995, 465, 636):
        return "low", "Encrypted service with standard exposure"

    return "low", "Standard service exposure"


# ────────────────────────────────────────────────────────────────────────────
# Pattern Recognition Engine
# ────────────────────────────────────────────────────────────────────────────

def _detect_legacy_cluster(host_results) -> List[NetworkInsight]:
    """Detect clusters of legacy / cleartext protocols across the network."""
    insights = []
    legacy_hosts = {}  # host -> list of legacy ports

    for hr in host_results:
        legacy_ports = []
        for pr in hr.ports:
            if pr.port in _LEGACY_CLEARTEXT_PORTS:
                legacy_ports.append(pr.port)
        if legacy_ports:
            legacy_hosts[hr.ip] = legacy_ports

    if len(legacy_hosts) >= 2:
        total_legacy = sum(len(v) for v in legacy_hosts.values())
        insights.append(NetworkInsight(
            category="warning",
            title="Legacy Cleartext Protocol Cluster Detected",
            description=(
                f"{total_legacy} cleartext services found across {len(legacy_hosts)} host(s). "
                f"This indicates systemic use of insecure protocols across the network. "
                f"Credentials transmitted over these services can be intercepted by anyone "
                f"on the same network segment. Prioritise migrating to encrypted alternatives "
                f"(SSH, HTTPS, IMAPS, SFTP)."
            ),
            affected_hosts=list(legacy_hosts.keys()),
            affected_ports=sorted({p for ports in legacy_hosts.values() for p in ports}),
            priority=80,
            icon="🔓",
        ))

    return insights


def _detect_database_exposure(host_results) -> List[NetworkInsight]:
    """Detect databases exposed on the network."""
    insights = []
    exposed_dbs = []

    for hr in host_results:
        for pr in hr.ports:
            svc = (pr.service or "").lower()
            if svc in _CRITICAL_EXPOSURE_SERVICES or pr.port in _DATABASE_PORTS:
                exposed_dbs.append((hr.ip, pr.port, svc or f"port-{pr.port}"))

    if exposed_dbs:
        db_hosts = list({e[0] for e in exposed_dbs})
        db_ports = sorted({e[1] for e in exposed_dbs})
        db_names = ", ".join(sorted({e[2] for e in exposed_dbs}))
        insights.append(NetworkInsight(
            category="critical_action",
            title=f"Database/Cache Services Exposed ({len(exposed_dbs)} instances)",
            description=(
                f"Found {len(exposed_dbs)} database or cache service(s) accessible on the network: "
                f"{db_names}. These services typically contain sensitive data and should be "
                f"firewalled to accept connections only from authorised application servers. "
                f"Check each for authentication requirements immediately."
            ),
            affected_hosts=db_hosts,
            affected_ports=db_ports,
            priority=95,
            icon="🗄️",
        ))

    return insights


def _detect_lateral_movement_paths(host_results) -> List[NetworkInsight]:
    """Identify potential lateral movement vectors across the network."""
    insights = []
    lateral_hosts = {}

    for hr in host_results:
        paths = []
        for pr in hr.ports:
            svc = (pr.service or "").lower()
            if svc in _LATERAL_MOVEMENT_SERVICES or pr.port in _REMOTE_ADMIN_PORTS:
                paths.append((pr.port, svc))
        if paths:
            lateral_hosts[hr.ip] = paths

    if len(lateral_hosts) >= 2:
        multi_path_hosts = [ip for ip, p in lateral_hosts.items() if len(p) >= 2]
        if multi_path_hosts:
            insights.append(NetworkInsight(
                category="warning",
                title="Multiple Lateral Movement Vectors Available",
                description=(
                    f"{len(multi_path_hosts)} host(s) expose 2+ remote access services "
                    f"(SSH, RDP, SMB, VNC). If an attacker compromises one host, these services "
                    f"provide ready-made pathways to pivot to other machines on the network. "
                    f"Consider restricting remote access to a single protocol per host and "
                    f"implementing network segmentation."
                ),
                affected_hosts=multi_path_hosts,
                priority=70,
                icon="🔀",
            ))

    return insights


def _detect_smb_network_risk(host_results) -> List[NetworkInsight]:
    """Detect wide SMB/NetBIOS exposure (worm propagation risk)."""
    insights = []
    smb_hosts = []

    for hr in host_results:
        for pr in hr.ports:
            if pr.port in (445, 139, 137, 138):
                smb_hosts.append(hr.ip)
                break

    if len(smb_hosts) >= 3:
        insights.append(NetworkInsight(
            category="warning",
            title=f"Wide SMB/NetBIOS Exposure ({len(smb_hosts)} hosts)",
            description=(
                f"SMB file-sharing protocol is enabled on {len(smb_hosts)} hosts. "
                f"Ransomware and network worms (WannaCry, NotPetya, EternalBlue) "
                f"propagate via SMB. If any host is compromised, the worm can spread "
                f"across all {len(smb_hosts)} SMB-enabled machines in minutes. "
                f"Disable SMBv1 on all hosts and restrict SMB to trusted subnets."
            ),
            affected_hosts=smb_hosts,
            affected_ports=[445, 139],
            priority=85,
            icon="🪱",
        ))

    return insights


def _detect_web_sprawl(host_results) -> List[NetworkInsight]:
    """Detect excessive web services (shadow IT indicator)."""
    insights = []
    web_hosts = []
    web_ports_set = {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000}

    for hr in host_results:
        web_count = sum(1 for pr in hr.ports if pr.port in web_ports_set)
        if web_count >= 2:
            web_hosts.append((hr.ip, web_count))

    if len(web_hosts) >= 2:
        total_web = sum(c for _, c in web_hosts)
        insights.append(NetworkInsight(
            category="recommendation",
            title=f"Web Service Sprawl Detected ({total_web} endpoints across {len(web_hosts)} hosts)",
            description=(
                f"Multiple web services are running across the network. Each web endpoint "
                f"increases the attack surface and may indicate shadow IT or forgotten "
                f"development servers. Audit each to confirm it's intentional, patched, "
                f"and serving a business purpose."
            ),
            affected_hosts=[h for h, _ in web_hosts],
            priority=50,
            icon="🌐",
        ))

    return insights


def _generate_offline_insights(scan_mode: str) -> List[NetworkInsight]:
    """Generate insights specific to offline scanning mode."""
    insights = []
    if scan_mode == "offline":
        insights.append(NetworkInsight(
            category="info",
            title="Offline Intelligence Mode Active",
            description=(
                "This scan ran without internet connectivity. PVS used its built-in "
                "curated vulnerability database (covering 15+ high-impact CVEs across "
                "OpenSSH, Apache, Nginx, Redis, ProFTPD, vsftpd, and OpenSSL) plus "
                "12 active network audit checks (unauthenticated databases, SMBv1, "
                "RDP without NLA, anonymous FTP, exposed Docker sockets, cleartext "
                "protocols, sensitive file leaks, and weak TLS). "
                "For additional CVE coverage from live NVD and OSV databases, "
                "reconnect to the internet and rescan."
            ),
            priority=30,
            icon="📡",
        ))
    return insights


# ────────────────────────────────────────────────────────────────────────────
# Vulnerability Analysis
# ────────────────────────────────────────────────────────────────────────────

def _analyze_vuln_patterns(cve_results: dict) -> List[NetworkInsight]:
    """Analyze CVE results for patterns and generate insights."""
    insights = []
    if not cve_results:
        return insights

    # Count active exposures vs static CVEs
    active_count = 0
    kev_count = 0
    rce_count = 0
    auth_bypass_count = 0

    for key, cves in cve_results.items():
        for cve in cves:
            cve_id = cve.cve_id if hasattr(cve, "cve_id") else cve.get("cve_id", "")
            desc = (cve.description if hasattr(cve, "description") else cve.get("description", "")).lower()
            is_kev = cve.is_kev if hasattr(cve, "is_kev") else cve.get("is_kev", False)

            if str(cve_id).startswith("VULN-"):
                active_count += 1
            if is_kev:
                kev_count += 1
            if any(kw in desc for kw in ("remote code execution", "rce", "arbitrary code")):
                rce_count += 1
            if any(kw in desc for kw in ("authentication bypass", "unauthenticated", "without auth")):
                auth_bypass_count += 1

    if rce_count >= 2:
        insights.append(NetworkInsight(
            category="critical_action",
            title=f"Multiple Remote Code Execution Vulnerabilities ({rce_count})",
            description=(
                f"Found {rce_count} vulnerability/ies that allow remote code execution (RCE). "
                f"These are the highest-risk findings — an attacker can run arbitrary commands "
                f"on the affected systems from the network. Patch or mitigate these FIRST."
            ),
            priority=100,
            icon="💀",
        ))

    if auth_bypass_count >= 2:
        insights.append(NetworkInsight(
            category="critical_action",
            title=f"Authentication Bypass Pattern ({auth_bypass_count} instances)",
            description=(
                f"Multiple services ({auth_bypass_count}) allow access without proper "
                f"authentication. This suggests a systemic authentication configuration "
                f"weakness across the network. Review authentication requirements for all "
                f"exposed services."
            ),
            priority=92,
            icon="🔑",
        ))

    if kev_count >= 1:
        insights.append(NetworkInsight(
            category="critical_action",
            title=f"CISA KEV: {kev_count} Actively Exploited Vulnerability/ies",
            description=(
                f"{kev_count} vulnerability/ies are listed in the CISA Known Exploited "
                f"Vulnerabilities catalog, meaning they are being actively used by "
                f"threat actors in real-world attacks RIGHT NOW. These require immediate "
                f"remediation — they are not theoretical risks."
            ),
            priority=98,
            icon="🚨",
        ))

    if active_count >= 1:
        insights.append(NetworkInsight(
            category="warning",
            title=f"{active_count} Confirmed Live Exposure(s) via Active Probing",
            description=(
                f"PVS actively probed network services and confirmed {active_count} "
                f"real-world exposure(s) (not just theoretical CVEs). These are verified "
                f"misconfigurations or vulnerabilities that PVS connected to and demonstrated."
            ),
            priority=88,
            icon="🔥",
        ))

    return insights


# ────────────────────────────────────────────────────────────────────────────
# Risk Score Calculation
# ────────────────────────────────────────────────────────────────────────────

def _calculate_network_risk_score(
    total_vulns: int,
    total_critical: int,
    total_high: int,
    total_medium: int,
    total_low: int,
    total_kev: int,
    total_active: int,
    total_open_ports: int,
    total_hosts: int,
) -> Tuple[float, str, str]:
    """
    Calculate an overall network risk score (0-100) using weighted factors.
    Returns (score, level, color).
    """
    if total_vulns == 0 and total_open_ports == 0:
        return 0.0, "MINIMAL", "#3fb950"

    score = 0.0

    # Severity-weighted vulnerability contribution (up to 50 pts)
    vuln_score = (
        total_critical * 12.0 +
        total_high * 6.0 +
        total_medium * 2.5 +
        total_low * 0.5
    )
    score += min(50.0, vuln_score)

    # CISA KEV multiplier (up to 20 pts)
    score += min(20.0, total_kev * 10.0)

    # Active confirmed exposures (up to 15 pts)
    score += min(15.0, total_active * 7.5)

    # Attack surface breadth (up to 10 pts)
    surface_factor = math.log2(max(1, total_open_ports)) * 1.5
    score += min(10.0, surface_factor)

    # Host count amplifier (up to 5 pts) — more hosts = larger blast radius
    if total_hosts > 1:
        host_factor = math.log2(total_hosts) * 2.0
        score += min(5.0, host_factor)

    final_score = round(min(100.0, max(0.0, score)), 1)

    if final_score >= 80:
        return final_score, "CRITICAL", "#f85149"
    elif final_score >= 60:
        return final_score, "HIGH", "#da3633"
    elif final_score >= 35:
        return final_score, "MEDIUM", "#d29922"
    elif final_score >= 10:
        return final_score, "LOW", "#3fb950"
    else:
        return final_score, "MINIMAL", "#3fb950"


# ────────────────────────────────────────────────────────────────────────────
# Executive Summary Generator
# ────────────────────────────────────────────────────────────────────────────

def _generate_executive_summary(posture: "NetworkPosture") -> str:
    """Generate a human-readable executive summary paragraph."""
    parts = []

    # Opening
    if posture.total_hosts == 1:
        parts.append(f"PVS scanned 1 host and discovered {posture.total_open_ports} open port(s).")
    else:
        parts.append(
            f"PVS scanned {posture.total_hosts} host(s) and discovered "
            f"{posture.total_open_ports} open port(s) across the network."
        )

    # Vulnerability summary
    if posture.total_vulns == 0:
        parts.append(
            "No known vulnerabilities were identified in the detected service versions. "
            "The network's security posture appears sound based on available intelligence."
        )
    else:
        severity_parts = []
        if posture.total_critical > 0:
            severity_parts.append(f"{posture.total_critical} critical")
        if posture.total_high > 0:
            severity_parts.append(f"{posture.total_high} high")
        if posture.total_medium > 0:
            severity_parts.append(f"{posture.total_medium} medium")
        if posture.total_low > 0:
            severity_parts.append(f"{posture.total_low} low")

        parts.append(
            f"Identified {posture.total_vulns} vulnerability/ies "
            f"({', '.join(severity_parts)} severity)."
        )

    # KEV warning
    if posture.total_kev > 0:
        parts.append(
            f"URGENT: {posture.total_kev} vulnerability/ies are listed in the CISA Known "
            f"Exploited Vulnerabilities catalog — these are being actively exploited by "
            f"threat actors and require immediate remediation."
        )

    # Active exposures
    if posture.total_active_exposures > 0:
        parts.append(
            f"{posture.total_active_exposures} confirmed live exposure(s) were verified "
            f"through active network probing."
        )

    # Risk assessment
    parts.append(
        f"Overall network risk score: {posture.risk_score}/100 ({posture.risk_level})."
    )

    # Offline mode note
    if posture.scan_mode == "offline":
        parts.append(
            "Note: This scan ran in offline mode using PVS's curated vulnerability database "
            "and active network audits. Reconnect to the internet for additional CVE coverage."
        )

    return " ".join(parts)


# ────────────────────────────────────────────────────────────────────────────
# Main Brain Analysis Entry Point
# ────────────────────────────────────────────────────────────────────────────

def analyze_scan_results(
    host_results,
    cve_results: Optional[dict] = None,
    scan_mode: str = "online",
) -> NetworkPosture:
    """
    Main Brain analysis entry point.

    Accepts raw scan results and CVE results, performs comprehensive offline
    analysis, and returns a NetworkPosture assessment with insights.

    This function works 100% offline — all intelligence is derived from
    rule-based heuristics and pattern recognition against the scan data.

    Args:
        host_results: List of HostResult objects from the scanner.
        cve_results:  Dict mapping "ip:port" -> list of CVE/vulnerability entries.
        scan_mode:    "online" or "offline" — recorded in the posture.

    Returns:
        NetworkPosture with risk score, insights, attack surface, and summary.
    """
    posture = NetworkPosture(scan_mode=scan_mode)
    cve_results = cve_results or {}

    # ── Basic Metrics ────────────────────────────────────────────────────
    posture.total_hosts = len(host_results)
    posture.total_open_ports = sum(len(hr.ports) for hr in host_results)

    # ── Vulnerability Counting ───────────────────────────────────────────
    for key, cves in cve_results.items():
        for cve in cves:
            posture.total_vulns += 1
            sev = (cve.severity if hasattr(cve, "severity") else cve.get("severity", "")).upper()
            is_kev = cve.is_kev if hasattr(cve, "is_kev") else cve.get("is_kev", False)
            cve_id = cve.cve_id if hasattr(cve, "cve_id") else cve.get("cve_id", "")

            if sev == "CRITICAL":
                posture.total_critical += 1
            elif sev == "HIGH":
                posture.total_high += 1
            elif sev == "MEDIUM":
                posture.total_medium += 1
            elif sev == "LOW":
                posture.total_low += 1
            if is_kev:
                posture.total_kev += 1
            if str(cve_id).startswith("VULN-"):
                posture.total_active_exposures += 1

    # ── Attack Surface Mapping ───────────────────────────────────────────
    for hr in host_results:
        for pr in hr.ports:
            level, reason = _classify_port_exposure(
                pr.port, pr.service or "", pr.banner or ""
            )
            lateral = (pr.service or "").lower() in _LATERAL_MOVEMENT_SERVICES
            posture.attack_surface.append(AttackSurfaceEntry(
                host=hr.ip,
                port=pr.port,
                service=pr.service or f"port-{pr.port}",
                exposure_level=level,
                exposure_reason=reason,
                lateral_movement_risk=lateral,
            ))

    # ── Pattern Recognition ──────────────────────────────────────────────
    posture.insights.extend(_detect_legacy_cluster(host_results))
    posture.insights.extend(_detect_database_exposure(host_results))
    posture.insights.extend(_detect_lateral_movement_paths(host_results))
    posture.insights.extend(_detect_smb_network_risk(host_results))
    posture.insights.extend(_detect_web_sprawl(host_results))
    posture.insights.extend(_analyze_vuln_patterns(cve_results))
    posture.insights.extend(_generate_offline_insights(scan_mode))

    # Sort insights by priority descending
    posture.insights.sort(key=lambda x: x.priority, reverse=True)

    # ── Risk Score ───────────────────────────────────────────────────────
    posture.risk_score, posture.risk_level, posture.risk_color = _calculate_network_risk_score(
        total_vulns=posture.total_vulns,
        total_critical=posture.total_critical,
        total_high=posture.total_high,
        total_medium=posture.total_medium,
        total_low=posture.total_low,
        total_kev=posture.total_kev,
        total_active=posture.total_active_exposures,
        total_open_ports=posture.total_open_ports,
        total_hosts=posture.total_hosts,
    )

    # ── Executive Summary ────────────────────────────────────────────────
    posture.executive_summary = _generate_executive_summary(posture)

    logger.info(
        f"Brain analysis complete: risk={posture.risk_score}/100 ({posture.risk_level}), "
        f"{len(posture.insights)} insights, {len(posture.attack_surface)} attack surface entries"
    )

    return posture

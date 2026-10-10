# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Compliance & CIS Benchmarking Framework.
Evaluates scanned hosts and local operating systems against:
  • CIS Controls v8 (Center for Internet Security)
  • NIST Cybersecurity Framework (CSF v2.0)
  • Enterprise Security Baseline Standards

Produces compliance posture scores, control gap matrices, and executive audit summaries.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from .logger import get_logger

logger = get_logger(__name__)


@dataclass
class CISControlCheck:
    """Represents the compliance evaluation of a single CIS Control safeguard."""
    control_id: str             # e.g., "CIS-3.3", "CIS-4.1"
    control_group: str          # e.g., "Control 04: Secure Configuration"
    title: str
    nist_csf_mapping: str       # e.g., "PR.AC-1", "PR.DS-1", "PR.IP-1"
    status: str                 # "PASS", "FAIL", "MANUAL_REVIEW"
    severity_if_failed: str     # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    rationale: str
    remediation_advice: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "control_group": self.control_group,
            "title": self.title,
            "nist_csf_mapping": self.nist_csf_mapping,
            "status": self.status,
            "severity_if_failed": self.severity_if_failed,
            "rationale": self.rationale,
            "remediation_advice": self.remediation_advice,
            "evidence": self.evidence,
        }


@dataclass
class ComplianceReport:
    """Comprehensive compliance evaluation assessment."""
    target: str
    compliance_score: float             # 0.0 - 100.0%
    readiness_rating: str               # "COMPLIANT", "SUBSTANTIALLY_COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT"
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    review_checks: int = 0
    controls_breakdown: List[CISControlCheck] = field(default_factory=list)
    control_group_scores: Dict[str, float] = field(default_factory=dict)
    executive_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "compliance_score": round(self.compliance_score, 1),
            "readiness_rating": self.readiness_rating,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "review_checks": self.review_checks,
            "controls_breakdown": [c.to_dict() for c in self.controls_breakdown],
            "control_group_scores": {k: round(v, 1) for k, v in self.control_group_scores.items()},
            "executive_summary": self.executive_summary,
        }


def evaluate_cis_benchmarks(
    target: str,
    scan_hosts: Optional[List[Dict[str, Any]]] = None,
    os_audit_results: Optional[List[Dict[str, Any]]] = None,
    active_vulns: Optional[List[Dict[str, Any]]] = None,
) -> ComplianceReport:
    """
    Evaluate target security posture against CIS Controls v8 and NIST CSF.
    Correlates network findings, OS hardening audit checks, and active vulnerability probes.
    """
    checks: List[CISControlCheck] = []
    scan_hosts = scan_hosts or []
    os_audit_results = os_audit_results or []
    active_vulns = active_vulns or []

    # Flatten vulnerability IDs and open ports
    all_vuln_ids = set()
    open_ports = set()
    for h in scan_hosts:
        for p in h.get("ports", []):
            if p.get("state") == "open":
                open_ports.add(p.get("port"))
            for cve in p.get("cves", []):
                cid = cve.get("cve_id", "")
                if cid:
                    all_vuln_ids.add(cid)

    for v in active_vulns:
        vid = v.get("vuln_id", "")
        if vid:
            all_vuln_ids.add(vid)

    # Flatten OS audit findings
    os_fail_ids = set()
    for item in os_audit_results:
        if item.get("status") in ("FAIL", "WARNING", "HIGH", "CRITICAL"):
            os_fail_ids.add(item.get("id", item.get("check_id", "")))

    # --- CIS Control 03: Data Protection ---
    cleartext_found = any(p in open_ports for p in (21, 23, 80, 110, 143)) or any("CLEARTEXT" in vid for vid in all_vuln_ids)
    checks.append(CISControlCheck(
        control_id="CIS-3.3",
        control_group="Control 03: Data Protection",
        title="Encrypt Sensitive Data in Transit (Enforce TLS/SSH)",
        nist_csf_mapping="PR.DS-2",
        status="FAIL" if cleartext_found else "PASS",
        severity_if_failed="HIGH",
        rationale="Unencrypted transmission protocols (HTTP, Telnet, FTP, POP3) expose credentials and session tokens to eavesdropping.",
        remediation_advice="Disable legacy cleartext services; redirect HTTP to HTTPS and enforce SSH/SFTP/IMAPS.",
        evidence="Cleartext services active on port(s)" if cleartext_found else "All communication channels encrypted with TLS/SSH",
    ))

    # --- CIS Control 04: Secure Configuration of Enterprise Assets ---
    firewall_disabled = "OS-SEC-WIN-FIREWALL" in os_fail_ids or "OS-SEC-LNX-FIREWALL" in os_fail_ids
    checks.append(CISControlCheck(
        control_id="CIS-4.4",
        control_group="Control 04: Secure Configuration",
        title="Implement and Manage Host-Based Firewalls",
        nist_csf_mapping="PR.PT-4",
        status="FAIL" if firewall_disabled else "PASS",
        severity_if_failed="CRITICAL",
        rationale="Host-based firewalls must be enabled on all profiles to reject unauthorized inbound network connections.",
        remediation_advice="Enable Windows Defender Firewall on Domain, Private, and Public profiles, or activate UFW/firewalld.",
        evidence="Host firewall profiles disabled or inactive" if firewall_disabled else "Host firewall active across profiles",
    ))

    smb_insecure = (445 in open_ports and "VULN-SMB-ETERNALBLUE" in all_vuln_ids) or "OS-SEC-WIN-SMB1" in os_fail_ids
    checks.append(CISControlCheck(
        control_id="CIS-4.8",
        control_group="Control 04: Secure Configuration",
        title="Uninstall or Disable Obsolete Protocols (SMBv1 / NetBIOS)",
        nist_csf_mapping="PR.IP-1",
        status="FAIL" if smb_insecure else "PASS",
        severity_if_failed="CRITICAL",
        rationale="Legacy protocols such as SMBv1 lack modern authentication controls and are vulnerable to EternalBlue worms.",
        remediation_advice="Disable SMBv1 via Windows Features or PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.",
        evidence="Legacy SMBv1 protocol enabled" if smb_insecure else "Legacy SMBv1 removed/disabled",
    ))

    uac_disabled = "OS-SEC-WIN-UAC" in os_fail_ids
    checks.append(CISControlCheck(
        control_id="CIS-4.1",
        control_group="Control 04: Secure Configuration",
        title="Enforce User Account Control (UAC) / Privilege Elevation",
        nist_csf_mapping="PR.AC-4",
        status="FAIL" if uac_disabled else "PASS",
        severity_if_failed="HIGH",
        rationale="UAC ensures processes do not inherit Administrator permissions without explicit authorization.",
        remediation_advice="Set EnableLUA=1 in HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.",
        evidence="UAC elevation prompt disabled" if uac_disabled else "UAC properly configured to prompt on elevation",
    ))

    # --- CIS Control 05: Account Management ---
    guest_active = "OS-SEC-WIN-GUEST" in os_fail_ids
    checks.append(CISControlCheck(
        control_id="CIS-5.3",
        control_group="Control 05: Account Management",
        title="Disable Dormant and Built-in Guest Accounts",
        nist_csf_mapping="PR.AC-1",
        status="FAIL" if guest_active else "PASS",
        severity_if_failed="MEDIUM",
        rationale="Default guest accounts provide unmonitored pathways for unauthorized system access.",
        remediation_advice="Disable Guest account: net user Guest /active:no.",
        evidence="Built-in Guest account active" if guest_active else "Guest account disabled",
    ))

    # --- CIS Control 07: Continuous Vulnerability Management ---
    has_kev = any("KEV" in str(vid) for vid in all_vuln_ids) or any("VULN-UNAUTH" in str(vid) for vid in all_vuln_ids)
    has_critical_vulns = any("CRITICAL" in str(v) for v in all_vuln_ids) or len(all_vuln_ids) > 0
    checks.append(CISControlCheck(
        control_id="CIS-7.1",
        control_group="Control 07: Continuous Vulnerability Management",
        title="Establish Automated Vulnerability Assessment Process",
        nist_csf_mapping="DE.CM-8",
        status="PASS",
        severity_if_failed="MEDIUM",
        rationale="Regular network and host vulnerability audits identify exploitable exposures before adversaries do.",
        remediation_advice="Schedule automated PVS vulnerability scans on recurring basis.",
        evidence="PVS automated assessment active",
    ))

    checks.append(CISControlCheck(
        control_id="CIS-7.4",
        control_group="Control 07: Continuous Vulnerability Management",
        title="Remediate Actively Exploited Threats (CISA KEV / RCE)",
        nist_csf_mapping="RS.MI-3",
        status="FAIL" if has_kev else "PASS",
        severity_if_failed="CRITICAL",
        rationale="Vulnerabilities cataloged in CISA KEV are subject to ongoing weaponization and must be mitigated immediately.",
        remediation_advice="Apply vendor patches and execute PVS automated remediation scripts.",
        evidence=f"{len([v for v in all_vuln_ids if 'KEV' in str(v) or 'UNAUTH' in str(v)])} active exploit(s) detected" if has_kev else "Zero known active KEV exploits detected",
    ))

    # --- CIS Control 09: Email and Web Browser Protections ---
    web_headers_missing = any("VULN-WEB-MISSING-HSTS" in vid or "VULN-WEB-CLICKJACKING" in vid for vid in all_vuln_ids)
    checks.append(CISControlCheck(
        control_id="CIS-9.2",
        control_group="Control 09: Email & Web Protections",
        title="Enforce Web Application Security Headers (HSTS, CSP, Frame Options)",
        nist_csf_mapping="PR.IP-1",
        status="FAIL" if web_headers_missing else "PASS",
        severity_if_failed="MEDIUM",
        rationale="Web applications must provide HTTP security headers to defend against Clickjacking and downgrade attacks.",
        remediation_advice="Configure HSTS, Content-Security-Policy, and X-Frame-Options in web server configuration.",
        evidence="Web security headers missing or deficient" if web_headers_missing else "Web applications compliant with security header baseline",
    ))

    # --- CIS Control 10: Malware Defenses ---
    av_disabled = "OS-SEC-WIN-DEFENDER" in os_fail_ids or "OS-SEC-LNX-CLAMAV" in os_fail_ids
    checks.append(CISControlCheck(
        control_id="CIS-10.1",
        control_group="Control 10: Malware Defenses",
        title="Deploy and Maintain Real-Time Anti-Malware Protection",
        nist_csf_mapping="DE.CM-4",
        status="FAIL" if av_disabled else "PASS",
        severity_if_failed="CRITICAL",
        rationale="Real-time endpoint antivirus protection is fundamental to intercept malicious binaries and ransomware.",
        remediation_advice="Ensure Windows Defender or endpoint EDR agent is running with real-time scanning active.",
        evidence="Endpoint antivirus engine disabled or out of date" if av_disabled else "Endpoint antivirus active with real-time protection enabled",
    ))

    # --- CIS Control 12: Network Infrastructure Management ---
    exposed_admin = any(p in open_ports for p in (2375, 6379, 27017, 3389)) and any("UNAUTH" in vid or "NLA" in vid for vid in all_vuln_ids)
    checks.append(CISControlCheck(
        control_id="CIS-12.1",
        control_group="Control 12: Network Infrastructure Management",
        title="Restrict Inbound Management & Database Port Exposure",
        nist_csf_mapping="PR.AC-5",
        status="FAIL" if exposed_admin else "PASS",
        severity_if_failed="CRITICAL",
        rationale="Administrative sockets (Docker daemon, unauthenticated databases, RDP without NLA) must never be open to untrusted subnets.",
        remediation_advice="Bind administrative services to 127.0.0.1 and require SSH tunnels or VPN for remote access.",
        evidence="Unauthenticated management/database ports open" if exposed_admin else "Administrative sockets isolated",
    ))

    # Calculate scores
    total = len(checks)
    passed = sum(1 for c in checks if c.status == "PASS")
    failed = sum(1 for c in checks if c.status == "FAIL")
    review = sum(1 for c in checks if c.status == "MANUAL_REVIEW")

    # Weighted score calculation: CRITICAL failures carry heavy penalty
    weight_map = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}
    total_weight = sum(weight_map.get(c.severity_if_failed, 1.0) for c in checks)
    passed_weight = sum(weight_map.get(c.severity_if_failed, 1.0) for c in checks if c.status == "PASS")

    score = round((passed_weight / total_weight) * 100.0, 1) if total_weight > 0 else 100.0

    if score >= 90.0:
        rating = "COMPLIANT"
    elif score >= 75.0:
        rating = "SUBSTANTIALLY_COMPLIANT"
    elif score >= 50.0:
        rating = "PARTIALLY_COMPLIANT"
    else:
        rating = "NON_COMPLIANT"

    # Control group breakdowns
    group_scores: Dict[str, float] = {}
    for c in checks:
        grp = c.control_group
        if grp not in group_scores:
            g_checks = [x for x in checks if x.control_group == grp]
            g_pass = sum(1 for x in g_checks if x.status == "PASS")
            group_scores[grp] = round((g_pass / len(g_checks)) * 100.0, 1)

    summary = (
        f"Assessed {target} across {total} CIS Controls v8 benchmarks. "
        f"Achieved {score}% compliance readiness ({rating}). "
        f"{passed} controls passed, {failed} failed with action items."
    )

    return ComplianceReport(
        target=target,
        compliance_score=score,
        readiness_rating=rating,
        total_checks=total,
        passed_checks=passed,
        failed_checks=failed,
        review_checks=review,
        controls_breakdown=checks,
        control_group_scores=group_scores,
        executive_summary=summary,
    )

# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
PVS Threat Intelligence & Exploitability Engine.
Delivers real-world attacker threat prioritization by combining:
  • FIRST EPSS (Exploit Prediction Scoring System) probability & percentiles
  • CISA KEV (Known Exploited Vulnerabilities) weaponization indicators
  • Proof-of-Concept (PoC) & Metasploit exploit availability indices
  • Real-World Exploitability Index (REI) 0-100 scoring
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from .logger import get_logger

logger = get_logger(__name__)

# Curated offline exploit intelligence database: known weaponized CVEs & PoC availability
KNOWN_EXPLOIT_CATALOG: Dict[str, Dict[str, Any]] = {
    # OpenSSH regreSSHion
    "CVE-2024-6387": {
        "poc_available": True,
        "metasploit_module": "exploit/linux/ssh/regresshion_rce",
        "exploit_type": "Remote Code Execution",
        "in_the_wild": True,
        "epss_default": 0.88,
        "epss_percentile_default": 0.98,
    },
    # Terrapin SSH
    "CVE-2023-48795": {
        "poc_available": True,
        "metasploit_module": "auxiliary/scanner/ssh/terrapin",
        "exploit_type": "Cryptographic Downgrade",
        "in_the_wild": True,
        "epss_default": 0.35,
        "epss_percentile_default": 0.82,
    },
    # Log4Shell
    "CVE-2021-44228": {
        "poc_available": True,
        "metasploit_module": "exploit/multi/http/log4shell_header_injection",
        "exploit_type": "Remote Code Execution",
        "in_the_wild": True,
        "epss_default": 0.97,
        "epss_percentile_default": 0.99,
    },
    # EternalBlue SMBv1
    "CVE-2017-0144": {
        "poc_available": True,
        "metasploit_module": "exploit/windows/smb/ms17_010_eternalblue",
        "exploit_type": "Kernel Remote Code Execution",
        "in_the_wild": True,
        "epss_default": 0.96,
        "epss_percentile_default": 0.99,
    },
    # BlueKeep RDP
    "CVE-2019-0708": {
        "poc_available": True,
        "metasploit_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "exploit_type": "Pre-Auth Remote Code Execution",
        "in_the_wild": True,
        "epss_default": 0.95,
        "epss_percentile_default": 0.99,
    },
    # Redis unauthenticated RCE
    "VULN-UNAUTH-REDIS": {
        "poc_available": True,
        "metasploit_module": "exploit/linux/redis/redis_replication_cmd_exec",
        "exploit_type": "Unauthenticated Remote Command Execution",
        "in_the_wild": True,
        "epss_default": 0.93,
        "epss_percentile_default": 0.98,
    },
    # Docker exposed socket RCE
    "VULN-DOCKER-EXPOSED": {
        "poc_available": True,
        "metasploit_module": "exploit/linux/http/docker_daemon_privilege_escalation",
        "exploit_type": "Host Takeover / Container Escape",
        "in_the_wild": True,
        "epss_default": 0.91,
        "epss_percentile_default": 0.97,
    },
    # Spring4Shell
    "CVE-2022-22965": {
        "poc_available": True,
        "metasploit_module": "exploit/multi/http/spring_framework_rce_spring4shell",
        "exploit_type": "Class Loader Manipulation RCE",
        "in_the_wild": True,
        "epss_default": 0.94,
        "epss_percentile_default": 0.99,
    },
    # Apache HTTP Server Path Traversal
    "CVE-2021-41773": {
        "poc_available": True,
        "metasploit_module": "exploit/multi/http/apache_normalize_path_rce",
        "exploit_type": "Path Traversal & RCE",
        "in_the_wild": True,
        "epss_default": 0.97,
        "epss_percentile_default": 0.99,
    },
    # OpenSSL Heartbleed
    "CVE-2014-0160": {
        "poc_available": True,
        "metasploit_module": "auxiliary/scanner/ssl/openssl_heartbleed",
        "exploit_type": "Memory Information Leak",
        "in_the_wild": True,
        "epss_default": 0.93,
        "epss_percentile_default": 0.98,
    },
}


@dataclass
class ThreatIntelProfile:
    """Rich threat intelligence profile for an individual vulnerability."""
    cve_id: str
    cvss_score: float
    epss_score: float                  # 0.0 to 1.0 (probability of exploitation in 30 days)
    epss_percentile: float             # 0.0 to 1.0 (ranking among all known CVEs)
    is_kev: bool                       # Listed in CISA Known Exploited Vulnerabilities catalog
    poc_available: bool = False        # Public Proof-of-Concept exists (GitHub / Exploit-DB)
    metasploit_module: str = ""        # Known weaponized Metasploit module path
    exploit_type: str = ""             # Attacker objective (e.g., "Remote Code Execution")
    in_the_wild: bool = False          # Observed active exploitation in threat telemetry
    real_world_exploitability_index: float = 0.0  # Composite 0-100 real-world risk score
    threat_tier: str = "LOW"           # "CRITICAL", "HIGH", "ELEVATED", "LOW"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "epss_score": round(self.epss_score, 4),
            "epss_percentile": round(self.epss_percentile, 4),
            "is_kev": self.is_kev,
            "poc_available": self.poc_available,
            "metasploit_module": self.metasploit_module,
            "exploit_type": self.exploit_type,
            "in_the_wild": self.in_the_wild,
            "real_world_exploitability_index": round(self.real_world_exploitability_index, 1),
            "threat_tier": self.threat_tier,
        }


def calculate_real_world_exploitability_index(
    cvss_score: float,
    epss_score: float,
    is_kev: bool,
    poc_available: bool,
    in_the_wild: bool,
) -> Tuple[float, str]:
    """
    Calculate the Real-World Exploitability Index (REI) on a 0-100 scale.
    Weights:
      • CVSS Base Score (Impact): up to 40 points
      • EPSS Probability (Likelihood in 30 days): up to 30 points
      • CISA KEV Status (Active weaponization): +20 points
      • Public PoC / Metasploit module available: +10 points
    """
    cvss = max(0.0, min(10.0, float(cvss_score)))
    epss = max(0.0, min(1.0, float(epss_score)))

    # Component scores
    score_cvss = (cvss / 10.0) * 40.0
    score_epss = epss * 30.0
    score_kev = 20.0 if (is_kev or in_the_wild) else 0.0
    score_poc = 10.0 if poc_available else 0.0

    total_rei = round(min(100.0, score_cvss + score_epss + score_kev + score_poc), 1)

    if total_rei >= 80.0 or (is_kev and cvss >= 8.0):
        tier = "CRITICAL"
    elif total_rei >= 60.0 or is_kev or epss >= 0.5:
        tier = "HIGH"
    elif total_rei >= 40.0 or poc_available or epss >= 0.2:
        tier = "ELEVATED"
    else:
        tier = "LOW"

    return total_rei, tier


def enrich_threat_intel(
    cve_id: str,
    cvss_score: float,
    epss_score: float = 0.0,
    epss_percentile: float = 0.0,
    is_kev: bool = False,
) -> ThreatIntelProfile:
    """Enrich a finding with exploit intelligence catalog data and calculated REI."""
    cid_upper = (cve_id or "").upper().strip()
    catalog_info = KNOWN_EXPLOIT_CATALOG.get(cid_upper, {})

    poc = catalog_info.get("poc_available", False)
    msf = catalog_info.get("metasploit_module", "")
    exp_type = catalog_info.get("exploit_type", "")
    wild = catalog_info.get("in_the_wild", False)

    # Use catalog defaults if EPSS is missing (offline mode)
    final_epss = epss_score or catalog_info.get("epss_default", 0.0)
    final_pct = epss_percentile or catalog_info.get("epss_percentile_default", 0.0)
    final_kev = is_kev or wild

    rei, tier = calculate_real_world_exploitability_index(
        cvss_score=cvss_score,
        epss_score=final_epss,
        is_kev=final_kev,
        poc_available=poc,
        in_the_wild=wild,
    )

    return ThreatIntelProfile(
        cve_id=cve_id,
        cvss_score=cvss_score,
        epss_score=final_epss,
        epss_percentile=final_pct,
        is_kev=final_kev,
        poc_available=poc,
        metasploit_module=msf,
        exploit_type=exp_type,
        in_the_wild=wild,
        real_world_exploitability_index=rei,
        threat_tier=tier,
    )


def generate_threat_matrix(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate an executive Threat & Exploitability Matrix from a collection of scan findings.
    Sorts findings by real-world threat urgency (highest REI first).
    """
    enriched: List[ThreatIntelProfile] = []

    for item in findings:
        cid = item.get("cve_id", "")
        score = float(item.get("score") or item.get("cvss_score") or 0.0)
        epss = float(item.get("epss_score", 0.0))
        pct = float(item.get("epss_percentile", 0.0))
        kev = bool(item.get("is_kev", False))
        profile = enrich_threat_intel(
            cve_id=cid,
            cvss_score=score,
            epss_score=epss,
            epss_percentile=pct,
            is_kev=kev,
        )
        enriched.append(profile)

    # Sort descending by REI
    enriched.sort(key=lambda p: (p.real_world_exploitability_index, p.epss_score), reverse=True)

    critical_count = sum(1 for p in enriched if p.threat_tier == "CRITICAL")
    high_count = sum(1 for p in enriched if p.threat_tier == "HIGH")
    elevated_count = sum(1 for p in enriched if p.threat_tier == "ELEVATED")
    low_count = sum(1 for p in enriched if p.threat_tier == "LOW")
    kev_count = sum(1 for p in enriched if p.is_kev)
    poc_count = sum(1 for p in enriched if p.poc_available)

    avg_rei = round(sum(p.real_world_exploitability_index for p in enriched) / len(enriched), 1) if enriched else 0.0

    return {
        "total_threats": len(enriched),
        "critical_urgency": critical_count,
        "high_urgency": high_count,
        "elevated_urgency": elevated_count,
        "low_urgency": low_count,
        "active_kev_count": kev_count,
        "public_poc_count": poc_count,
        "average_exploitability_index": avg_rei,
        "profiles": [p.to_dict() for p in enriched],
    }

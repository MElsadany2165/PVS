# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for pvs/threat_intel.py.
"""

import pytest
from pvs.threat_intel import (
    calculate_real_world_exploitability_index,
    enrich_threat_intel,
    generate_threat_matrix,
    KNOWN_EXPLOIT_CATALOG,
)


def test_calculate_real_world_exploitability_index_critical():
    """Test REI calculation for high CVSS, high EPSS, and KEV."""
    rei, tier = calculate_real_world_exploitability_index(
        cvss_score=9.8,
        epss_score=0.92,
        is_kev=True,
        poc_available=True,
        in_the_wild=True,
    )
    assert rei >= 85.0
    assert tier == "CRITICAL"


def test_calculate_real_world_exploitability_index_low():
    """Test REI calculation for low CVSS, low EPSS, and no PoC."""
    rei, tier = calculate_real_world_exploitability_index(
        cvss_score=3.5,
        epss_score=0.01,
        is_kev=False,
        poc_available=False,
        in_the_wild=False,
    )
    assert rei < 30.0
    assert tier == "LOW"


def test_enrich_threat_intel_known_catalog():
    """Test catalog enrichment for known weaponized vulnerability (Log4Shell)."""
    profile = enrich_threat_intel(
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        is_kev=True,
    )
    assert profile.poc_available is True
    assert "log4shell" in profile.metasploit_module
    assert profile.in_the_wild is True
    assert profile.epss_score >= 0.9
    assert profile.threat_tier == "CRITICAL"


def test_generate_threat_matrix_aggregation():
    """Test threat matrix generation and priority sorting."""
    findings = [
        {"cve_id": "CVE-2021-44228", "score": 10.0, "is_kev": True, "epss_score": 0.97},
        {"cve_id": "CVE-2020-0001", "score": 4.0, "is_kev": False, "epss_score": 0.02},
    ]
    matrix = generate_threat_matrix(findings)
    assert matrix["total_threats"] == 2
    assert matrix["critical_urgency"] >= 1
    assert matrix["active_kev_count"] == 1
    # Check sorted descending by REI
    profiles = matrix["profiles"]
    assert profiles[0]["cve_id"] == "CVE-2021-44228"

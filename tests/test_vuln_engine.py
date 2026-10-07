# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

import pytest
import time
from pathlib import Path
from pvs.vuln_engine import VulnerabilityEngine, LocalVulnCache, EnhancedCVEEntry
from pvs.remediation import RemediationPlan, RemediationStep


def test_local_vuln_cache(tmp_path: Path):
    db_file = tmp_path / "test_cache.db"
    cache = LocalVulnCache(db_path=db_file)

    # Test KEV write & read
    kev_entries = [
        {
            "cveID": "CVE-2024-6387",
            "vendorProject": "OpenSSH",
            "product": "OpenSSH",
            "vulnerabilityName": "regreSSHion RCE",
            "dateAdded": "2024-07-01",
            "shortDescription": "Unauthenticated RCE in OpenSSH server.",
            "requiredAction": "Apply updates per vendor instructions.",
        }
    ]
    cache.save_kev_entries(kev_entries)

    kev_item = cache.get_kev("CVE-2024-6387")
    assert kev_item is not None
    assert kev_item["cve_id"] == "CVE-2024-6387"
    assert "Apply updates" in kev_item["required_action"]

    # Test CVE cache write & read
    cve_entry = EnhancedCVEEntry(
        cve_id="CVE-2024-6387",
        description="regreSSHion vulnerability",
        severity="CRITICAL",
        score=8.1,
        is_kev=True,
        kev_action="Apply updates per vendor instructions.",
    )
    cache.set_cves("ssh:8.9p1:5", [cve_entry])

    retrieved = cache.get_cves("ssh:8.9p1:5")
    assert retrieved is not None
    assert len(retrieved) == 1
    assert retrieved[0].cve_id == "CVE-2024-6387"
    assert retrieved[0].is_kev is True


@pytest.mark.asyncio
async def test_vuln_engine_cached_lookup(tmp_path: Path):
    db_file = tmp_path / "engine_cache.db"
    engine = VulnerabilityEngine(use_cache=True)
    engine.cache = LocalVulnCache(db_path=db_file)

    # Seed cache
    cve_entry = EnhancedCVEEntry(
        cve_id="CVE-2023-1234",
        description="Fake SSH CVE",
        severity="HIGH",
        score=7.5,
    )
    engine.cache.set_cves("ssh:8.9p1:5", [cve_entry])

    results = await engine.lookup_service_cves_async("ssh", "8.9p1", max_results=5, port=22)
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2023-1234"


def test_version_parsing():
    """Test semver parsing utility."""
    assert VulnerabilityEngine._parse_version("8.9p1") == (8, 91)  # p stripped, digits concatenated per segment
    assert VulnerabilityEngine._parse_version("2.4.52") == (2, 4, 52)
    assert VulnerabilityEngine._parse_version("7.0.0") == (7, 0, 0)
    assert VulnerabilityEngine._parse_version("1.18.0-ubuntu1") == (1, 18, 0)
    assert VulnerabilityEngine._parse_version("") is None
    assert VulnerabilityEngine._parse_version("10") == (10,)


def test_version_in_range_filtering():
    """Test version-based CVE filtering."""
    # Detected version 8.9 is below 'before 9.8' threshold -> affected
    assert VulnerabilityEngine._version_in_range("8.9", "Vulnerability in OpenSSH before 9.8 allows RCE") is True

    # Detected version 9.9 is above 'before 9.8' threshold -> NOT affected
    assert VulnerabilityEngine._version_in_range("9.9", "Vulnerability in OpenSSH before 9.8 allows RCE") is False

    # No version info -> assume affected (fail-open)
    assert VulnerabilityEngine._version_in_range("", "Some vulnerability") is True

    # No 'before' keyword -> can't filter, assume affected
    assert VulnerabilityEngine._version_in_range("2.4.52", "Apache httpd vulnerability") is True

    # 'prior to' phrasing
    assert VulnerabilityEngine._version_in_range("1.20", "Nginx prior to 1.25.3 is vulnerable") is True
    assert VulnerabilityEngine._version_in_range("1.26.0", "Nginx prior to 1.25.3 is vulnerable") is False


def test_epss_cache_operations(tmp_path: Path):
    """Test EPSS cache write and read."""
    db_file = tmp_path / "epss_test.db"
    cache = LocalVulnCache(db_path=db_file)

    cache.set_epss("CVE-2024-6387", 0.995, 0.999)
    res = cache.get_epss("CVE-2024-6387")
    assert res is not None
    assert round(res[0], 3) == 0.995
    assert round(res[1], 3) == 0.999

    # Non-existent CVE returns None
    assert cache.get_epss("CVE-9999-0000") is None


def test_calculate_threat_score():
    """Test composite PVS Threat Score calculation."""
    from pvs.vuln_engine import calculate_threat_score

    # Critical actively exploited RCE with high EPSS
    score, level = calculate_threat_score(
        cvss_score=8.1,
        is_kev=True,
        epss_score=0.95,
        categories={"rce"},
    )
    assert score >= 85.0
    assert level == "CRITICAL"

    # Low severity, no KEV, low EPSS
    score_low, level_low = calculate_threat_score(
        cvss_score=3.5,
        is_kev=False,
        epss_score=0.001,
        categories={"info_disclosure"},
    )
    assert score_low < 45.0
    assert level_low == "LOW"


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

    results = await engine.lookup_service_cves_async("ssh", "8.9p1", max_results=5)
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2023-1234"

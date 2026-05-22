# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

import pytest
from unittest.mock import MagicMock, patch
from pvs.nvd_client import NVDClient, build_cpe, CVEEntry

def test_build_cpe():
    # Test SSH banner CPE building
    cpe = build_cpe("ssh", "SSH-2.0-OpenSSH_8.9p1", "8.9p1")
    assert cpe == "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"

    # Test nginx HTTP banner CPE building
    cpe = build_cpe("http", "nginx/1.24.0", "1.24.0")
    assert cpe == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"

    # Test mapping fallback using service name
    cpe = build_cpe("redis", "", "7.2.3")
    assert cpe == "cpe:2.3:a:redis:redis:7.2.3:*:*:*:*:*:*:*"

    # Return None if version is missing
    assert build_cpe("ssh", "", "") is None


@pytest.mark.asyncio
async def test_nvd_client_cache_and_cpe_async():
    nvd = NVDClient()
    nvd._cache["cpe:cpe:2.3:a:redis:redis:7.2.3:*:*:*:*:*:*:*"] = [
        CVEEntry(cve_id="CVE-2023-1234", description="Fake Redis CVE", severity="HIGH", score=7.5)
    ]

    cves = await nvd.lookup_service_cves_async("redis", "7.2.3")
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-1234"

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

    # Test Apache HTTP banner with slash-prefixed version
    cpe = build_cpe("http", "Apache/2.4.52 (Ubuntu)", "Apache/2.4.52 (Ubuntu)")
    assert cpe == "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"

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


def test_nvd_client_retry_sync():
    nvd = NVDClient(rate_limit=0.01)
    
    import urllib.error
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = b'{"vulnerabilities": []}'
    
    call_count = 0
    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise urllib.error.HTTPError("http://nvd", 403, "Forbidden", {}, None)
        return mock_response

    with patch("urllib.request.urlopen", side_effect=side_effect):
        with patch("time.sleep") as mock_sleep:
            cves = nvd.search_by_keyword("redis")
            assert call_count == 2
            assert cves == []
            mock_sleep.assert_any_call(2.0)


@pytest.mark.asyncio
async def test_nvd_client_retry_async():
    nvd = NVDClient(rate_limit=0.01)

    import urllib.error
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = b'{"vulnerabilities": []}'
    
    call_count = 0
    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise urllib.error.HTTPError("http://nvd", 403, "Forbidden", {}, None)
        return mock_response

    with patch("urllib.request.urlopen", side_effect=side_effect):
        with patch("asyncio.sleep") as mock_sleep:
            cves = await nvd.search_by_keyword_async("redis")
            assert call_count == 2
            assert cves == []
            mock_sleep.assert_any_call(2.0)



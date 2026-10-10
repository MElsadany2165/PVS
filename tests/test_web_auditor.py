# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for pvs/web_auditor.py.
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from pvs.web_auditor import (
    audit_web_security_headers,
    audit_cors_misconfiguration,
    audit_sensitive_web_files,
    audit_insecure_http_methods,
    audit_web_service_full,
    _send_raw_http_request,
)


@pytest.mark.asyncio
async def test_audit_web_security_headers_missing_all():
    """Test detecting missing security headers on an insecure response."""
    mock_resp = (200, {"server": "nginx"}, "<html><body>Hello</body></html>")
    with patch("pvs.web_auditor._send_raw_http_request", new=AsyncMock(return_value=mock_resp)):
        vulns = await audit_web_security_headers("127.0.0.1", 443, use_ssl=True)
        vuln_ids = [v.vuln_id for v in vulns]
        assert "VULN-WEB-MISSING-HSTS" in vuln_ids
        assert "VULN-WEB-CLICKJACKING" in vuln_ids
        assert "VULN-WEB-MISSING-CSP" in vuln_ids
        assert "VULN-WEB-MIME-SNIFFING" in vuln_ids


@pytest.mark.asyncio
async def test_audit_web_security_headers_hardened():
    """Test that a fully hardened server triggers no header vulnerabilities."""
    mock_resp = (200, {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "set-cookie": "session=xyz; Secure; HttpOnly; SameSite=Strict",
    }, "<html>Safe</html>")
    with patch("pvs.web_auditor._send_raw_http_request", new=AsyncMock(return_value=mock_resp)):
        vulns = await audit_web_security_headers("127.0.0.1", 443, use_ssl=True)
        assert len(vulns) == 0


@pytest.mark.asyncio
async def test_audit_cors_reflected_credentials():
    """Test detecting arbitrary reflected CORS origin with credentials enabled."""
    mock_resp = (200, {
        "access-control-allow-origin": "https://evil-attacker.example.com",
        "access-control-allow-credentials": "true",
    }, "")
    with patch("pvs.web_auditor._send_raw_http_request", new=AsyncMock(return_value=mock_resp)):
        vulns = await audit_cors_misconfiguration("127.0.0.1", 80)
        assert len(vulns) == 1
        assert vulns[0].vuln_id == "VULN-WEB-CORS-REFLECTED-CREDENTIALS"
        assert vulns[0].severity == "CRITICAL"


@pytest.mark.asyncio
async def test_audit_sensitive_web_files_env_leak():
    """Test detecting an exposed .env file containing credentials."""
    async def mock_fetch(ip, port, method="GET", path="/", headers=None, timeout=2.5, use_ssl=False):
        if path == "/.env":
            return 200, {}, "DB_PASSWORD=supersecret\nAPP_KEY=base64:12345"
        return 404, {}, "Not found"

    with patch("pvs.web_auditor._send_raw_http_request", new=AsyncMock(side_effect=mock_fetch)):
        vulns = await audit_sensitive_web_files("127.0.0.1", 80)
        assert len(vulns) == 1
        assert vulns[0].vuln_id == "VULN-WEB-ENV-LEAK"
        assert vulns[0].severity == "CRITICAL"


@pytest.mark.asyncio
async def test_audit_insecure_http_methods_trace():
    """Test detecting enabled HTTP TRACE method."""
    mock_resp = (200, {"allow": "GET, POST, OPTIONS, TRACE"}, "")
    with patch("pvs.web_auditor._send_raw_http_request", new=AsyncMock(return_value=mock_resp)):
        vulns = await audit_insecure_http_methods("127.0.0.1", 80)
        vuln_ids = [v.vuln_id for v in vulns]
        assert "VULN-WEB-HTTP-TRACE-ENABLED" in vuln_ids

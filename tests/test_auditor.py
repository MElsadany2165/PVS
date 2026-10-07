# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for pvs/auditor.py -- active network vulnerability auditing engine.
Uses mock asyncio streams to avoid real network connections.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pvs.auditor import (
    ActiveVulnerability,
    audit_redis,
    audit_memcached,
    audit_docker,
    audit_ftp_anonymous,
    audit_cleartext_protocol,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_reader_writer(read_bytes: bytes):
    """Create mock (reader, writer) pair that returns the given bytes on read."""
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=read_bytes)
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return reader, writer


# ---------------------------------------------------------------------------
# audit_redis
# ---------------------------------------------------------------------------

class TestAuditRedis:
    @pytest.mark.asyncio
    async def test_redis_unauthenticated_detected(self):
        """If Redis responds to INFO without auth error, flag it as open."""
        redis_info = b"$2048\r\n# Server\r\nredis_version:7.0.5\r\n"
        with patch("pvs.auditor._safe_connect", return_value=make_reader_writer(redis_info)):
            findings = await audit_redis("127.0.0.1", 6379)
        assert len(findings) >= 1
        assert findings[0].severity in ("CRITICAL", "HIGH")
        assert "redis" in findings[0].service.lower()

    @pytest.mark.asyncio
    async def test_redis_with_auth_not_flagged(self):
        """If Redis returns NOAUTH, it requires auth - should not be flagged as open."""
        auth_error = b"-NOAUTH Authentication required.\r\n"
        with patch("pvs.auditor._safe_connect", return_value=make_reader_writer(auth_error)):
            findings = await audit_redis("127.0.0.1", 6379)
        # Should have 0 unauthenticated findings
        assert all("unauth" not in f.vuln_id.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_redis_connection_refused(self):
        """If connection fails, return empty findings."""
        with patch("pvs.auditor._safe_connect", return_value=(None, None)):
            findings = await audit_redis("127.0.0.1", 6379)
        assert findings == []


# ---------------------------------------------------------------------------
# audit_memcached
# ---------------------------------------------------------------------------

class TestAuditMemcached:
    @pytest.mark.asyncio
    async def test_memcached_open_detected(self):
        stats_resp = b"STAT pid 1234\r\nSTAT version 1.6.12\r\nEND\r\n"
        with patch("pvs.auditor._safe_connect", return_value=make_reader_writer(stats_resp)):
            findings = await audit_memcached("127.0.0.1", 11211)
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_memcached_connection_refused(self):
        with patch("pvs.auditor._safe_connect", return_value=(None, None)):
            findings = await audit_memcached("127.0.0.1", 11211)
        assert findings == []


# ---------------------------------------------------------------------------
# audit_docker
# ---------------------------------------------------------------------------

class TestAuditDocker:
    @pytest.mark.asyncio
    async def test_docker_daemon_open_detected(self):
        docker_resp = b'HTTP/1.1 200 OK\r\n\r\n{"ApiVersion":"1.41","Version":"20.10.21"}'
        with patch("pvs.auditor._safe_connect", return_value=make_reader_writer(docker_resp)):
            findings = await audit_docker("127.0.0.1", 2375)
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_docker_not_running(self):
        with patch("pvs.auditor._safe_connect", return_value=(None, None)):
            findings = await audit_docker("127.0.0.1", 2375)
        assert findings == []


# ---------------------------------------------------------------------------
# audit_ftp_anonymous
# ---------------------------------------------------------------------------

class TestAuditFtpAnonymous:
    @pytest.mark.asyncio
    async def test_anonymous_ftp_detected(self):
        # FTP 230 = login successful
        ftp_banner = b"220 vsftpd 3.0.5\r\n"
        ftp_230 = b"230 Login successful.\r\n"
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=[ftp_banner, ftp_230, ftp_230])
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch("pvs.auditor._safe_connect", return_value=(reader, writer)):
            findings = await audit_ftp_anonymous("127.0.0.1", 21)
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_anonymous_ftp_denied(self):
        ftp_banner = b"220 vsftpd 3.0.5\r\n"
        ftp_530 = b"530 Login incorrect.\r\n"
        reader = AsyncMock()
        reader.read = AsyncMock(side_effect=[ftp_banner, ftp_530])
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch("pvs.auditor._safe_connect", return_value=(reader, writer)):
            findings = await audit_ftp_anonymous("127.0.0.1", 21)
        assert findings == []


# ---------------------------------------------------------------------------
# audit_cleartext_protocol
# ---------------------------------------------------------------------------

class TestAuditCleartextProtocol:
    @pytest.mark.asyncio
    async def test_telnet_flagged(self):
        findings = await audit_cleartext_protocol("127.0.0.1", 23, "telnet")
        assert len(findings) >= 1
        assert "cleartext" in findings[0].vuln_id.lower() or "telnet" in findings[0].vuln_id.lower()

    @pytest.mark.asyncio
    async def test_ftp_flagged(self):
        findings = await audit_cleartext_protocol("127.0.0.1", 21, "ftp")
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_http_flagged(self):
        findings = await audit_cleartext_protocol("127.0.0.1", 80, "http")
        assert len(findings) >= 1
        assert findings[0].severity in ("MEDIUM", "HIGH")


# ---------------------------------------------------------------------------
# ActiveVulnerability.to_cve_dict
# ---------------------------------------------------------------------------

class TestActiveVulnerabilityToCveDict:
    def test_to_cve_dict_structure(self):
        av = ActiveVulnerability(
            vuln_id="VULN-REDIS-OPEN",
            title="Unauthenticated Redis",
            severity="CRITICAL",
            score=9.8,
            service="redis",
            port=6379,
            description="Redis accessible without authentication",
            remediation_key="redis_unauthenticated",
            evidence="INFO responded without auth",
            cve_id="CVE-2022-0543",
        )
        d = av.to_cve_dict()
        assert d["cve_id"] == "CVE-2022-0543"
        assert d["severity"] == "CRITICAL"
        assert d["score"] == 9.8
        assert "redis" in d["description"].lower() or "redis" in str(d["affected_products"]).lower()

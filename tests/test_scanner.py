# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Test suite for PVS scanner module.
"""
import pytest
from pvs.scanner import parse_ports, resolve_targets, parse_banner


class TestParsePorts:
    """Test port specification parsing."""

    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_port_range(self):
        result = parse_ports("20-25")
        assert result == [20, 21, 22, 23, 24, 25]

    def test_comma_separated(self):
        result = parse_ports("22,80,443")
        assert result == [22, 80, 443]

    def test_mixed(self):
        result = parse_ports("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_preset_top20(self):
        result = parse_ports("top20")
        assert len(result) == 20
        assert 80 in result
        assert 443 in result

    def test_preset_top100(self):
        result = parse_ports("top100")
        assert len(result) > 50

    def test_invalid_port(self):
        result = parse_ports("abc")
        assert result == []

    def test_out_of_range(self):
        result = parse_ports("0,70000")
        assert result == []


class TestResolveTargets:
    """Test target resolution."""

    def test_single_ip(self):
        result = resolve_targets("127.0.0.1")
        assert result == ["127.0.0.1"]

    def test_cidr_slash32(self):
        result = resolve_targets("192.168.1.1/32")
        assert result == ["192.168.1.1"]

    def test_cidr_slash30(self):
        result = resolve_targets("192.168.1.0/30")
        assert len(result) == 2  # .1 and .2 (network/broadcast excluded)

    def test_ip_range(self):
        result = resolve_targets("192.168.1.1-192.168.1.5")
        assert len(result) == 5

    def test_ip_range_shorthand(self):
        result = resolve_targets("192.168.1.1-5")
        assert len(result) == 5

    def test_localhost(self):
        result = resolve_targets("localhost")
        assert len(result) == 1


class TestParseBanner:
    """Test banner parsing."""

    def test_ssh_banner(self):
        service, version = parse_banner("SSH-2.0-OpenSSH_8.9p1", 22)
        assert service == "ssh"
        assert "OpenSSH" in version

    def test_http_server_header(self):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
        service, version = parse_banner(banner, 80)
        assert service == "http"
        assert "nginx" in version

    def test_ftp_banner(self):
        service, version = parse_banner("220 vsftpd 3.0.5", 21)
        assert service == "ftp"

    def test_empty_banner(self):
        service, version = parse_banner("", 80)
        assert service == "http"
        assert version == ""

# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for PVS Subnet Discovery & Asset Intelligence Engine.
"""

from unittest.mock import patch, AsyncMock
import pytest

from pvs.discover import (
    DiscoveredDevice,
    _classify_device,
    discover_subnet,
)


def test_discovered_device_serialization():
    dev = DiscoveredDevice(
        ip="192.168.1.1",
        hostname="router.home",
        is_up=True,
        latency_ms=1.45,
        device_role="Gateway / Router",
        os_guess="Embedded Linux / Network OS",
        open_ports=[53, 80, 443],
        services=["Port 53", "Port 80", "Port 443"],
    )
    d = dev.to_dict()
    assert d["ip"] == "192.168.1.1"
    assert d["hostname"] == "router.home"
    assert d["device_role"] == "Gateway / Router"
    assert d["latency_ms"] == 1.45
    assert len(d["open_ports"]) == 3


def test_classify_device_roles():
    # Gateway router
    role, os_guess = _classify_device("192.168.1.1", "", [53, 80])
    assert "Router" in role or "Gateway" in role

    # Windows PC
    role, os_guess = _classify_device("192.168.1.105", "desktop-win11", [445, 139])
    assert "Windows" in role

    # Linux server
    role, os_guess = _classify_device("192.168.1.200", "srv-ubuntu", [22])
    assert "Linux" in role

    # Printer
    role, os_guess = _classify_device("192.168.1.45", "hp-officejet", [9100, 631])
    assert "Printer" in role

    # IP Camera
    role, os_guess = _classify_device("192.168.1.80", "cam-hallway", [554])
    assert "Camera" in role


@pytest.mark.asyncio
async def test_discover_subnet_mock():
    # Mock filter_live_hosts and port probe
    with patch("pvs.discover.filter_live_hosts", new_callable=AsyncMock) as mock_filter:
        mock_filter.return_value = ["192.168.1.1", "192.168.1.50"]
        with patch("pvs.discover._probe_port", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = 80
            with patch("pvs.discover._resolve_hostname", new_callable=AsyncMock) as mock_host:
                mock_host.return_value = "gateway.local"

                devices = await discover_subnet("192.168.1.0/30", timeout=0.1, concurrency=10)
                assert len(devices) == 2
                assert devices[0].ip == "192.168.1.1"
                assert devices[0].hostname == "gateway.local"
                assert 80 in devices[0].open_ports

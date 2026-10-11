# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for PVS Continuous Monitor & Webhook Alert Engine.
"""

import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pvs.monitor import (
    PortSnapshot,
    TargetSnapshot,
    MonitorDiff,
    MonitorStorage,
    WebhookDispatcher,
    compute_diff,
)


def test_snapshot_serialization():
    p1 = PortSnapshot(port=80, state="open", service="http", banner="Apache/2.4", version="2.4.52")
    d = p1.to_dict()
    assert d["port"] == 80
    assert d["service"] == "http"

    p2 = PortSnapshot.from_dict(d)
    assert p2.port == 80
    assert p2.service == "http"
    assert p2.banner == "Apache/2.4"

    snap = TargetSnapshot(
        target="192.168.1.50",
        timestamp=time.time(),
        is_up=True,
        ports=[p1],
        vulns=[{"id": "CVE-2024-1234", "severity": "HIGH"}],
        risk_score=7.0,
        summary="1 open port",
    )
    s_dict = snap.to_dict()
    assert s_dict["target"] == "192.168.1.50"
    assert len(s_dict["ports"]) == 1
    assert len(s_dict["vulns"]) == 1

    restored = TargetSnapshot.from_dict(s_dict)
    assert restored.target == snap.target
    assert restored.is_up is True
    assert restored.ports[0].port == 80
    assert restored.risk_score == 7.0


def test_compute_diff_initial_baseline():
    snap = TargetSnapshot(
        target="10.0.0.1",
        timestamp=time.time(),
        is_up=True,
        ports=[PortSnapshot(port=22, service="ssh")],
        vulns=[],
        risk_score=0.0,
    )
    # First scan ever: previous is None
    diff = compute_diff(None, snap)
    assert diff.has_changes is True
    assert len(diff.new_ports) == 1
    assert diff.new_ports[0].port == 22
    assert diff.severity == "INFO"


def test_compute_diff_new_port_and_critical():
    prev = TargetSnapshot(
        target="10.0.0.1",
        timestamp=100.0,
        is_up=True,
        ports=[PortSnapshot(port=80, service="http")],
        vulns=[],
        risk_score=0.0,
    )
    # New port opened: 6379 (Redis - known critical port)
    curr = TargetSnapshot(
        target="10.0.0.1",
        timestamp=200.0,
        is_up=True,
        ports=[
            PortSnapshot(port=80, service="http"),
            PortSnapshot(port=6379, service="redis"),
        ],
        vulns=[],
        risk_score=10.0,
    )
    diff = compute_diff(prev, curr)
    assert diff.has_changes is True
    assert len(diff.new_ports) == 1
    assert diff.new_ports[0].port == 6379
    assert diff.severity == "CRITICAL"  # Port 6379 is in CRITICAL_PORTS
    assert diff.risk_delta == 10.0


def test_compute_diff_closed_port_and_resolved_vuln():
    prev = TargetSnapshot(
        target="10.0.0.1",
        timestamp=100.0,
        is_up=True,
        ports=[
            PortSnapshot(port=80, service="http"),
            PortSnapshot(port=21, service="ftp"),
        ],
        vulns=[{"id": "CVE-2023-9999", "port": 21, "severity": "HIGH"}],
        risk_score=7.0,
    )
    curr = TargetSnapshot(
        target="10.0.0.1",
        timestamp=200.0,
        is_up=True,
        ports=[PortSnapshot(port=80, service="http")],
        vulns=[],
        risk_score=0.0,
    )
    diff = compute_diff(prev, curr)
    assert diff.has_changes is True
    assert len(diff.closed_ports) == 1
    assert diff.closed_ports[0].port == 21
    assert len(diff.resolved_vulns) == 1
    assert diff.resolved_vulns[0]["id"] == "CVE-2023-9999"
    assert diff.risk_delta == -7.0
    assert diff.severity == "LOW"  # Remediation improvement!


def test_compute_diff_service_version_drift():
    prev = TargetSnapshot(
        target="10.0.0.1",
        timestamp=100.0,
        is_up=True,
        ports=[PortSnapshot(port=80, service="http", version="1.0")],
        vulns=[],
    )
    curr = TargetSnapshot(
        target="10.0.0.1",
        timestamp=200.0,
        is_up=True,
        ports=[PortSnapshot(port=80, service="http", version="2.0")],
        vulns=[],
    )
    diff = compute_diff(prev, curr)
    assert diff.has_changes is True
    assert len(diff.service_changes) == 1
    assert diff.service_changes[0]["old_version"] == "1.0"
    assert diff.service_changes[0]["new_version"] == "2.0"
    assert diff.severity == "MEDIUM"


def test_monitor_storage_sqlite(tmp_path):
    db_path = tmp_path / "test_monitor.db"
    storage = MonitorStorage(db_path=db_path)

    snap = TargetSnapshot(
        target="192.168.1.10",
        timestamp=1234567.0,
        is_up=True,
        ports=[PortSnapshot(port=443, service="https")],
        vulns=[],
        risk_score=2.0,
        summary="HTTPS open",
    )
    storage.save_snapshot(snap)

    latest = storage.get_latest_snapshot("192.168.1.10")
    assert latest is not None
    assert latest.target == "192.168.1.10"
    assert len(latest.ports) == 1
    assert latest.ports[0].port == 443

    # Record events
    storage.record_event(
        target="192.168.1.10",
        event_type="NEW_PORTS",
        severity="HIGH",
        title="Port 443 opened",
        details={"port": 443},
    )
    events = storage.get_events(limit=10)
    assert len(events) == 1
    assert events[0]["event_type"] == "NEW_PORTS"
    assert events[0]["title"] == "Port 443 opened"

    # Clear history
    storage.clear_history("192.168.1.10")
    assert storage.get_latest_snapshot("192.168.1.10") is None
    assert len(storage.get_events()) == 0


def test_webhook_dispatcher_channel_detection():
    assert WebhookDispatcher.detect_channel_type("https://discord.com/api/webhooks/123/xyz") == "discord"
    assert WebhookDispatcher.detect_channel_type("https://discordapp.com/api/webhooks/123/xyz") == "discord"
    assert WebhookDispatcher.detect_channel_type("https://hooks.slack.com/services/T00/B00/X00") == "slack"
    assert WebhookDispatcher.detect_channel_type("https://api.telegram.org/bot12345/sendMessage") == "telegram"
    assert WebhookDispatcher.detect_channel_type("https://siem.corp.internal/webhook/alerts") == "generic"


def test_webhook_dispatcher_payload_formatting():
    diff = MonitorDiff(
        target="192.168.1.100",
        timestamp=time.time(),
        new_ports=[PortSnapshot(port=3389, service="rdp")],
        new_vulns=[{"id": "VULN-RDP-NLA", "severity": "HIGH", "title": "RDP without NLA"}],
        resolved_vulns=[{"id": "VULN-SMBV1", "severity": "CRITICAL"}],
        severity="HIGH",
        risk_delta=3.5,
    )

    # Discord format
    discord_payload = WebhookDispatcher._format_discord(diff, "Office Server")
    assert "embeds" in discord_payload
    embed = discord_payload["embeds"][0]
    assert "192.168.1.100" in embed["title"] or "Office Server" in embed["title"]
    field_names = [f["name"] for f in embed["fields"]]
    assert any("Newly Opened Ports" in fn for fn in field_names)
    assert any("New Vulnerabilities" in fn for fn in field_names)

    # Slack format
    slack_payload = WebhookDispatcher._format_slack(diff, "Office Server")
    assert "blocks" in slack_payload
    assert len(slack_payload["blocks"]) >= 3

    # Generic format
    gen_payload = WebhookDispatcher._format_generic(diff, "Office Server")
    assert gen_payload["event"] == "monitor_diff_alert"
    assert gen_payload["severity"] == "HIGH"
    assert gen_payload["diff"]["has_changes"] is True


def test_webhook_send_sync_mock():
    diff = MonitorDiff(
        target="127.0.0.1",
        timestamp=time.time(),
        new_ports=[PortSnapshot(port=80, service="http")],
        severity="HIGH",
    )

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value.status = 200

    with patch("urllib.request.urlopen", return_value=mock_resp):
        success = WebhookDispatcher.send_webhook_sync(
            "https://discord.com/api/webhooks/mock/test",
            diff
        )
        assert success is True

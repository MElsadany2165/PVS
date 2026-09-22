# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

import pytest
from pvs.remediation import get_remediation_plan, RemediationPlan, RemediationStep


def test_ssh_remediation_plan_multi_os():
    plan = get_remediation_plan("ssh", version="8.9p1", cve_id="CVE-2024-6387")
    assert isinstance(plan, RemediationPlan)
    assert plan.service == "ssh"
    assert len(plan.steps) == 4
    
    # Check multi-OS command presence
    step2 = plan.steps[1]
    assert "apt" in step2.command_linux or "dnf" in step2.command_linux
    assert "winget" in step2.command_windows
    assert "brew" in step2.command_macos
    assert step2.primary_command != ""


def test_http_remediation_plan_multi_os():
    plan = get_remediation_plan("apache", version="2.4.52")
    assert len(plan.steps) >= 4
    step1 = plan.steps[0]
    assert "ServerTokens" in step1.command_linux
    assert "httpd.conf" in step1.command_windows


def test_redis_remediation_plan_multi_os():
    plan = get_remediation_plan("redis", version="7.0.0")
    step1 = plan.steps[0]
    assert "bind 127.0.0.1" in step1.command_linux
    assert "redis" in step1.command_windows.lower()


def test_dynamic_remediation_fallback_multi_os():
    plan = get_remediation_plan("custom_app", version="1.0.0", cve_id="CVE-2026-9999")
    assert plan.service == "custom_app"
    assert plan.cve_id == "CVE-2026-9999"
    assert len(plan.steps) == 4
    step2 = plan.steps[1]
    assert "custom_app" in step2.command_linux
    assert "custom_app" in step2.command_windows
    assert "custom_app" in step2.command_macos

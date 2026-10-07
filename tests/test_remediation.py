# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

import pytest
from pvs.remediation import (
    get_remediation_plan, RemediationPlan, RemediationStep,
    analyze_cve_categories,
)


def test_ssh_remediation_plan_multi_os():
    plan = get_remediation_plan("ssh", version="8.9p1", cve_id="CVE-2024-6387", port=22)
    assert isinstance(plan, RemediationPlan)
    assert plan.service == "ssh"
    assert len(plan.steps) >= 4

    # Check multi-OS command presence on the patch step
    patch_step = None
    for s in plan.steps:
        if s.category == "patch":
            patch_step = s
            break
    assert patch_step is not None
    assert "apt" in patch_step.command_linux or "dnf" in patch_step.command_linux
    assert patch_step.primary_command != ""


def test_http_remediation_plan_multi_os():
    plan = get_remediation_plan("apache", version="2.4.52", port=80)
    assert len(plan.steps) >= 3
    step1 = plan.steps[0]
    assert "ServerTokens" in step1.command_linux


def test_redis_remediation_plan_multi_os():
    plan = get_remediation_plan("redis", version="7.0.0", port=6379)
    step1 = plan.steps[0]
    assert "bind 127.0.0.1" in step1.command_linux
    assert "redis" in step1.command_windows.lower()


def test_dynamic_remediation_fallback_with_port():
    """Test that dynamic fallback uses actual port number instead of <PORT> placeholder."""
    plan = get_remediation_plan("custom_app", version="1.0.0", cve_id="CVE-2026-9999", port=8443)
    assert plan.service == "custom_app"
    assert plan.cve_id == "CVE-2026-9999"
    assert len(plan.steps) >= 3

    # The patch step should reference the service
    patch_step = plan.steps[1]
    assert "custom_app" in patch_step.command_linux

    # The firewall step should reference the actual port, not <PORT>
    firewall_step = None
    for s in plan.steps:
        if s.category == "firewall":
            firewall_step = s
            break
    assert firewall_step is not None
    assert "<PORT>" not in firewall_step.command_linux
    assert "8443" in firewall_step.command_linux
    assert "8443" in firewall_step.command_windows


def test_no_port_placeholder_in_any_remediation():
    """Ensure no service produces <PORT> placeholder in any command."""
    services = [
        ("ssh", 22), ("http", 80), ("nginx", 443), ("mysql", 3306),
        ("redis", 6379), ("smb", 445), ("ftp", 21), ("postgresql", 5432),
        ("mongodb", 27017), ("elasticsearch", 9200), ("rdp", 3389),
        ("telnet", 23), ("smtp", 25), ("dns", 53), ("snmp", 161),
        ("vnc", 5900), ("memcached", 11211), ("docker", 2375),
        ("tomcat", 8080), ("iis", 80),
    ]
    for svc, port in services:
        plan = get_remediation_plan(svc, version="1.0", port=port)
        for step in plan.steps:
            assert "<PORT>" not in step.command_linux, f"<PORT> found in {svc} linux: {step.title}"
            assert "<PORT>" not in step.command_windows, f"<PORT> found in {svc} windows: {step.title}"
            assert "<PORT>" not in step.command_macos, f"<PORT> found in {svc} macos: {step.title}"


def test_service_alias_resolution():
    """Test that service aliases resolve to the correct KB entry."""
    # apache -> http
    plan1 = get_remediation_plan("apache", port=80)
    assert "Apache" in plan1.summary or "HTTP" in plan1.summary or "Harden" in plan1.summary

    # microsoft-ds -> smb
    plan2 = get_remediation_plan("microsoft-ds", port=445)
    assert "SMB" in plan2.summary or "smb" in plan2.summary.lower()

    # mariadb -> mysql
    plan3 = get_remediation_plan("mariadb", port=3306)
    assert "MySQL" in plan3.summary or "MariaDB" in plan3.summary or "database" in plan3.summary.lower()


def test_cve_category_analysis():
    """Test CVE description category detection."""
    cats = analyze_cve_categories("Remote code execution vulnerability in OpenSSH")
    assert "rce" in cats

    cats2 = analyze_cve_categories("Authentication bypass allows unauthorized access")
    assert "auth_bypass" in cats2

    cats3 = analyze_cve_categories("Buffer overflow in the heap memory")
    assert "buffer_overflow" in cats3

    cats4 = analyze_cve_categories("Weak cipher suite allows TLS 1.0 downgrade attack")
    assert "weak_crypto" in cats4

    cats5 = analyze_cve_categories("Log4j JNDI injection allows remote class loading")
    assert "deserialization" in cats5

    cats6 = analyze_cve_categories("Denial of service via HTTP/2 rapid reset")
    assert "dos" in cats6


def test_cve_category_hardening_injection():
    """Test that RCE CVE descriptions inject extra hardening steps."""
    plan = get_remediation_plan(
        "ssh", version="8.9p1", cve_id="CVE-2024-6387",
        cve_description="Remote code execution vulnerability in OpenSSH server",
        severity="CRITICAL", port=22,
    )
    # Should have more steps than the base KB due to RCE hardening injection
    categories = [s.category for s in plan.steps]
    assert "harden" in categories, "RCE description should inject hardening steps"


def test_remediation_plan_to_dict():
    """Test serialization to dict format for JSON/HTML export."""
    plan = get_remediation_plan("redis", version="7.0.0", port=6379)
    d = plan.to_dict()
    assert d["service"] == "redis"
    assert isinstance(d["steps"], list)
    assert len(d["steps"]) > 0
    for step in d["steps"]:
        assert "step_number" in step
        assert "title" in step
        assert "command_linux" in step
        assert "command_windows" in step
        assert "command_macos" in step
        assert "category" in step
        assert "rollback_linux" in step
        assert "rollback_windows" in step
        assert "rollback_macos" in step
        assert "disruption_level" in step
        assert "estimated_time" in step


def test_remediation_rollback_and_safety_metadata():
    """Verify that remediation plans include populated rollback and operational safety metadata."""
    plan = get_remediation_plan("ssh", version="8.9p1", port=22)
    for step in plan.steps:
        assert step.rollback_linux != "", f"Missing rollback_linux in {step.title}"
        assert step.rollback_windows != "", f"Missing rollback_windows in {step.title}"
        assert step.rollback_macos != "", f"Missing rollback_macos in {step.title}"
        assert step.disruption_level in ("ZERO_DOWNTIME", "CONFIG_RELOAD", "SERVICE_RESTART", "READ_ONLY", "LOW")
        assert step.estimated_time != ""


def test_active_vulnerability_remediation_plans():
    """Verify that all active network vulnerability types generate actionable multi-OS plans."""
    active_keys = [
        ("unauth_redis", 6379),
        ("unauth_mongodb", 27017),
        ("unauth_memcached", 11211),
        ("unauth_elasticsearch", 9200),
        ("docker_socket", 2375),
        ("smbv1_enabled", 445),
        ("rdp_nla", 3389),
        ("ftp_anonymous", 21),
        ("cleartext_telnet", 23),
        ("cleartext_ftp", 21),
        ("cleartext_http", 80),
        ("cleartext_pop3", 110),
        ("cleartext_imap", 143),
        ("http_trace", 80),
        ("missing_hsts", 443),
        ("missing_xframe", 80),
        ("exposed_files", 80),
        ("deprecated_tls", 443),
        ("weak_ciphers", 443),
    ]
    for key, port in active_keys:
        plan = get_remediation_plan(key, port=port)
        assert len(plan.steps) >= 2, f"Expected >= 2 steps for {key}"
        for step in plan.steps:
            assert step.title != ""
            assert step.primary_command != "", f"Missing command for {key} in {step.title}"
            assert "<PORT>" not in step.command_linux
            assert "<PORT>" not in step.command_windows
            assert "<PORT>" not in step.command_macos



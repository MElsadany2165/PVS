# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for the Local OS Security Auditor and related integrations.
"""

import sys
import pytest
from unittest.mock import patch, MagicMock

from pvs.os_auditor import (
    OSFinding,
    detect_os_info,
    audit_local_os,
    _check_windows_defender,
    _check_windows_firewall,
    _check_windows_smb1,
    _check_windows_rdp,
    _check_windows_uac,
    _check_linux_firewall,
    _check_linux_ssh_config,
    _check_linux_aslr,
    _check_macos_sip,
    _check_macos_gatekeeper,
)
from pvs.remediation_engine import (
    group_vulnerabilities_by_root_cause,
    generate_remediation_script,
)
from pvs.reporter import build_scan_data


def test_detect_os_info():
    """Verify that detect_os_info returns complete system metadata."""
    info = detect_os_info()
    assert isinstance(info, dict)
    assert "platform" in info
    assert "os_type" in info
    assert "os_name" in info
    assert "architecture" in info
    assert info["os_type"] in ("windows", "linux", "macos", "unknown")


def test_os_finding_to_enhanced_cve_dict():
    """Verify conversion of OSFinding to EnhancedCVEEntry compatible dict."""
    finding = OSFinding(
        finding_id="OS-TEST-001",
        title="Test OS Vulnerability",
        severity="HIGH",
        score=7.8,
        description="A test vulnerability description",
        evidence="Evidence value detected on system",
        remediation_cmd="Set-TestOption -Enabled $true",
        remediation_description="Enable test option",
        verification_cmd="(Get-TestOption).Enabled",
        category="config",
        os_type="windows",
    )

    cve_dict = finding.to_enhanced_cve_dict()
    assert cve_dict["cve_id"] == "OS-TEST-001"
    assert cve_dict["severity"] == "HIGH"
    assert cve_dict["score"] == 7.8
    assert "remediation" in cve_dict
    assert len(cve_dict["remediation"]["steps"]) == 2

    # Step 1: harden
    step1 = cve_dict["remediation"]["steps"][0]
    assert step1["category"] == "harden"
    assert step1["command_windows"] == "Set-TestOption -Enabled $true"

    # Step 2: verify
    step2 = cve_dict["remediation"]["steps"][1]
    assert step2["category"] == "verify"
    assert step2["command_windows"] == "(Get-TestOption).Enabled"


def test_check_windows_defender_mocked():
    """Test Windows Defender check with disabled RTP."""
    with patch("pvs.os_auditor._run_cmd") as mock_cmd:
        mock_cmd.return_value = (0, "RTP=False\nAMS=True\nAS=True\nAV=True", "")
        findings = _check_windows_defender()
        assert len(findings) == 1
        assert findings[0].finding_id == "OS-WIN-DEFENDER-RTP-OFF"
        assert findings[0].severity == "CRITICAL"


def test_check_windows_firewall_mocked():
    """Test Windows Firewall check with disabled profiles."""
    with patch("pvs.os_auditor._run_cmd") as mock_cmd:
        mock_cmd.return_value = (0, "Domain=False\nPrivate=True\nPublic=False", "")
        findings = _check_windows_firewall()
        assert len(findings) == 1
        assert "Domain" in findings[0].title
        assert "Public" in findings[0].title
        assert findings[0].severity == "CRITICAL"


def test_check_windows_smb1_mocked():
    """Test Windows SMBv1 check when enabled."""
    with patch("pvs.os_auditor._run_cmd") as mock_cmd:
        mock_cmd.return_value = (0, "STATE=Enabled", "")
        findings = _check_windows_smb1()
        assert len(findings) == 1
        assert findings[0].finding_id == "OS-WIN-SMB1-ENABLED"
        assert findings[0].severity == "CRITICAL"


def test_check_linux_firewall_mocked():
    """Test Linux firewall check when inactive."""
    with patch("pvs.os_auditor._run_cmd_shell") as mock_cmd, \
         patch("shutil.which", return_value="/usr/sbin/ufw"):
        mock_cmd.return_value = (0, "Status: inactive", "")
        findings = _check_linux_firewall()
        assert len(findings) == 1
        assert findings[0].finding_id == "OS-LIN-FIREWALL-OFF"


def test_check_macos_sip_mocked():
    """Test macOS SIP check when disabled."""
    with patch("pvs.os_auditor._run_cmd_shell") as mock_cmd:
        mock_cmd.return_value = (0, "System Integrity Protection status: disabled.", "")
        findings = _check_macos_sip()
        assert len(findings) == 1
        assert findings[0].finding_id == "OS-MAC-SIP-DISABLED"
        assert findings[0].severity == "CRITICAL"


def test_audit_local_os_sorting():
    """Verify that audit_local_os sorts findings by severity (CRITICAL first)."""
    f_low = OSFinding("OS-LOW", "Low Finding", "LOW", 3.0, "", "", "", "", "", "config", "windows")
    f_crit = OSFinding("OS-CRIT", "Critical Finding", "CRITICAL", 9.5, "", "", "", "", "", "firewall", "windows")
    f_high = OSFinding("OS-HIGH", "High Finding", "HIGH", 7.5, "", "", "", "", "", "auth", "windows")

    mock_os_info = {"os_type": "windows", "os_name": "Windows"}
    with patch("pvs.os_auditor._check_windows_defender", return_value=[f_crit]), \
         patch("pvs.os_auditor._check_windows_firewall", return_value=[f_low]), \
         patch("pvs.os_auditor._check_windows_updates", return_value=[f_high]), \
         patch("pvs.os_auditor._check_windows_smb1", return_value=[]), \
         patch("pvs.os_auditor._check_windows_rdp", return_value=[]), \
         patch("pvs.os_auditor._check_windows_password_policy", return_value=[]), \
         patch("pvs.os_auditor._check_windows_guest_account", return_value=[]), \
         patch("pvs.os_auditor._check_windows_autorun", return_value=[]), \
         patch("pvs.os_auditor._check_windows_uac", return_value=[]), \
         patch("pvs.os_auditor._check_windows_bitlocker", return_value=[]), \
         patch("pvs.os_auditor._check_windows_powershell_policy", return_value=[]), \
         patch("pvs.os_auditor._check_windows_smb_signing", return_value=[]):
        _, results = audit_local_os(mock_os_info)
        assert len(results) == 3
        assert results[0].severity == "CRITICAL"
        assert results[1].severity == "HIGH"
        assert results[2].severity == "LOW"


def test_root_cause_grouping_with_os_findings():
    """Verify that root-cause grouping in remediation_engine handles OS findings."""
    f = OSFinding(
        finding_id="OS-WIN-DEFENDER-RTP-OFF",
        title="Windows Defender Real-Time Protection DISABLED",
        severity="CRITICAL",
        score=9.5,
        description="Windows Defender RTP is off",
        evidence="RTP=False",
        remediation_cmd="Set-MpPreference -DisableRealtimeMonitoring $false",
        remediation_description="Enable Windows Defender RTP",
        verification_cmd="(Get-MpComputerStatus).RealTimeProtectionEnabled",
        category="service",
        os_type="windows",
    )

    cve_results = {
        "127.0.0.1:host": [f.to_enhanced_cve_dict()]
    }

    root_causes = group_vulnerabilities_by_root_cause(cve_results)
    assert len(root_causes) == 1
    rc = root_causes[0]
    assert rc.action_type == "OS_POLICY_HARDEN"
    assert "Host OS Security" in rc.component
    assert "Set-MpPreference" in rc.command_windows
    assert "(Get-MpComputerStatus).RealTimeProtectionEnabled" == rc.verification_command


def test_generate_script_with_os_findings():
    """Verify that generate_remediation_script outputs OS verification commands."""
    f = OSFinding(
        finding_id="OS-WIN-FIREWALL-OFF",
        title="Windows Firewall Disabled",
        severity="CRITICAL",
        score=9.0,
        description="Firewall is off",
        evidence="Domain=False",
        remediation_cmd="Set-NetFirewallProfile -Profile Domain -Enabled True",
        remediation_description="Enable Domain Firewall",
        verification_cmd="Get-NetFirewallProfile",
        category="firewall",
        os_type="windows",
    )

    cve_results = {
        "127.0.0.1:host": [f.to_enhanced_cve_dict()]
    }

    fname, script = generate_remediation_script(cve_results, target_ip="127.0.0.1", os_target="windows")
    assert fname.endswith(".ps1")
    assert "Set-NetFirewallProfile" in script
    assert "Get-NetFirewallProfile" in script
    assert "Test-Admin" in script


def test_build_scan_data_with_host_os_findings():
    """Verify build_scan_data includes Host OS Security under virtual port 0."""
    f = OSFinding(
        finding_id="OS-TEST-123",
        title="Test OS Finding",
        severity="HIGH",
        score=7.0,
        description="Desc",
        evidence="Evidence",
        remediation_cmd="command",
        remediation_description="rem desc",
        verification_cmd="ver cmd",
        category="update",
        os_type="windows",
    )

    cve_results = {
        "127.0.0.1:host": [f.to_enhanced_cve_dict()]
    }

    data = build_scan_data("127.0.0.1", [], cve_results, scan_mode="offline")
    assert len(data["hosts"]) == 1
    host = data["hosts"][0]
    assert len(host["ports"]) == 1
    port_entry = host["ports"][0]
    assert port_entry["port"] == 0
    assert port_entry["service"] == "Host OS Security"
    assert len(port_entry["cves"]) == 1
    assert port_entry["cves"][0]["cve_id"] == "OS-TEST-123"

# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for pvs/remediation_engine.py and Brain attack chains.
"""

import pytest
from pvs.remediation_engine import (
    group_vulnerabilities_by_root_cause,
    generate_remediation_script,
    verify_remediation_live,
    RootCauseFix,
)
from pvs.brain import analyze_scan_results, NetworkPosture
from pvs.scanner import HostResult, PortResult


def test_group_vulnerabilities_by_root_cause():
    """Test clustering multiple CVEs into a single root-cause fix."""
    cve_mock = [
        {
            "cve_id": "CVE-2024-6387",
            "severity": "CRITICAL",
            "score": 8.1,
            "description": "OpenSSH regreSSHion unauthenticated RCE",
            "remediation": {
                "service": "ssh",
                "summary": "Upgrade OpenSSH",
                "steps": [
                    {
                        "step_number": 1,
                        "title": "Upgrade",
                        "command_linux": "sudo apt update && sudo apt install --only-upgrade openssh-server -y",
                        "command_windows": "winget upgrade OpenSSH.Server",
                        "category": "patch",
                    }
                ]
            }
        },
        {
            "cve_id": "CVE-2023-48795",
            "severity": "MEDIUM",
            "score": 5.9,
            "description": "Terrapin attack sequence manipulation",
        }
    ]
    cve_results = {"127.0.0.1:22": cve_mock}
    root_causes = group_vulnerabilities_by_root_cause(cve_results)

    assert len(root_causes) == 1
    rc = root_causes[0]
    assert rc.port == 22
    assert "CVE-2024-6387" in rc.cve_ids
    assert "CVE-2023-48795" in rc.cve_ids
    assert rc.max_severity == "CRITICAL"
    assert "openssh" in rc.command_linux.lower()


def test_generate_remediation_script_linux():
    """Test generating a bash script with backups and verification."""
    cve_results = {
        "127.0.0.1:6379": [
            {
                "cve_id": "VULN-UNAUTH-REDIS",
                "severity": "CRITICAL",
                "score": 10.0,
                "description": "Redis unauthenticated access",
                "remediation": {
                    "service": "redis",
                    "summary": "Harden Redis",
                    "steps": [
                        {
                            "step_number": 1,
                            "title": "Bind Localhost",
                            "command_linux": "sudo sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf",
                            "command_windows": "Restart-Service redis",
                            "category": "harden",
                        }
                    ]
                }
            }
        ]
    }
    filename, script = generate_remediation_script(cve_results, target_ip="127.0.0.1", os_target="linux")
    assert filename.endswith(".sh")
    assert "#!/usr/bin/env bash" in script
    assert "BACKUP_DIR=" in script
    assert "bind 127.0.0.1" in script
    assert "VERIFICATION PROBES" in script


def test_generate_remediation_script_windows():
    """Test generating a PowerShell script with elevation check."""
    cve_results = {
        "127.0.0.1:3389": [
            {
                "cve_id": "VULN-RDP-NLA-DISABLED",
                "severity": "HIGH",
                "score": 7.5,
                "description": "RDP without NLA",
                "remediation": {
                    "service": "rdp",
                    "summary": "Enable NLA",
                    "steps": [
                        {
                            "step_number": 1,
                            "title": "Enable NLA",
                            "command_windows": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1",
                            "category": "harden",
                        }
                    ]
                }
            }
        ]
    }
    filename, script = generate_remediation_script(cve_results, target_ip="127.0.0.1", os_target="windows")
    assert filename.endswith(".ps1")
    assert "Test-Admin" in script
    assert "UserAuthentication" in script
    assert "Test-NetConnection" in script


def test_brain_attack_chains_and_root_causes():
    """Test Brain synthesizing multi-stage attack chains and root-cause actions."""
    host = HostResult(
        ip="192.168.1.100",
        is_up=True,
        ports=[
            PortResult(port=6379, state="open", service="redis"),  # entry point
            PortResult(port=22, state="open", service="ssh"),      # pivot / lateral movement
        ]
    )
    cve_results = {
        "192.168.1.100:6379": [
            {
                "cve_id": "VULN-UNAUTH-REDIS",
                "severity": "CRITICAL",
                "score": 10.0,
                "description": "Unauthenticated Redis command execution",
            }
        ]
    }
    posture = analyze_scan_results([host], cve_results=cve_results)

    assert len(posture.attack_chains) >= 1
    chain = posture.attack_chains[0]
    assert chain["host"] == "192.168.1.100"
    assert "Initial Access" in chain["stage_1_entry"]
    assert "Lateral Movement" in chain["stage_2_pivot"]
    assert len(posture.root_cause_actions) >= 1


@pytest.mark.asyncio
async def test_verify_remediation_live_closed_port():
    """Test live verification on a closed port returns RESOLVED."""
    # Port 65432 should not be listening on 127.0.0.1
    res = await verify_remediation_live("127.0.0.1", 65432, service="redis")
    assert res["status"] == "RESOLVED"
    assert res["verified"] is True


@pytest.mark.asyncio
async def test_verify_remediation_live_cve_closed_port():
    """Test CVE verification on a closed port marks threat eliminated."""
    res = await verify_remediation_live("127.0.0.1", 65433, service="ssh", vuln_id="CVE-2024-6387")
    assert res["status"] == "RESOLVED"
    assert res["verified"] is True
    assert "closed or rejected" in res["message"]


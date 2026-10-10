# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for pvs/compliance.py.
"""

import pytest
from pvs.compliance import evaluate_cis_benchmarks, CISControlCheck, ComplianceReport


def test_evaluate_cis_benchmarks_clean_system():
    """Test evaluating a secure system with no open cleartext ports and no failures."""
    report = evaluate_cis_benchmarks(
        target="127.0.0.1",
        scan_hosts=[{"ip": "127.0.0.1", "ports": [{"port": 443, "state": "open", "cves": []}]}],
        os_audit_results=[],
        active_vulns=[],
    )
    assert report.compliance_score >= 85.0
    assert report.failed_checks == 0
    assert report.readiness_rating in ("COMPLIANT", "SUBSTANTIALLY_COMPLIANT")
    assert report.total_checks > 5


def test_evaluate_cis_benchmarks_with_failures():
    """Test evaluating an insecure system with cleartext protocols and disabled firewall."""
    report = evaluate_cis_benchmarks(
        target="127.0.0.1",
        scan_hosts=[{"ip": "127.0.0.1", "ports": [{"port": 21, "state": "open", "cves": []}]}],
        os_audit_results=[
            {"id": "OS-SEC-WIN-FIREWALL", "status": "FAIL"},
            {"id": "OS-SEC-WIN-UAC", "status": "FAIL"},
        ],
        active_vulns=[{"vuln_id": "VULN-CLEARTEXT-FTP"}],
    )
    assert report.failed_checks >= 2
    assert report.compliance_score < 75.0
    assert report.readiness_rating in ("PARTIALLY_COMPLIANT", "NON_COMPLIANT")

    failed_ids = [c.control_id for c in report.controls_breakdown if c.status == "FAIL"]
    assert "CIS-3.3" in failed_ids  # Cleartext
    assert "CIS-4.4" in failed_ids  # Host firewall

# Copyright (c) 2026 Mohamed Essam Elsadany
# Licensed under the MIT License. See LICENSE file for details.

"""
Unit tests for pvs/cve_db.py -- curated offline CVE database and
semantic version comparison engine.
"""

import pytest
from pvs.cve_db import (
    parse_semver,
    compare_versions,
    is_version_affected,
    find_curated_cves,
    CURATED_NETWORK_CVES,
)


# ---------------------------------------------------------------------------
# parse_semver
# ---------------------------------------------------------------------------

class TestParseSemver:
    def test_simple_dotted(self):
        parts, suff = parse_semver("2.4.58")
        assert parts == (2, 4, 58)
        assert suff == ""

    def test_openssh_style(self):
        parts, suff = parse_semver("8.9p1")
        assert parts == (8, 9)
        assert "p1" in suff

    def test_leading_prefix_stripped(self):
        parts, suff = parse_semver("OpenSSH_8.9p1")
        assert parts == (8, 9)

    def test_empty_string(self):
        parts, suff = parse_semver("")
        assert parts == ()

    def test_v_prefix(self):
        parts, suff = parse_semver("v1.2.3")
        assert parts == (1, 2, 3)


# ---------------------------------------------------------------------------
# compare_versions
# ---------------------------------------------------------------------------

class TestCompareVersions:
    def test_less_than(self):
        assert compare_versions("2.4.49", "2.4.52") == -1

    def test_greater_than(self):
        assert compare_versions("9.8p1", "8.9p1") == 1

    def test_equal(self):
        assert compare_versions("1.0.0", "1.0.0") == 0

    def test_different_lengths(self):
        assert compare_versions("2.4", "2.4.1") == -1

    def test_openssh_regression(self):
        assert compare_versions("9.7p1", "9.8p1") == -1
        assert compare_versions("9.8p1", "9.8p1") == 0


# ---------------------------------------------------------------------------
# is_version_affected  (multi-condition spec string)
# ---------------------------------------------------------------------------

class TestIsVersionAffected:
    def test_range_affected(self):
        # RegreSSHion: >= 8.5p1, < 9.8p1
        assert is_version_affected("8.9p1", ">= 8.5p1, < 9.8p1") is True

    def test_range_below_lower_bound(self):
        assert is_version_affected("8.4p1", ">= 8.5p1, < 9.8p1") is False

    def test_range_at_upper_bound(self):
        assert is_version_affected("9.8p1", ">= 8.5p1, < 9.8p1") is False

    def test_apache_path_traversal(self):
        # CVE-2021-41773: = 2.4.49
        assert is_version_affected("2.4.49", "= 2.4.49") is True
        assert is_version_affected("2.4.50", "= 2.4.49") is False

    def test_nginx_range(self):
        assert is_version_affected("1.25.2", "< 1.25.3") is True
        assert is_version_affected("1.25.3", "< 1.25.3") is False

    def test_empty_version_returns_false(self):
        # is_version_affected returns False for empty version (safe default)
        assert is_version_affected("", "< 9.8p1") is False

    def test_all_spec_always_true(self):
        assert is_version_affected("1.0.0", "all") is True


# ---------------------------------------------------------------------------
# find_curated_cves
# ---------------------------------------------------------------------------

class TestFindCuratedCves:
    def test_openssh_regreSSHion_detected(self):
        # OpenSSH 8.9p1 is in the affected range for CVE-2024-6387 RegreSSHion
        results = find_curated_cves("ssh", "8.9p1", banner="OpenSSH_8.9p1")
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2024-6387" in cve_ids, f"Expected CVE-2024-6387 in {cve_ids}"

    def test_openssh_patched_not_detected(self):
        # OpenSSH 9.8p1 is the fix -- should NOT be flagged for RegreSSHion
        results = find_curated_cves("ssh", "9.8p1", banner="OpenSSH_9.8p1")
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2024-6387" not in cve_ids, "Patched OpenSSH 9.8p1 should not trigger RegreSSHion"

    def test_apache_path_traversal(self):
        # CVE-2021-41773 affects Apache 2.4.49 only
        results = find_curated_cves("apache", "2.4.49", banner="Apache/2.4.49")
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2021-41773" in cve_ids, f"Expected CVE-2021-41773 in {cve_ids}"

    def test_apache_patched_not_affected(self):
        results = find_curated_cves("apache", "2.4.58", banner="Apache/2.4.58")
        cve_ids = [r.cve_id for r in results]
        assert "CVE-2021-41773" not in cve_ids

    def test_empty_service_returns_empty(self):
        assert find_curated_cves("", "") == []

    def test_unknown_service_returns_empty(self):
        assert find_curated_cves("unknown", "") == []

    def test_results_sorted_by_score_desc(self):
        results = find_curated_cves("ssh", "8.9p1", banner="OpenSSH_8.9p1")
        if len(results) > 1:
            scores = [r.score for r in results]
            assert scores == sorted(scores, reverse=True)

    def test_curated_db_non_empty(self):
        # Sanity: the database itself must have entries
        assert len(CURATED_NETWORK_CVES) >= 10, f"Expected at least 10 entries, got {len(CURATED_NETWORK_CVES)}"

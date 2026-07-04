"""
tests/unit/test_cvss_epss.py
==============================
Unit tests for CVSS 3.1 vector mapping, EPSS scoring, and the
Weissman Priority Score formula in src/cvss_epss.py.

Run with: pytest tests/unit/test_cvss_epss.py -v
"""

import pytest
from unittest.mock import MagicMock, patch

from src.cvss_epss import (
    severity_to_cvss_vector,
    parse_cvss_vector,
    get_epss_score,
    cvss_severity_to_numeric,
    weissman_priority_score,
)


# ---------------------------------------------------------------------------
# severity_to_cvss_vector
# ---------------------------------------------------------------------------

class TestSeverityToCvssVector:
    def test_critical_vector(self):
        v = severity_to_cvss_vector("critical")
        assert v.startswith("CVSS:3.1")
        assert "C:H" in v and "I:H" in v and "A:H" in v

    def test_high_vector(self):
        v = severity_to_cvss_vector("high")
        assert "C:H" in v

    def test_medium_vector(self):
        v = severity_to_cvss_vector("medium")
        assert v.startswith("CVSS:3.1")

    def test_low_vector(self):
        v = severity_to_cvss_vector("low")
        assert "AC:H" in v

    def test_unknown_falls_back(self):
        v = severity_to_cvss_vector("unknown")
        assert v.startswith("CVSS:3.1")

    def test_none_falls_back(self):
        v = severity_to_cvss_vector(None)
        assert v.startswith("CVSS:3.1")

    def test_case_insensitive(self):
        assert severity_to_cvss_vector("CRITICAL") == severity_to_cvss_vector("critical")
        assert severity_to_cvss_vector("High") == severity_to_cvss_vector("high")


# ---------------------------------------------------------------------------
# parse_cvss_vector
# ---------------------------------------------------------------------------

class TestParseCvssVector:
    def test_parse_critical_vector(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = parse_cvss_vector(v)
        assert score is not None
        assert score >= 9.0  # Critical

    def test_parse_high_vector(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        score = parse_cvss_vector(v)
        assert score is not None
        assert 6.0 <= score <= 9.5

    def test_parse_medium_vector(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
        score = parse_cvss_vector(v)
        assert score is not None
        assert 4.0 <= score <= 7.0

    def test_parse_low_vector(self):
        v = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"
        score = parse_cvss_vector(v)
        assert score is not None
        assert 0.0 <= score < 5.0

    def test_returns_none_for_empty(self):
        assert parse_cvss_vector("") is None
        assert parse_cvss_vector(None) is None

    def test_returns_none_for_invalid_prefix(self):
        assert parse_cvss_vector("CVSS:2.0/AV:N/AC:L") is None

    def test_returns_none_for_no_metrics(self):
        assert parse_cvss_vector("CVSS:3.1") is None

    def test_scope_changed_vector(self):
        # Scope:Changed vectors should score higher
        v_unchanged = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        v_changed = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        score_u = parse_cvss_vector(v_unchanged)
        score_c = parse_cvss_vector(v_changed)
        assert score_u is not None and score_c is not None
        assert score_c >= score_u  # Scope:Changed should be >= Scope:Unchanged

    def test_returns_float(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = parse_cvss_vector(v)
        assert isinstance(score, float)

    def test_zero_impact(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        score = parse_cvss_vector(v)
        assert score is not None
        assert score == 0.0


# ---------------------------------------------------------------------------
# cvss_severity_to_numeric
# ---------------------------------------------------------------------------

class TestCvssSeverityToNumeric:
    def test_critical_is_highest(self):
        assert cvss_severity_to_numeric("critical") > cvss_severity_to_numeric("high")

    def test_high_greater_than_medium(self):
        assert cvss_severity_to_numeric("high") > cvss_severity_to_numeric("medium")

    def test_medium_greater_than_low(self):
        assert cvss_severity_to_numeric("medium") > cvss_severity_to_numeric("low")

    def test_case_insensitive(self):
        assert cvss_severity_to_numeric("CRITICAL") == cvss_severity_to_numeric("critical")

    def test_unknown_returns_medium(self):
        assert cvss_severity_to_numeric("unknown") == cvss_severity_to_numeric("medium")

    def test_none_returns_medium(self):
        assert cvss_severity_to_numeric(None) == cvss_severity_to_numeric("medium")

    def test_all_values_in_range(self):
        for sev in ("critical", "high", "medium", "low"):
            v = cvss_severity_to_numeric(sev)
            assert 0.0 <= v <= 10.0


# ---------------------------------------------------------------------------
# get_epss_score
# ---------------------------------------------------------------------------

class TestGetEpssScore:
    def test_returns_none_for_non_cve(self):
        assert get_epss_score("NOT-A-CVE") is None
        assert get_epss_score("") is None
        assert get_epss_score(None) is None

    def test_returns_none_for_cve_without_prefix(self):
        assert get_epss_score("2024-1234") is None

    @patch("src.cvss_epss.safe_get")
    def test_returns_score_from_api(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"cve": "CVE-2024-1234", "epss": "0.75"}]}
        mock_get.return_value = mock_resp

        score = get_epss_score("CVE-2024-1234")
        assert score == pytest.approx(0.75)

    @patch("src.cvss_epss.safe_get")
    def test_returns_none_on_http_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        assert get_epss_score("CVE-2024-0001") is None

    @patch("src.cvss_epss.safe_get")
    def test_returns_none_on_empty_data(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": []}
        mock_get.return_value = mock_resp

        assert get_epss_score("CVE-2024-9999") is None

    @patch("src.cvss_epss.safe_get")
    def test_returns_none_on_exception(self, mock_get):
        mock_get.side_effect = ConnectionError("network error")
        assert get_epss_score("CVE-2024-0001") is None

    @patch("src.cvss_epss.safe_get")
    def test_accepts_lowercase_cve(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"epss": "0.1"}]}
        mock_get.return_value = mock_resp

        score = get_epss_score("cve-2024-5555")
        assert score is not None


# ---------------------------------------------------------------------------
# weissman_priority_score
# ---------------------------------------------------------------------------

class TestWeissmanPriorityScore:
    def test_returns_float(self):
        score = weissman_priority_score(cvss_value=8.0, epss_value=0.5)
        assert isinstance(score, float)

    def test_range_is_0_to_100(self):
        for cvss in (0.0, 5.0, 10.0):
            for epss in (0.0, 0.5, 1.0):
                score = weissman_priority_score(cvss_value=cvss, epss_value=epss)
                assert 0.0 <= score <= 100.0

    def test_max_score_at_max_params(self):
        score = weissman_priority_score(
            cvss_value=10.0,
            epss_value=1.0,
            asset_criticality=2.0,
        )
        assert score == pytest.approx(100.0, abs=0.1)

    def test_higher_epss_means_higher_score(self):
        low = weissman_priority_score(cvss_value=7.0, epss_value=0.1)
        high = weissman_priority_score(cvss_value=7.0, epss_value=0.9)
        assert high > low

    def test_higher_criticality_means_higher_score(self):
        normal = weissman_priority_score(cvss_value=7.0, epss_value=0.5, asset_criticality=1.0)
        critical = weissman_priority_score(cvss_value=7.0, epss_value=0.5, asset_criticality=2.0)
        assert critical > normal

    def test_severity_fallback_when_no_cvss(self):
        s_critical = weissman_priority_score(severity="critical", epss_value=0.5)
        s_low = weissman_priority_score(severity="low", epss_value=0.5)
        assert s_critical > s_low

    def test_vector_used_when_cvss_missing(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score_vector = weissman_priority_score(vector=v, epss_value=0.5)
        score_severity = weissman_priority_score(severity="critical", epss_value=0.5)
        # Both should produce meaningful (> 20%) scores for critical findings
        assert score_vector > 20.0
        assert score_severity > 20.0

    def test_zero_epss_produces_low_score(self):
        score = weissman_priority_score(cvss_value=10.0, epss_value=0.0)
        # Even critical CVSS with 0 EPSS should be bounded
        assert score < 30.0

    def test_criticality_clipped_to_range(self):
        score_low = weissman_priority_score(cvss_value=5.0, epss_value=0.5, asset_criticality=0.1)
        score_high = weissman_priority_score(cvss_value=5.0, epss_value=0.5, asset_criticality=10.0)
        score_min = weissman_priority_score(cvss_value=5.0, epss_value=0.5, asset_criticality=0.5)
        score_max = weissman_priority_score(cvss_value=5.0, epss_value=0.5, asset_criticality=2.0)
        # Clipped values should match boundary values
        assert score_low == score_min
        assert score_high == score_max

    def test_defaults_work(self):
        # Should not raise and should return a valid score
        score = weissman_priority_score()
        assert 0.0 <= score <= 100.0

    def test_rounded_to_2_decimal_places(self):
        score = weissman_priority_score(cvss_value=7.3, epss_value=0.42)
        decimal_part = str(score).split(".")
        if len(decimal_part) > 1:
            assert len(decimal_part[1]) <= 2

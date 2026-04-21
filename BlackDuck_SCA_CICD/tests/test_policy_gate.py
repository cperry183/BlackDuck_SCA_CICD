"""
test_policy_gate.py — Unit tests for policy_gate.py

Run with:
    pip install pytest pytest-mock requests
    pytest tests/ -v
"""

import sys
import types
import pytest
from unittest.mock import MagicMock, patch

# Shim the module under test so we can import it without side effects
sys.path.insert(0, "scripts")
import policy_gate


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MOCK_BEARER = "test-bearer-token"
MOCK_VERSION_HREF = "https://hub.example.com/api/projects/pid/versions/vid"


def make_vuln(severity, cvss, status="NEW", name="CVE-2099-0001",
              comp="some-lib", ver="1.0.0"):
    return {
        "componentName": comp,
        "componentVersionName": ver,
        "vulnerabilityWithRemediation": [{
            "vulnerabilityName": name,
            "severity": severity,
            "overallScore": cvss,
            "remediationStatus": status,
        }],
    }


# ---------------------------------------------------------------------------
# get_bearer_token
# ---------------------------------------------------------------------------

def test_get_bearer_token_success():
    with patch("policy_gate.requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.raise_for_status = lambda: None
        mock_post.return_value.json.return_value = {"bearerToken": MOCK_BEARER}

        token = policy_gate.get_bearer_token("https://hub.example.com", "api-key", verify=True)
        assert token == MOCK_BEARER


def test_get_bearer_token_failure():
    import requests as req
    with patch("policy_gate.requests.post") as mock_post:
        mock_post.return_value.raise_for_status.side_effect = req.HTTPError("401")
        with pytest.raises(req.HTTPError):
            policy_gate.get_bearer_token("https://hub.example.com", "bad-token", verify=True)


# ---------------------------------------------------------------------------
# get_vuln_summary
# ---------------------------------------------------------------------------

def test_vuln_summary_no_findings():
    with patch("policy_gate.requests.get") as mock_get:
        mock_get.return_value.raise_for_status = lambda: None
        mock_get.return_value.json.return_value = {"items": []}

        summary = policy_gate.get_vuln_summary(MOCK_VERSION_HREF, {}, verify=True)
        assert summary["counts"]["CRITICAL"] == 0
        assert summary["max_cvss"] == 0.0
        assert summary["violations"] == []


def test_vuln_summary_critical_finding():
    vuln_data = [make_vuln("CRITICAL", 10.0, comp="log4j-core", ver="2.14.1",
                            name="CVE-2021-44228")]
    with patch("policy_gate.requests.get") as mock_get:
        mock_get.return_value.raise_for_status = lambda: None
        mock_get.return_value.json.return_value = {"items": vuln_data}

        summary = policy_gate.get_vuln_summary(MOCK_VERSION_HREF, {}, verify=True)
        assert summary["counts"]["CRITICAL"] == 1
        assert summary["max_cvss"] == 10.0
        assert len(summary["violations"]) == 1


def test_vuln_summary_mixed_severities():
    vulns = [
        make_vuln("CRITICAL", 9.8),
        make_vuln("CRITICAL", 10.0),
        make_vuln("HIGH", 8.1),
        make_vuln("MEDIUM", 5.5),
        make_vuln("LOW", 2.0),
    ]
    with patch("policy_gate.requests.get") as mock_get:
        mock_get.return_value.raise_for_status = lambda: None
        mock_get.return_value.json.return_value = {"items": vulns}

        summary = policy_gate.get_vuln_summary(MOCK_VERSION_HREF, {}, verify=True)
        assert summary["counts"]["CRITICAL"] == 2
        assert summary["counts"]["HIGH"] == 1
        assert summary["counts"]["MEDIUM"] == 1
        assert summary["counts"]["LOW"] == 1
        assert summary["max_cvss"] == 10.0


# ---------------------------------------------------------------------------
# main() — end-to-end with mocked API
# ---------------------------------------------------------------------------

def _mock_args(fail_on="CRITICAL", max_cvss=None, insecure=False):
    args = MagicMock()
    args.bd_url = "https://hub.example.com"
    args.bd_token = "test-token"
    args.project = "test-project"
    args.version = "1.0.0"
    args.fail_on_severities = fail_on
    args.max_cvss = max_cvss
    args.insecure = insecure
    return args


@patch("policy_gate.find_project_version", return_value=MOCK_VERSION_HREF)
@patch("policy_gate.get_bearer_token", return_value=MOCK_BEARER)
@patch("policy_gate.parse_args")
def test_main_clean_passes(mock_parse, mock_auth, mock_find):
    mock_parse.return_value = _mock_args()
    with patch("policy_gate.get_vuln_summary") as mock_summary:
        mock_summary.return_value = {
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "max_cvss": 0.0,
            "violations": [],
        }
        result = policy_gate.main()
    assert result == 0


@patch("policy_gate.find_project_version", return_value=MOCK_VERSION_HREF)
@patch("policy_gate.get_bearer_token", return_value=MOCK_BEARER)
@patch("policy_gate.parse_args")
def test_main_critical_fails(mock_parse, mock_auth, mock_find):
    mock_parse.return_value = _mock_args(fail_on="CRITICAL")
    with patch("policy_gate.get_vuln_summary") as mock_summary:
        mock_summary.return_value = {
            "counts": {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "max_cvss": 10.0,
            "violations": [make_vuln("CRITICAL", 10.0)],
        }
        result = policy_gate.main()
    assert result == 1


@patch("policy_gate.find_project_version", return_value=MOCK_VERSION_HREF)
@patch("policy_gate.get_bearer_token", return_value=MOCK_BEARER)
@patch("policy_gate.parse_args")
def test_main_high_not_blocked_when_only_critical_threshold(mock_parse, mock_auth, mock_find):
    """HIGH vulns should pass if only CRITICAL is in fail_on_severities."""
    mock_parse.return_value = _mock_args(fail_on="CRITICAL")
    with patch("policy_gate.get_vuln_summary") as mock_summary:
        mock_summary.return_value = {
            "counts": {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "max_cvss": 8.9,
            "violations": [make_vuln("HIGH", 8.9)],
        }
        result = policy_gate.main()
    assert result == 0


@patch("policy_gate.find_project_version", return_value=MOCK_VERSION_HREF)
@patch("policy_gate.get_bearer_token", return_value=MOCK_BEARER)
@patch("policy_gate.parse_args")
def test_main_cvss_threshold_triggers(mock_parse, mock_auth, mock_find):
    """CVSS threshold should fail even if severity list wouldn't block it."""
    mock_parse.return_value = _mock_args(fail_on="CRITICAL", max_cvss=8.5)
    with patch("policy_gate.get_vuln_summary") as mock_summary:
        mock_summary.return_value = {
            "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "max_cvss": 9.8,
            "violations": [make_vuln("HIGH", 9.8)],
        }
        result = policy_gate.main()
    assert result == 1


@patch("policy_gate.find_project_version", return_value=None)
@patch("policy_gate.get_bearer_token", return_value=MOCK_BEARER)
@patch("policy_gate.parse_args")
def test_main_project_not_found_returns_2(mock_parse, mock_auth, mock_find):
    mock_parse.return_value = _mock_args()
    result = policy_gate.main()
    assert result == 2


@patch("policy_gate.find_project_version", return_value=MOCK_VERSION_HREF)
@patch("policy_gate.get_bearer_token", return_value=MOCK_BEARER)
@patch("policy_gate.parse_args")
def test_main_cvss_exactly_at_threshold_fails(mock_parse, mock_auth, mock_find):
    """Boundary condition: CVSS == threshold should fail (>=)."""
    mock_parse.return_value = _mock_args(max_cvss=9.0)
    with patch("policy_gate.get_vuln_summary") as mock_summary:
        mock_summary.return_value = {
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "max_cvss": 9.0,
            "violations": [make_vuln("HIGH", 9.0)],
        }
        result = policy_gate.main()
    assert result == 1


@patch("policy_gate.find_project_version", return_value=MOCK_VERSION_HREF)
@patch("policy_gate.get_bearer_token", return_value=MOCK_BEARER)
@patch("policy_gate.parse_args")
def test_main_cvss_just_below_threshold_passes(mock_parse, mock_auth, mock_find):
    """Boundary condition: CVSS just below threshold should pass."""
    mock_parse.return_value = _mock_args(max_cvss=9.0)
    with patch("policy_gate.get_vuln_summary") as mock_summary:
        mock_summary.return_value = {
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "max_cvss": 8.9,
            "violations": [],
        }
        result = policy_gate.main()
    assert result == 0

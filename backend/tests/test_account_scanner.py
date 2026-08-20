"""
Unit tests for app.scanners.account_scanner.

Mirrors the account-rule tests in test_iam_scanner.py — this scanner
targets the same 'account' node type, just sourced from CloudTrail
data instead of IAM data.
"""

from app.models.finding import Finding, Severity
from app.scanners.account_scanner import (
    _check_cloudtrail_logging,
    scan_account,
)


def _account(account_id: str = "123456789012", **props) -> dict:
    """Build a minimal account-shaped topology node dict."""
    return {
        "id": account_id,
        "type": "account",
        "name": f"AWS Account {account_id}",
        "parent_id": None,
        "properties": props,
    }


# --- _check_cloudtrail_logging --------------------------------------------
class TestCheckCloudtrailLogging:

    def test_returns_finding_when_logging_disabled(self):
        finding = _check_cloudtrail_logging(
            _account(cloudtrail_logging_enabled=False)
        )
        assert finding is not None
        assert finding.finding_type_id == "ACCOUNT_CLOUDTRAIL_DISABLED"

    def test_returns_none_when_logging_enabled(self):
        finding = _check_cloudtrail_logging(
            _account(cloudtrail_logging_enabled=True)
        )
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        finding = _check_cloudtrail_logging(_account())
        assert finding is not None
        assert finding.finding_type_id == "ACCOUNT_CLOUDTRAIL_DISABLED"

    def test_finding_has_critical_severity_and_correct_shape(self):
        finding = _check_cloudtrail_logging(
            _account("999988887777", cloudtrail_logging_enabled=False)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.CRITICAL
        assert finding.resource_id == "999988887777"
        assert finding.title == "No active CloudTrail trail logging the account"
        assert len(finding.framework_references) > 0


# --- scan_account --------------------------------------------------------
class TestScanAccount:

    def test_returns_empty_list_when_topology_has_no_nodes_key(self):
        assert scan_account({}) == []

    def test_returns_empty_list_when_no_account_node_present(self):
        topology = {
            "nodes": [{"id": "i-1", "type": "ec2_instance", "properties": {}}]
        }
        assert scan_account(topology) == []

    def test_ignores_non_account_nodes(self):
        topology = {
            "nodes": [
                _account(cloudtrail_logging_enabled=False),
                {"id": "i-1", "type": "ec2_instance"},
            ]
        }
        findings = scan_account(topology)
        assert all(f.resource_id == "123456789012" for f in findings)

    def test_returns_zero_findings_when_cloudtrail_logging_enabled(self):
        topology = {
            "nodes": [_account(cloudtrail_logging_enabled=True)]
        }
        assert scan_account(topology) == []

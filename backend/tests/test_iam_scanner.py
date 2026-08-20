"""
Unit tests for app.scanners.iam_scanner.

Mirrors test_kms_scanner.py's structure, adjusted for the fact that
this scanner walks 'account' nodes rather than a list of resources —
there is at most one per topology.
"""

from app.models.finding import Finding, Severity
from app.scanners.iam_scanner import (
    _check_root_access_keys,
    _check_account_mfa,
    scan_iam,
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


# --- _check_root_access_keys ----------------------------------------------
class TestCheckRootAccessKeys:

    def test_returns_finding_when_root_keys_present(self):
        finding = _check_root_access_keys(
            _account(root_access_keys_present=True)
        )
        assert finding is not None
        assert finding.finding_type_id == "IAM_ROOT_ACCESS_KEYS_ACTIVE"

    def test_returns_none_when_root_keys_absent(self):
        finding = _check_root_access_keys(
            _account(root_access_keys_present=False)
        )
        assert finding is None

    def test_returns_none_when_property_missing(self):
        # Computed upstream from AccountAccessKeysPresent, where a
        # missing/zero count means zero keys, not unknown state.
        finding = _check_root_access_keys(_account())
        assert finding is None

    def test_finding_has_critical_severity_and_correct_shape(self):
        finding = _check_root_access_keys(
            _account("999988887777", root_access_keys_present=True)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.CRITICAL
        assert finding.resource_id == "999988887777"
        assert finding.title == "Root user has active access keys"
        assert len(finding.framework_references) > 0


# --- _check_account_mfa -----------------------------------------------
class TestCheckAccountMfa:

    def test_returns_finding_when_mfa_disabled(self):
        finding = _check_account_mfa(_account(account_mfa_enabled=False))
        assert finding is not None
        assert finding.finding_type_id == "IAM_ACCOUNT_MFA_NOT_ENABLED"

    def test_returns_none_when_mfa_enabled(self):
        finding = _check_account_mfa(_account(account_mfa_enabled=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # MFA status is a genuine protection signal, same fail-closed
        # semantic as encryption_enabled in the S3 scanner.
        finding = _check_account_mfa(_account())
        assert finding is not None
        assert finding.finding_type_id == "IAM_ACCOUNT_MFA_NOT_ENABLED"

    def test_finding_has_high_severity_and_correct_shape(self):
        finding = _check_account_mfa(
            _account("999988887777", account_mfa_enabled=False)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "999988887777"
        assert finding.title == "Root user does not have MFA enabled"
        assert len(finding.framework_references) > 0


# --- scan_iam ----------------------------------------------------------
class TestScanIam:

    def test_returns_empty_list_when_topology_has_no_nodes_key(self):
        assert scan_iam({}) == []

    def test_returns_empty_list_when_no_account_node_present(self):
        topology = {
            "nodes": [
                {"id": "i-1", "type": "ec2_instance", "properties": {}},
                {"id": "bucket-1", "type": "s3_bucket", "properties": {}},
            ]
        }
        assert scan_iam(topology) == []

    def test_ignores_non_account_nodes(self):
        topology = {
            "nodes": [
                _account(root_access_keys_present=True),
                {"id": "i-1", "type": "ec2_instance"},  # no properties dict
            ]
        }
        findings = scan_iam(topology)
        assert all(f.resource_id == "123456789012" for f in findings)

    def test_returns_zero_findings_for_clean_account(self):
        topology = {
            "nodes": [
                _account(
                    root_access_keys_present=False,
                    account_mfa_enabled=True,
                )
            ]
        }
        assert scan_iam(topology) == []

    def test_returns_two_findings_for_account_with_both_issues(self):
        # The flagship case: our mock's account, which has both no
        # MFA and active root keys. Both rules fire on the same
        # resource, mirroring the S3/KMS stacked-findings pattern.
        topology = {
            "nodes": [
                _account(
                    "123456789012",
                    root_access_keys_present=True,
                    account_mfa_enabled=False,
                )
            ]
        }
        findings = scan_iam(topology)
        assert len(findings) == 2
        assert all(f.resource_id == "123456789012" for f in findings)
        assert [f.finding_type_id for f in findings] == [
            "IAM_ROOT_ACCESS_KEYS_ACTIVE",
            "IAM_ACCOUNT_MFA_NOT_ENABLED",
        ]

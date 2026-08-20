"""
Unit tests for app.scanners.iam_scanner.

Mirrors test_kms_scanner.py's structure for the account-level rules,
adjusted for the fact that this scanner walks 'account' nodes rather
than a list of resources — there is at most one per topology. The
access-key-age rule walks 'iam_user' nodes instead, one per user,
the same shape as S3 buckets or KMS keys.
"""

from datetime import datetime, timedelta, timezone

from app.models.finding import Finding, Severity
from app.scanners.iam_scanner import (
    _check_root_access_keys,
    _check_account_mfa,
    _check_password_policy,
    _check_access_key_age,
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


def _iam_user(username: str = "test-user", access_keys=None) -> dict:
    """Build a minimal iam_user-shaped topology node dict."""
    return {
        "id": username,
        "type": "iam_user",
        "name": username,
        "parent_id": None,
        "properties": {"access_keys": access_keys or []},
    }


def _iso(dt: datetime) -> str:
    return dt.isoformat()


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


# --- _check_password_policy ---------------------------------------------
class TestCheckPasswordPolicy:

    def test_returns_finding_when_no_policy_configured(self):
        finding = _check_password_policy(
            _account(password_policy_min_length=None)
        )
        assert finding is not None
        assert finding.finding_type_id == "IAM_PASSWORD_POLICY_WEAK"

    def test_returns_finding_when_policy_too_short(self):
        finding = _check_password_policy(
            _account(password_policy_min_length=8)
        )
        assert finding is not None
        assert finding.finding_type_id == "IAM_PASSWORD_POLICY_WEAK"

    def test_returns_none_when_policy_meets_minimum(self):
        finding = _check_password_policy(
            _account(password_policy_min_length=14)
        )
        assert finding is None

    def test_returns_none_when_policy_exceeds_minimum(self):
        finding = _check_password_policy(
            _account(password_policy_min_length=20)
        )
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        finding = _check_password_policy(_account())
        assert finding is not None
        assert finding.finding_type_id == "IAM_PASSWORD_POLICY_WEAK"

    def test_finding_has_medium_severity_and_correct_shape(self):
        finding = _check_password_policy(
            _account("999988887777", password_policy_min_length=None)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.MEDIUM
        assert finding.resource_id == "999988887777"
        assert finding.title == "Account password policy is weak or missing"
        assert len(finding.framework_references) > 0


# --- _check_access_key_age ------------------------------------------------
class TestCheckAccessKeyAge:

    def test_returns_finding_when_active_key_older_than_90_days(self):
        old_date = datetime.now(timezone.utc) - timedelta(days=91)
        user = _iam_user(access_keys=[
            {"access_key_id": "AKIA1", "status": "Active", "create_date": _iso(old_date)}
        ])
        finding = _check_access_key_age(user)
        assert finding is not None
        assert finding.finding_type_id == "IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS"

    def test_returns_none_when_active_key_within_90_days(self):
        recent_date = datetime.now(timezone.utc) - timedelta(days=10)
        user = _iam_user(access_keys=[
            {"access_key_id": "AKIA1", "status": "Active", "create_date": _iso(recent_date)}
        ])
        assert _check_access_key_age(user) is None

    def test_ignores_old_inactive_key(self):
        # A deactivated key isn't a live credential, even if old —
        # only Active keys count.
        old_date = datetime.now(timezone.utc) - timedelta(days=365)
        user = _iam_user(access_keys=[
            {"access_key_id": "AKIA1", "status": "Inactive", "create_date": _iso(old_date)}
        ])
        assert _check_access_key_age(user) is None

    def test_returns_none_for_user_with_no_access_keys(self):
        assert _check_access_key_age(_iam_user(access_keys=[])) is None

    def test_returns_finding_when_create_date_unparseable_fail_closed(self):
        user = _iam_user(access_keys=[
            {"access_key_id": "AKIA1", "status": "Active", "create_date": "not-a-date"}
        ])
        finding = _check_access_key_age(user)
        assert finding is not None
        assert finding.finding_type_id == "IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS"

    def test_flags_user_if_any_one_of_several_keys_is_old(self):
        recent_date = datetime.now(timezone.utc) - timedelta(days=5)
        old_date = datetime.now(timezone.utc) - timedelta(days=200)
        user = _iam_user(access_keys=[
            {"access_key_id": "AKIA-NEW", "status": "Active", "create_date": _iso(recent_date)},
            {"access_key_id": "AKIA-OLD", "status": "Active", "create_date": _iso(old_date)},
        ])
        finding = _check_access_key_age(user)
        assert finding is not None

    def test_finding_has_medium_severity_and_correct_shape(self):
        old_date = datetime.now(timezone.utc) - timedelta(days=200)
        user = _iam_user(
            "legacy-svc-account",
            access_keys=[
                {"access_key_id": "AKIA1", "status": "Active", "create_date": _iso(old_date)}
            ],
        )
        finding = _check_access_key_age(user)
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.MEDIUM
        assert finding.resource_id == "legacy-svc-account"
        assert finding.title == "IAM access key older than 90 days"
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
                    password_policy_min_length=14,
                )
            ]
        }
        assert scan_iam(topology) == []

    def test_returns_three_findings_for_account_with_all_issues(self):
        # The flagship case: our mock's account, which has active
        # root keys, no MFA, and no password policy. All three rules
        # fire on the same resource, mirroring the S3/KMS
        # stacked-findings pattern.
        topology = {
            "nodes": [
                _account(
                    "123456789012",
                    root_access_keys_present=True,
                    account_mfa_enabled=False,
                    password_policy_min_length=None,
                )
            ]
        }
        findings = scan_iam(topology)
        assert len(findings) == 3
        assert all(f.resource_id == "123456789012" for f in findings)
        assert [f.finding_type_id for f in findings] == [
            "IAM_ROOT_ACCESS_KEYS_ACTIVE",
            "IAM_ACCOUNT_MFA_NOT_ENABLED",
            "IAM_PASSWORD_POLICY_WEAK",
        ]

    def test_dispatches_account_and_user_nodes_to_the_right_rules(self):
        # An account node and a user node in the same topology: each
        # must only be checked against its own rule group. If the
        # dispatch broke, a user node would either produce zero
        # findings (account rules silently skip it) or crash (user
        # rules called against an account node's shape).
        old_date = datetime.now(timezone.utc) - timedelta(days=200)
        topology = {
            "nodes": [
                _account(
                    root_access_keys_present=True,
                    account_mfa_enabled=True,
                    password_policy_min_length=20,
                ),
                _iam_user(
                    "legacy-svc-account",
                    access_keys=[
                        {
                            "access_key_id": "AKIA1",
                            "status": "Active",
                            "create_date": _iso(old_date),
                        }
                    ],
                ),
            ]
        }
        findings = scan_iam(topology)
        finding_type_ids = {f.finding_type_id for f in findings}
        assert finding_type_ids == {
            "IAM_ROOT_ACCESS_KEYS_ACTIVE",
            "IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS",
        }
        by_resource = {f.finding_type_id: f.resource_id for f in findings}
        assert by_resource["IAM_ROOT_ACCESS_KEYS_ACTIVE"] == "123456789012"
        assert by_resource["IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS"] == "legacy-svc-account"

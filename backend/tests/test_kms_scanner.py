"""
Unit tests for app.scanners.kms_scanner.

Mirrors test_s3_scanner.py's structure: one test class per rule
function, covering the happy path, the negative case, and fail-closed
behaviour on a missing property, plus a class for the top-level
scan_kms_keys walker.
"""

from app.models.finding import Finding, Severity
from app.scanners.kms_scanner import (
    _check_key_rotation,
    _check_pending_deletion,
    _check_has_alias,
    _check_key_policy_overly_broad,
    scan_kms_keys,
)


def _kms_key(key_id: str = "test-key", **props) -> dict:
    """Build a minimal kms_key-shaped topology node dict."""
    return {
        "id": key_id,
        "type": "kms_key",
        "name": key_id,
        "parent_id": None,
        "properties": props,
    }


# --- _check_key_rotation -------------------------------------------------
class TestCheckKeyRotation:

    def test_returns_finding_when_rotation_disabled(self):
        finding = _check_key_rotation(_kms_key(key_rotation_enabled=False))
        assert finding is not None
        assert finding.finding_type_id == "KMS_KEY_ROTATION_DISABLED"

    def test_returns_none_when_rotation_enabled(self):
        finding = _check_key_rotation(_kms_key(key_rotation_enabled=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # Rotation status is a *protection* signal, same fail-closed
        # semantic as encryption_enabled and versioning_enabled on
        # the S3 side. If we can't confirm rotation is on, flag it.
        finding = _check_key_rotation(_kms_key())
        assert finding is not None
        assert finding.finding_type_id == "KMS_KEY_ROTATION_DISABLED"

    def test_finding_has_high_severity_and_correct_shape(self):
        finding = _check_key_rotation(
            _kms_key("static-key-material", key_rotation_enabled=False)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "static-key-material"
        assert finding.title == "KMS key rotation not enabled"
        assert len(finding.framework_references) > 0


# --- _check_pending_deletion ----------------------------------------------
class TestCheckPendingDeletion:

    def test_returns_finding_when_state_is_pending_deletion(self):
        finding = _check_pending_deletion(_kms_key(key_state="PendingDeletion"))
        assert finding is not None
        assert finding.finding_type_id == "KMS_KEY_PENDING_DELETION"

    def test_returns_none_when_state_is_enabled(self):
        finding = _check_pending_deletion(_kms_key(key_state="Enabled"))
        assert finding is None

    def test_returns_none_when_property_missing(self):
        # key_state is a *detection* signal, not a protection signal.
        # Missing data means we didn't detect the dangerous state ->
        # no finding, same semantic as is_public_via_acl in the S3
        # scanner. We don't invent a pending deletion out of missing
        # data.
        finding = _check_pending_deletion(_kms_key())
        assert finding is None

    def test_finding_has_critical_severity_and_correct_shape(self):
        finding = _check_pending_deletion(
            _kms_key("doomed-key", key_state="PendingDeletion")
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.CRITICAL
        assert finding.resource_id == "doomed-key"
        assert finding.title == "KMS key scheduled for deletion"
        assert len(finding.framework_references) > 0


# --- _check_has_alias ------------------------------------------------
class TestCheckHasAlias:

    def test_returns_finding_when_no_alias(self):
        finding = _check_has_alias(_kms_key(has_alias=False))
        assert finding is not None
        assert finding.finding_type_id == "KMS_KEY_MISSING_ALIAS"

    def test_returns_none_when_alias_present(self):
        finding = _check_has_alias(_kms_key(has_alias=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # has_alias is a protection-adjacent signal, same fail-closed
        # semantic as key_rotation_enabled: if we can't confirm the
        # key has an alias, we don't assume it does.
        finding = _check_has_alias(_kms_key())
        assert finding is not None
        assert finding.finding_type_id == "KMS_KEY_MISSING_ALIAS"

    def test_finding_has_low_severity_and_correct_shape(self):
        finding = _check_has_alias(_kms_key("unlabelled-key", has_alias=False))
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.LOW
        assert finding.resource_id == "unlabelled-key"
        assert finding.title == "KMS key has no alias pointing to it"
        assert len(finding.framework_references) > 0


# --- _check_key_policy_overly_broad --------------------------------------
class TestCheckKeyPolicyOverlyBroad:

    def test_returns_finding_when_policy_overly_broad(self):
        finding = _check_key_policy_overly_broad(
            _kms_key(key_policy_overly_broad=True)
        )
        assert finding is not None
        assert finding.finding_type_id == "KMS_KEY_POLICY_OVERLY_BROAD"

    def test_returns_none_when_policy_not_overly_broad(self):
        finding = _check_key_policy_overly_broad(
            _kms_key(key_policy_overly_broad=False)
        )
        assert finding is None

    def test_returns_none_when_property_missing(self):
        # Detection signal, not a protection signal: missing/unparsed
        # policy data means we don't know, so we don't invent a
        # wildcard grant out of that absence, same semantic as
        # key_state.
        finding = _check_key_policy_overly_broad(_kms_key())
        assert finding is None

    def test_finding_has_high_severity_and_correct_shape(self):
        finding = _check_key_policy_overly_broad(
            _kms_key("wide-open-key", key_policy_overly_broad=True)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "wide-open-key"
        assert finding.title == "KMS key policy grants an unconditioned wildcard principal"
        assert len(finding.framework_references) > 0


# --- scan_kms_keys ---------------------------------------------------
class TestScanKmsKeys:

    def test_returns_empty_list_when_topology_has_no_nodes_key(self):
        assert scan_kms_keys({}) == []

    def test_returns_empty_list_when_no_kms_keys_present(self):
        topology = {
            "nodes": [
                {"id": "i-1", "type": "ec2_instance", "properties": {}},
                {"id": "bucket-1", "type": "s3_bucket", "properties": {}},
            ]
        }
        assert scan_kms_keys(topology) == []

    def test_ignores_non_kms_nodes(self):
        topology = {
            "nodes": [
                _kms_key("unrotated", key_rotation_enabled=False),
                {"id": "i-1", "type": "ec2_instance"},  # no properties dict
                {"id": "bucket-1", "type": "s3_bucket", "properties": {}},
            ]
        }
        findings = scan_kms_keys(topology)
        assert all(f.resource_id == "unrotated" for f in findings)

    def test_returns_zero_findings_for_rotated_key(self):
        topology = {
            "nodes": [
                _kms_key("rotated-key", key_rotation_enabled=True, has_alias=True)
            ]
        }
        assert scan_kms_keys(topology) == []

    def test_returns_two_findings_for_key_with_both_issues(self):
        # The flagship case: our mock's customer-managed key, which
        # both never had rotation enabled and has since been
        # scheduled for deletion. Both rules fire on the same
        # resource, mirroring the S3 scanner's stacked-findings
        # pattern on the uploads bucket. has_alias=True here since
        # this test is specifically about the rotation/deletion pair,
        # not the separate alias rule -- see TestCheckHasAlias for that.
        topology = {
            "nodes": [
                _kms_key(
                    "doomed-key",
                    key_rotation_enabled=False,
                    key_state="PendingDeletion",
                    has_alias=True,
                )
            ]
        }
        findings = scan_kms_keys(topology)
        assert len(findings) == 2
        assert all(f.resource_id == "doomed-key" for f in findings)
        assert [f.finding_type_id for f in findings] == [
            "KMS_KEY_ROTATION_DISABLED",
            "KMS_KEY_PENDING_DELETION",
        ]

    def test_scans_multiple_keys_independently(self):
        topology = {
            "nodes": [
                _kms_key("rotated", key_rotation_enabled=True, has_alias=True),
                _kms_key("unrotated", key_rotation_enabled=False, has_alias=True),
            ]
        }
        findings = scan_kms_keys(topology)
        assert len(findings) == 1
        assert findings[0].resource_id == "unrotated"
        assert findings[0].finding_type_id == "KMS_KEY_ROTATION_DISABLED"

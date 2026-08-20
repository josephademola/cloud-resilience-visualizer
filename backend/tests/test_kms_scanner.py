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
            "nodes": [_kms_key("rotated-key", key_rotation_enabled=True)]
        }
        assert scan_kms_keys(topology) == []

    def test_scans_multiple_keys_independently(self):
        topology = {
            "nodes": [
                _kms_key("rotated", key_rotation_enabled=True),
                _kms_key("unrotated", key_rotation_enabled=False),
            ]
        }
        findings = scan_kms_keys(topology)
        assert len(findings) == 1
        assert findings[0].resource_id == "unrotated"
        assert findings[0].finding_type_id == "KMS_KEY_ROTATION_DISABLED"

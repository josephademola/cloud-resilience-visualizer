"""
Unit tests for app.scanners.tagging_scanner.

Mirrors the other scanners' test structure: one test class per rule
function, plus a class for the top-level scan_tagging() walker. This
scanner spans three node types (s3_bucket, kms_key, iam_user) instead
of one, so the walker tests cover all three plus the non-taggable
types this scanner must ignore.
"""

from app.models.finding import Finding, Severity
from app.scanners.tagging_scanner import (
    _check_has_any_tags,
    scan_tagging,
)


def _resource(resource_id: str = "test-resource", node_type: str = "s3_bucket", **props) -> dict:
    """Build a minimal taggable-resource-shaped topology node dict."""
    return {
        "id": resource_id,
        "type": node_type,
        "name": resource_id,
        "parent_id": None,
        "properties": props,
    }


# --- _check_has_any_tags ----------------------------------------------
class TestCheckHasAnyTags:

    def test_returns_finding_when_no_tags(self):
        finding = _check_has_any_tags(_resource(has_any_tags=False))
        assert finding is not None
        assert finding.finding_type_id == "RESOURCE_MISSING_TAGS"

    def test_returns_none_when_tagged(self):
        finding = _check_has_any_tags(_resource(has_any_tags=True))
        assert finding is None

    def test_returns_finding_when_property_missing(self):
        # A resource with zero tags never appears in the tagging
        # API's response at all -- this is a plain membership fact,
        # not a missing-data judgment call, so absence resolves the
        # same way an explicit False does.
        finding = _check_has_any_tags(_resource())
        assert finding is not None
        assert finding.finding_type_id == "RESOURCE_MISSING_TAGS"

    def test_finding_has_low_severity_and_correct_shape(self):
        finding = _check_has_any_tags(
            _resource("orphaned-bucket", has_any_tags=False)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.LOW
        assert finding.resource_id == "orphaned-bucket"
        assert finding.title == "Resource has no tags"
        assert len(finding.framework_references) > 0


# --- scan_tagging -------------------------------------------------------
class TestScanTagging:

    def test_returns_empty_list_when_topology_has_no_nodes_key(self):
        assert scan_tagging({}) == []

    def test_returns_empty_list_when_no_taggable_resources_present(self):
        topology = {
            "nodes": [
                {"id": "vpc-1", "type": "vpc", "properties": {}},
                {"id": "acc-1", "type": "account", "properties": {}},
            ]
        }
        assert scan_tagging(topology) == []

    def test_ignores_non_taggable_node_types(self):
        topology = {
            "nodes": [
                _resource("untagged-bucket", "s3_bucket", has_any_tags=False),
                {"id": "vpc-1", "type": "vpc", "properties": {}},
                {"id": "i-1", "type": "ec2_instance"},  # no properties dict
            ]
        }
        findings = scan_tagging(topology)
        assert all(f.resource_id == "untagged-bucket" for f in findings)

    def test_checks_all_three_taggable_resource_types(self):
        topology = {
            "nodes": [
                _resource("bucket-1", "s3_bucket", has_any_tags=False),
                _resource("key-1", "kms_key", has_any_tags=False),
                _resource("user-1", "iam_user", has_any_tags=False),
            ]
        }
        findings = scan_tagging(topology)
        assert {f.resource_id for f in findings} == {"bucket-1", "key-1", "user-1"}
        assert all(f.finding_type_id == "RESOURCE_MISSING_TAGS" for f in findings)

    def test_returns_zero_findings_when_everything_is_tagged(self):
        topology = {
            "nodes": [
                _resource("bucket-1", "s3_bucket", has_any_tags=True),
                _resource("key-1", "kms_key", has_any_tags=True),
                _resource("user-1", "iam_user", has_any_tags=True),
            ]
        }
        assert scan_tagging(topology) == []

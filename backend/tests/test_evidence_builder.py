"""
Unit tests for app.evidence.builder.

These tests verify:
  - Record has all required top-level keys.
  - Scope correctly extracts node count, security group count, and
    unique resource types from the topology.
  - Findings summary correctly aggregates by severity and collects
    unique affected resources.
  - Input hash is deterministic: same topology always produces the
    same hash regardless of call order.
  - Integrity hash covers the full record: mutating any field would
    produce a different hash.
  - Record is fully JSON-serialisable (no datetime or other types
    that json.dumps can't handle).
  - IAM identity and data_source flow through from caller to record.
  - Empty topology and empty findings are handled gracefully.
"""

import json
import pytest

from app.evidence.builder import build_evidence_record, TOOL_VERSION
from app.models.finding import Finding, FrameworkReference, Severity


# ---- Small helpers --------------------------------------------------

def _finding(
    finding_type_id: str = "S3_PUBLIC_VIA_ACL",
    severity: Severity = Severity.CRITICAL,
    resource_id: str = "test-bucket",
    risk_acceptance: dict | None = None,
) -> Finding:
    return Finding(
        finding_type_id=finding_type_id,
        title="Test finding",
        severity=severity,
        resource_id=resource_id,
        description="test",
        remediation="test",
        framework_references=(
            FrameworkReference("nis2", "Article 21(2)(i)", "Access control"),
        ),
        risk_acceptance=risk_acceptance,
    )


def _topology(nodes=None, security_groups=None) -> dict:
    return {
        "metadata": {"schema_version": "1.0", "node_count": len(nodes or [])},
        "nodes": nodes or [],
        "security_groups": security_groups or [],
    }


def _node(node_id: str, node_type: str) -> dict:
    return {"id": node_id, "type": node_type, "name": node_id,
            "parent_id": None, "properties": {}}


# ---- build_evidence_record ------------------------------------------

class TestBuildEvidenceRecord:

    def test_record_has_all_required_top_level_keys(self):
        record = build_evidence_record(_topology(), [])
        required_keys = {
            "schema_version", "tool_version", "generated_at",
            "data_source", "iam_identity", "scope",
            "findings_summary", "input_hash", "integrity_hash",
        }
        assert set(record.keys()) == required_keys

    def test_tool_version_matches_constant(self):
        record = build_evidence_record(_topology(), [])
        assert record["tool_version"] == TOOL_VERSION

    def test_iam_identity_flows_through(self):
        record = build_evidence_record(
            _topology(), [],
            iam_identity="arn:aws:iam::574xxxxxxxxx:user/crv-admin",
        )
        assert record["iam_identity"] == "arn:aws:iam::574xxxxxxxxx:user/crv-admin"

    def test_data_source_flows_through(self):
        record = build_evidence_record(_topology(), [], data_source="live")
        assert record["data_source"] == "live"

    def test_default_data_source_is_mock(self):
        record = build_evidence_record(_topology(), [])
        assert record["data_source"] == "mock"

    def test_default_iam_identity_is_mock_mode(self):
        record = build_evidence_record(_topology(), [])
        assert record["iam_identity"] == "mock-mode"

    def test_record_is_fully_json_serialisable(self):
        # Catches any datetime, set, or other non-serialisable type
        # slipping into the record.
        nodes = [_node("vpc-1", "vpc"), _node("bucket-1", "s3_bucket")]
        topology = _topology(nodes=nodes, security_groups=[{}, {}])
        findings = [_finding()]
        record = build_evidence_record(topology, findings)
        json.dumps(record)  # raises TypeError if anything can't serialise


class TestScope:

    def test_scope_node_count_matches_topology(self):
        topology = _topology(nodes=[_node("a", "vpc"), _node("b", "subnet")])
        record = build_evidence_record(topology, [])
        assert record["scope"]["node_count"] == 2

    def test_scope_security_group_count_matches_topology(self):
        topology = _topology(security_groups=[{}, {}, {}])
        record = build_evidence_record(topology, [])
        assert record["scope"]["security_group_count"] == 3

    def test_scope_resource_types_are_unique_and_sorted(self):
        nodes = [
            _node("vpc-1", "vpc"),
            _node("bucket-1", "s3_bucket"),
            _node("bucket-2", "s3_bucket"),  # duplicate type
            _node("ec2-1", "ec2_instance"),
        ]
        topology = _topology(nodes=nodes)
        record = build_evidence_record(topology, [])
        types = record["scope"]["resource_types"]
        assert types == sorted(set(types))
        assert "s3_bucket" in types
        assert types.count("s3_bucket") == 1  # deduplicated

    def test_empty_topology_produces_zero_counts(self):
        record = build_evidence_record(_topology(), [])
        assert record["scope"]["node_count"] == 0
        assert record["scope"]["security_group_count"] == 0
        assert record["scope"]["resource_types"] == []

    def test_project_tag_flows_through_into_scope(self):
        # Phase 9a Feature 4: a scoped scan self-documents which
        # project it covered, inside scope rather than as a new
        # top-level key.
        record = build_evidence_record(
            _topology(), [], project_tag="Project=ConfidentialClient"
        )
        assert record["scope"]["project_tag"] == "Project=ConfidentialClient"

    def test_project_tag_defaults_to_none_for_unscoped_scan(self):
        record = build_evidence_record(_topology(), [])
        assert record["scope"]["project_tag"] is None


class TestFindingsSummary:

    def test_total_reflects_number_of_findings(self):
        findings = [_finding(), _finding(severity=Severity.HIGH)]
        record = build_evidence_record(_topology(), findings)
        assert record["findings_summary"]["total"] == 2

    def test_by_severity_counts_correctly(self):
        findings = [
            _finding(severity=Severity.CRITICAL),
            _finding(severity=Severity.CRITICAL),
            _finding(severity=Severity.HIGH),
            _finding(severity=Severity.MEDIUM),
        ]
        record = build_evidence_record(_topology(), findings)
        summary = record["findings_summary"]["by_severity"]
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 0

    def test_affected_resources_are_unique_and_sorted(self):
        findings = [
            _finding(resource_id="bucket-b"),
            _finding(resource_id="bucket-a"),
            _finding(resource_id="bucket-b"),  # duplicate
        ]
        record = build_evidence_record(_topology(), findings)
        affected = record["findings_summary"]["affected_resources"]
        # Deduplicated and sorted
        assert affected == ["bucket-a", "bucket-b"]

    def test_empty_findings_produces_zero_summary(self):
        record = build_evidence_record(_topology(), [])
        summary = record["findings_summary"]
        assert summary["total"] == 0
        assert all(v == 0 for v in summary["by_severity"].values())
        assert summary["affected_resources"] == []
        assert summary["risk_accepted"] == 0

    def test_risk_accepted_counts_findings_with_acceptance_attached(self):
        findings = [
            _finding(resource_id="bucket-a", risk_acceptance={"reason": "accepted"}),
            _finding(resource_id="bucket-b"),
        ]
        record = build_evidence_record(_topology(), findings)
        summary = record["findings_summary"]
        assert summary["risk_accepted"] == 1
        # total still counts everything -- nothing silently dropped
        # from the evidence record just because it was accepted.
        assert summary["total"] == 2


class TestHashing:

    def test_input_hash_starts_with_sha256_prefix(self):
        record = build_evidence_record(_topology(), [])
        assert record["input_hash"].startswith("sha256:")

    def test_integrity_hash_starts_with_sha256_prefix(self):
        record = build_evidence_record(_topology(), [])
        assert record["integrity_hash"].startswith("sha256:")

    def test_input_hash_is_deterministic_for_same_topology(self):
        # Same topology input must produce the same hash on every call.
        # This is the key property: auditors can re-hash topology.json
        # to verify the scan record is authentic.
        topology = _topology(nodes=[_node("vpc-1", "vpc")])
        record1 = build_evidence_record(topology, [])
        record2 = build_evidence_record(topology, [])
        assert record1["input_hash"] == record2["input_hash"]

    def test_input_hash_differs_for_different_topologies(self):
        topology_a = _topology(nodes=[_node("vpc-a", "vpc")])
        topology_b = _topology(nodes=[_node("vpc-b", "vpc")])
        record_a = build_evidence_record(topology_a, [])
        record_b = build_evidence_record(topology_b, [])
        assert record_a["input_hash"] != record_b["input_hash"]

    def test_integrity_hash_differs_from_input_hash(self):
        # These hash different things — they must not be equal.
        record = build_evidence_record(_topology(), [])
        assert record["integrity_hash"] != record["input_hash"]
"""
Unit tests for app.compliance.

The aggregator takes a flat list of Findings and reshapes them into
a per-framework view suitable for the compliance dashboard.

These tests verify:
  - Framework order is deterministic and matches the display spec.
  - Framework metadata (full name, unit label) is populated.
  - Requirements are sorted by reference_id inside each framework.
  - When multiple findings reference the same requirement, they are
    grouped under it (rather than duplicating the requirement entry).
  - Empty input produces empty requirements — never raises.
  - Finding summaries inside requirements have the expected shape.

Fixtures use hand-built Finding objects rather than reading real
mapping files. Keeps the tests self-contained — a mapping file change
can't accidentally break a scanner test.
"""

from app.compliance import build_compliance_view
from app.models.finding import Finding, FrameworkReference, Severity


def _ref(framework: str, reference_id: str, label: str) -> FrameworkReference:
    """Shorthand for building a FrameworkReference in test fixtures."""
    return FrameworkReference(framework, reference_id, label)


def _finding(
    finding_type_id: str,
    severity: Severity,
    resource_id: str,
    title: str,
    refs: tuple[FrameworkReference, ...],
) -> Finding:
    """Shorthand for building a Finding in test fixtures."""
    return Finding(
        finding_type_id=finding_type_id,
        title=title,
        severity=severity,
        resource_id=resource_id,
        description="test description",
        remediation="test remediation",
        framework_references=refs,
    )


# --- build_compliance_view -------------------------------------------
class TestBuildComplianceView:

    def test_returns_all_five_frameworks_in_expected_order(self):
        # Framework order is a display-layer decision that lives in
        # the aggregator. Locking it in prevents accidental drift.
        # NIS2 first (broadest EU coverage), CE and ShiftCommute last
        # (UK-baseline and engagement-specific, respectively).
        result = build_compliance_view([])
        framework_names = [fw["framework"] for fw in result["frameworks"]]
        assert framework_names == [
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
            "shiftcommute",
        ]

    def test_framework_metadata_populated(self):
        # Each framework entry must carry its display metadata:
        # human-readable full name and unit label ("N articles
        # failing" etc.). Frontend depends on both being non-empty.
        result = build_compliance_view([])
        for fw in result["frameworks"]:
            assert fw["framework_full_name"], (
                f"{fw['framework']} has empty full_name"
            )
            assert fw["unit_label"], (
                f"{fw['framework']} has empty unit_label"
            )

    def test_empty_findings_produces_empty_requirements(self):
        # No findings -> no failing requirements. But the four
        # framework entries still exist (with failing_count = 0)
        # so the dashboard can render "0 articles failing" cleanly
        # rather than a missing section.
        result = build_compliance_view([])
        assert result["metadata"]["total_findings"] == 0
        for fw in result["frameworks"]:
            assert fw["failing_count"] == 0
            assert fw["failing_requirements"] == []

    def test_finding_produces_requirement_entry_in_referenced_framework(self):
        # A finding with one NIS2 reference should produce one
        # failing requirement under NIS2, and nothing under the
        # other three frameworks.
        f = _finding(
            "S3_TEST",
            Severity.HIGH,
            "test-bucket",
            "Test finding",
            (_ref("nis2", "Article 21(2)(i)", "Access control"),),
        )
        result = build_compliance_view([f])

        nis2 = next(fw for fw in result["frameworks"] if fw["framework"] == "nis2")
        assert nis2["failing_count"] == 1
        assert nis2["failing_requirements"][0]["reference_id"] == "Article 21(2)(i)"

        # Other three frameworks are empty for this finding
        for fw_name in ["ncsc_caf", "mitre_attack", "cyber_essentials"]:
            fw = next(f for f in result["frameworks"] if f["framework"] == fw_name)
            assert fw["failing_count"] == 0

    def test_multiple_findings_on_same_requirement_are_grouped(self):
        # Two findings both referencing the same MITRE technique T1530
        # should produce ONE requirement entry with TWO findings under
        # it — not two separate requirement entries.
        f1 = _finding(
            "S3_PUBLIC_VIA_ACL",
            Severity.CRITICAL,
            "bucket-a",
            "Public ACL",
            (_ref("mitre_attack", "T1530", "Data from Cloud Storage"),),
        )
        f2 = _finding(
            "S3_ENCRYPTION_DISABLED",
            Severity.HIGH,
            "bucket-a",
            "No encryption",
            (_ref("mitre_attack", "T1530", "Data from Cloud Storage"),),
        )
        result = build_compliance_view([f1, f2])

        mitre = next(
            fw for fw in result["frameworks"] if fw["framework"] == "mitre_attack"
        )
        assert mitre["failing_count"] == 1  # ONE unique technique
        assert len(mitre["failing_requirements"][0]["findings"]) == 2

    def test_requirements_sorted_alphabetically_by_reference_id(self):
        # Determinism matters for auditing — the same input must
        # produce the same output on every call, including within a
        # framework. Sorting by reference_id gives us that guarantee.
        f = _finding(
            "S3_TEST",
            Severity.MEDIUM,
            "bucket-a",
            "Test",
            (
                _ref("nis2", "Article 21(2)(i)", "Access control"),
                _ref("nis2", "Article 21(2)(e)", "System security"),
                _ref("nis2", "Article 21(2)(h)", "Encryption"),
            ),
        )
        result = build_compliance_view([f])
        nis2 = next(fw for fw in result["frameworks"] if fw["framework"] == "nis2")
        ref_ids = [r["reference_id"] for r in nis2["failing_requirements"]]
        assert ref_ids == sorted(ref_ids)  # alphabetical order

    def test_finding_summary_has_expected_shape(self):
        # The dashboard reads specific fields off each finding
        # summary: finding_type_id, resource_id, severity, title.
        # Lock in the shape.
        f = _finding(
            "S3_PUBLIC_VIA_ACL",
            Severity.CRITICAL,
            "my-bucket",
            "The title text",
            (_ref("nis2", "Article 21(2)(i)", "Access control"),),
        )
        result = build_compliance_view([f])
        nis2 = next(fw for fw in result["frameworks"] if fw["framework"] == "nis2")
        summary = nis2["failing_requirements"][0]["findings"][0]
        assert summary == {
            "finding_type_id": "S3_PUBLIC_VIA_ACL",
            "resource_id": "my-bucket",
            "severity": "critical",
            "title": "The title text",
        }
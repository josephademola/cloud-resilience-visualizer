"""
Unit tests for app.risk_acceptance.

Covers the three public functions:
    - load_risk_acceptances: file-tolerant loading
    - find_acceptance: matching + expiry logic
    - apply_risk_acceptances: attaching acceptance metadata to findings
      without ever removing or hiding one
"""

from datetime import date

from app.models.finding import Finding, Severity
from app.risk_acceptance import (
    load_risk_acceptances,
    find_acceptance,
    apply_risk_acceptances,
)


def _finding(
    finding_type_id: str = "S3_VERSIONING_DISABLED",
    resource_id: str = "test-bucket",
) -> Finding:
    return Finding(
        finding_type_id=finding_type_id,
        title="Test finding",
        severity=Severity.MEDIUM,
        resource_id=resource_id,
        description="test",
        remediation="test",
    )


def _acceptance(
    finding_type_id: str = "S3_VERSIONING_DISABLED",
    resource_id: str = "test-bucket",
    reason: str = "Bucket is being decommissioned",
    accepted_by: str = "Jane Doe",
    accepted_date: str = "2026-01-01",
    expires: str | None = None,
) -> dict:
    return {
        "finding_type_id": finding_type_id,
        "resource_id": resource_id,
        "reason": reason,
        "accepted_by": accepted_by,
        "accepted_date": accepted_date,
        "expires": expires,
    }


# --- load_risk_acceptances ----------------------------------------------
class TestLoadRiskAcceptances:

    def test_returns_empty_list_when_file_missing(self, tmp_path):
        missing_path = tmp_path / "does-not-exist.json"
        assert load_risk_acceptances(missing_path) == []

    def test_returns_acceptances_from_file(self, tmp_path):
        path = tmp_path / "risk_acceptances.json"
        path.write_text(
            '{"acceptances": [{"finding_type_id": "X", "resource_id": "Y"}]}',
            encoding="utf-8",
        )
        result = load_risk_acceptances(path)
        assert result == [{"finding_type_id": "X", "resource_id": "Y"}]

    def test_returns_empty_list_when_acceptances_key_missing(self, tmp_path):
        path = tmp_path / "risk_acceptances.json"
        path.write_text('{"_meta": {}}', encoding="utf-8")
        assert load_risk_acceptances(path) == []

    def test_raises_on_malformed_json(self, tmp_path):
        # A present-but-broken file is a real configuration error --
        # surfaced loudly, not swallowed as "zero acceptances".
        path = tmp_path / "risk_acceptances.json"
        path.write_text("not valid json", encoding="utf-8")
        import pytest
        with pytest.raises(Exception):
            load_risk_acceptances(path)


# --- find_acceptance ------------------------------------------------------
class TestFindAcceptance:

    def test_returns_none_for_no_acceptances(self):
        assert find_acceptance("X", "Y", []) is None

    def test_matches_exact_finding_type_and_resource(self):
        acceptances = [_acceptance()]
        result = find_acceptance("S3_VERSIONING_DISABLED", "test-bucket", acceptances)
        assert result is not None
        assert result["accepted_by"] == "Jane Doe"

    def test_returns_none_when_finding_type_does_not_match(self):
        acceptances = [_acceptance(finding_type_id="S3_VERSIONING_DISABLED")]
        assert find_acceptance("S3_LOGGING_DISABLED", "test-bucket", acceptances) is None

    def test_returns_none_when_resource_does_not_match(self):
        acceptances = [_acceptance(resource_id="other-bucket")]
        assert find_acceptance("S3_VERSIONING_DISABLED", "test-bucket", acceptances) is None

    def test_wildcard_resource_matches_any_resource(self):
        acceptances = [_acceptance(resource_id="*")]
        result = find_acceptance("S3_VERSIONING_DISABLED", "any-bucket-at-all", acceptances)
        assert result is not None

    def test_returns_none_when_expired(self):
        acceptances = [_acceptance(expires="2026-01-01")]
        result = find_acceptance(
            "S3_VERSIONING_DISABLED", "test-bucket", acceptances,
            today=date(2026, 6, 1),
        )
        assert result is None

    def test_returns_acceptance_when_not_yet_expired(self):
        acceptances = [_acceptance(expires="2026-12-31")]
        result = find_acceptance(
            "S3_VERSIONING_DISABLED", "test-bucket", acceptances,
            today=date(2026, 6, 1),
        )
        assert result is not None

    def test_returns_acceptance_when_expiry_is_today(self):
        acceptances = [_acceptance(expires="2026-06-01")]
        result = find_acceptance(
            "S3_VERSIONING_DISABLED", "test-bucket", acceptances,
            today=date(2026, 6, 1),
        )
        assert result is not None

    def test_indefinite_when_expires_is_none(self):
        acceptances = [_acceptance(expires=None)]
        result = find_acceptance(
            "S3_VERSIONING_DISABLED", "test-bucket", acceptances,
            today=date(2099, 1, 1),
        )
        assert result is not None

    def test_treats_unparseable_expiry_as_expired(self):
        acceptances = [_acceptance(expires="not-a-date")]
        result = find_acceptance("S3_VERSIONING_DISABLED", "test-bucket", acceptances)
        assert result is None


# --- apply_risk_acceptances ------------------------------------------------
class TestApplyRiskAcceptances:

    def test_returns_same_findings_when_no_acceptances(self):
        findings = [_finding()]
        result = apply_risk_acceptances(findings, [])
        assert result == findings

    def test_attaches_acceptance_to_matching_finding(self):
        findings = [_finding()]
        acceptances = [_acceptance()]
        result = apply_risk_acceptances(findings, acceptances)
        assert result[0].risk_acceptance is not None
        assert result[0].risk_acceptance["accepted_by"] == "Jane Doe"
        assert result[0].risk_acceptance["reason"] == "Bucket is being decommissioned"

    def test_leaves_non_matching_finding_untouched(self):
        findings = [_finding(resource_id="unrelated-bucket")]
        acceptances = [_acceptance(resource_id="test-bucket")]
        result = apply_risk_acceptances(findings, acceptances)
        assert result[0].risk_acceptance is None

    def test_never_removes_a_finding(self):
        # The core auditability guarantee: accepted findings stay in
        # the list, just annotated -- never filtered out here.
        findings = [_finding(), _finding(resource_id="other-bucket")]
        acceptances = [_acceptance()]
        result = apply_risk_acceptances(findings, acceptances)
        assert len(result) == 2

    def test_original_finding_object_is_not_mutated(self):
        # Finding is frozen -- apply_risk_acceptances must produce a
        # new object via dataclasses.replace, never mutate in place.
        original = _finding()
        apply_risk_acceptances([original], [_acceptance()])
        assert original.risk_acceptance is None

    def test_expired_acceptance_leaves_finding_active(self):
        findings = [_finding()]
        acceptances = [_acceptance(expires="2020-01-01")]
        result = apply_risk_acceptances(findings, acceptances, today=date(2026, 1, 1))
        assert result[0].risk_acceptance is None

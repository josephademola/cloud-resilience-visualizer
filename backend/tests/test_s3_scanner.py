"""
Unit tests for app.scanners.s3_scanner.

Each rule function (_check_public_via_acl, _check_public_access_block,
_check_encryption) gets its own test class that verifies:
  - Happy path: config that violates the rule produces a Finding with
    the correct shape (severity, title, resource_id, framework refs).
  - Negative case: config that satisfies the rule returns None, not a
    Finding.
  - Defensive behaviour: missing property is treated per the rule's
    fail-open / fail-closed semantic (see s3_scanner module docstring
    for the distinction).

A separate class covers scan_s3_buckets — the top-level walker that
loops over topology nodes and stitches per-rule results together.

Fixtures are small hand-built bucket dicts, in the same style as the
normalizer tests. The scanner reads real mapping files via the loader
(no mocking) — this is deliberate: we want tests to fail loudly if
the loader-to-scanner integration breaks.
"""

from app.models.finding import Finding, Severity
from app.scanners.s3_scanner import (
    _check_public_via_acl,
    _check_public_access_block,
    _check_encryption,
    _check_versioning,
    _check_logging,
    _check_lifecycle,
    scan_s3_buckets,
)


# --- Small helper for building bucket fixtures -----------------------
# Each rule cares about ONE property, but the bucket needs an id and
# a properties dict for the code to work. This helper keeps the
# individual tests focused on what they're actually asserting.

def _bucket(bucket_id: str = "test-bucket", **props) -> dict:
    """Build a minimal bucket-shaped dict with the given properties."""
    return {
        "id": bucket_id,
        "type": "s3_bucket",
        "name": bucket_id,
        "parent_id": None,
        "properties": props,
    }


# --- _check_public_via_acl -------------------------------------------
class TestCheckPublicViaAcl:

    def test_returns_finding_when_bucket_is_public_via_acl(self):
        # The rule fires when is_public_via_acl is True. This is the
        # canonical S3 leak case — an AllUsers ACL grant.
        finding = _check_public_via_acl(_bucket(is_public_via_acl=True))
        assert finding is not None
        assert finding.finding_type_id == "S3_PUBLIC_VIA_ACL"

    def test_returns_none_when_bucket_is_not_public_via_acl(self):
        # A properly-configured bucket has is_public_via_acl False.
        # Rule should stay silent — no Finding produced.
        finding = _check_public_via_acl(_bucket(is_public_via_acl=False))
        assert finding is None

    def test_returns_none_when_property_missing(self):
        # is_public_via_acl is a *detection* signal, not a protection
        # signal. Missing data means we didn't detect anything -> no
        # finding. We don't invent problems out of missing data.
        finding = _check_public_via_acl(_bucket())
        assert finding is None

    def test_finding_has_critical_severity_and_correct_shape(self):
        # Full shape assertion for the happy path: severity is
        # CRITICAL (public data leak), resource_id echoes the bucket,
        # framework references are populated by the loader.
        finding = _check_public_via_acl(
            _bucket("mycompany-leak", is_public_via_acl=True)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.CRITICAL
        assert finding.resource_id == "mycompany-leak"
        assert finding.title == "Bucket publicly readable via legacy ACL"
        # Framework references must have been stitched in — an empty
        # list here would indicate the loader is broken or the
        # mapping file lost this finding type.
        assert len(finding.framework_references) > 0


# --- _check_public_access_block --------------------------------------
class TestCheckPublicAccessBlock:

    def test_returns_finding_when_pab_not_fully_enabled(self):
        # Even one PAB flag being off means "not fully enabled" and
        # the safety net has a hole. Rule fires.
        finding = _check_public_access_block(
            _bucket(public_access_block_fully_enabled=False)
        )
        assert finding is not None
        assert finding.finding_type_id == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"

    def test_returns_none_when_pab_fully_enabled(self):
        finding = _check_public_access_block(
            _bucket(public_access_block_fully_enabled=True)
        )
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # PAB is a *protection* signal. Missing data means we can't
        # confirm the protection is on -> assume it isn't -> flag it.
        # Fail-closed matches how production CSPM tools (Prowler,
        # ScoutSuite) treat missing protection state.
        finding = _check_public_access_block(_bucket())
        assert finding is not None
        assert finding.finding_type_id == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"

    def test_finding_has_medium_severity_and_correct_shape(self):
        # PAB disabled is Medium, not Critical: it's a weakness of
        # the safety net, not an active leak. A publicly-readable
        # bucket without PAB is worse than PAB disabled alone.
        finding = _check_public_access_block(
            _bucket("weak-safety-net", public_access_block_fully_enabled=False)
        )
        assert finding.severity == Severity.MEDIUM
        assert finding.resource_id == "weak-safety-net"
        assert finding.title == "S3 Public Access Block not fully enabled"
        assert len(finding.framework_references) > 0


# --- _check_encryption -----------------------------------------------
class TestCheckEncryption:

    def test_returns_finding_when_encryption_disabled(self):
        finding = _check_encryption(_bucket(encryption_enabled=False))
        assert finding is not None
        assert finding.finding_type_id == "S3_ENCRYPTION_DISABLED"

    def test_returns_none_when_encryption_enabled(self):
        finding = _check_encryption(_bucket(encryption_enabled=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # Encryption is a *protection* signal — same fail-closed
        # semantic as PAB. If we can't verify encryption is on, we
        # can't assume it is. Flag it and let the user check.
        finding = _check_encryption(_bucket())
        assert finding is not None
        assert finding.finding_type_id == "S3_ENCRYPTION_DISABLED"

    def test_finding_has_high_severity_and_correct_shape(self):
        # Encryption off is High: data at rest is unencrypted, but
        # not directly exposed to the internet the way an AllUsers
        # grant is. Critical is reserved for active exposure.
        finding = _check_encryption(
            _bucket("plaintext-bucket", encryption_enabled=False)
        )
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "plaintext-bucket"
        assert finding.title == "Server-side encryption not configured"
        assert len(finding.framework_references) > 0


# --- _check_versioning -------------------------------------------------
class TestCheckVersioning:

    def test_returns_finding_when_versioning_disabled(self):
        finding = _check_versioning(_bucket(versioning_enabled=False))
        assert finding is not None
        assert finding.finding_type_id == "S3_VERSIONING_DISABLED"

    def test_returns_none_when_versioning_enabled(self):
        finding = _check_versioning(_bucket(versioning_enabled=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # Versioning is a *protection* signal, same fail-closed
        # semantic as encryption and PAB. If we can't verify
        # versioning is on, we can't assume it is.
        finding = _check_versioning(_bucket())
        assert finding is not None
        assert finding.finding_type_id == "S3_VERSIONING_DISABLED"

    def test_finding_has_medium_severity_and_correct_shape(self):
        finding = _check_versioning(
            _bucket("no-recovery-bucket", versioning_enabled=False)
        )
        assert finding.severity == Severity.MEDIUM
        assert finding.resource_id == "no-recovery-bucket"
        assert finding.title == "Bucket versioning not enabled"
        assert len(finding.framework_references) > 0


# --- _check_logging ----------------------------------------------------
class TestCheckLogging:

    def test_returns_finding_when_logging_disabled(self):
        finding = _check_logging(_bucket(logging_enabled=False))
        assert finding is not None
        assert finding.finding_type_id == "S3_LOGGING_DISABLED"

    def test_returns_none_when_logging_enabled(self):
        finding = _check_logging(_bucket(logging_enabled=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # Logging is a *protection* signal — same fail-closed
        # semantic as versioning, encryption, and PAB.
        finding = _check_logging(_bucket())
        assert finding is not None
        assert finding.finding_type_id == "S3_LOGGING_DISABLED"

    def test_finding_has_low_severity_and_correct_shape(self):
        finding = _check_logging(
            _bucket("no-audit-trail-bucket", logging_enabled=False)
        )
        assert finding.severity == Severity.LOW
        assert finding.resource_id == "no-audit-trail-bucket"
        assert finding.title == "S3 access logging not enabled"
        assert len(finding.framework_references) > 0


# --- _check_lifecycle ---------------------------------------------------
class TestCheckLifecycle:

    def test_returns_finding_when_lifecycle_not_configured(self):
        finding = _check_lifecycle(_bucket(lifecycle_configured=False))
        assert finding is not None
        assert finding.finding_type_id == "S3_LIFECYCLE_MISSING"

    def test_returns_none_when_lifecycle_configured(self):
        finding = _check_lifecycle(_bucket(lifecycle_configured=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        finding = _check_lifecycle(_bucket())
        assert finding is not None
        assert finding.finding_type_id == "S3_LIFECYCLE_MISSING"

    def test_finding_has_low_severity_and_correct_shape(self):
        finding = _check_lifecycle(
            _bucket("unbounded-retention-bucket", lifecycle_configured=False)
        )
        assert finding.severity == Severity.LOW
        assert finding.resource_id == "unbounded-retention-bucket"
        assert finding.title == "S3 lifecycle policy not configured"
        assert len(finding.framework_references) > 0


# --- scan_s3_buckets -------------------------------------------------
class TestScanS3Buckets:

    def test_returns_empty_list_when_topology_has_no_nodes_key(self):
        # Defensive against a malformed topology. scanner never raises.
        assert scan_s3_buckets({}) == []

    def test_returns_empty_list_when_no_s3_buckets_present(self):
        # A topology of EC2 and RDS only should produce zero findings.
        topology = {
            "nodes": [
                {"id": "i-1", "type": "ec2_instance", "properties": {}},
                {"id": "db-1", "type": "rds_instance", "properties": {}},
            ]
        }
        assert scan_s3_buckets(topology) == []

    def test_ignores_non_s3_nodes(self):
        # A topology with a mix of S3 and non-S3 nodes should only
        # produce findings for the S3 ones. Non-S3 nodes with
        # missing/weird properties must not cause crashes.
        topology = {
            "nodes": [
                _bucket("leaky", is_public_via_acl=True),
                {"id": "i-1", "type": "ec2_instance"},  # no properties dict
                {"id": "vpc-1", "type": "vpc", "properties": {}},
            ]
        }
        findings = scan_s3_buckets(topology)
        assert all(f.resource_id == "leaky" for f in findings)

    def test_returns_zero_findings_for_fully_secure_bucket(self):
        # All six checks pass -> no findings.
        topology = {
            "nodes": [
                _bucket(
                    "secure-logs",
                    is_public_via_acl=False,
                    public_access_block_fully_enabled=True,
                    encryption_enabled=True,
                    versioning_enabled=True,
                    logging_enabled=True,
                    lifecycle_configured=True,
                )
            ]
        }
        assert scan_s3_buckets(topology) == []

    def test_returns_six_findings_for_bucket_with_all_six_issues(self):
        # The flagship case: our mock's misconfigured uploads bucket.
        # All six rules fire, producing six separate findings on
        # the same resource, each with its own severity.
        topology = {
            "nodes": [
                _bucket(
                    "uploads",
                    is_public_via_acl=True,
                    public_access_block_fully_enabled=False,
                    encryption_enabled=False,
                    versioning_enabled=False,
                    logging_enabled=False,
                    lifecycle_configured=False,
                )
            ]
        }
        findings = scan_s3_buckets(topology)
        assert len(findings) == 6
        # Each finding is against the same resource...
        assert all(f.resource_id == "uploads" for f in findings)
        # ...but each has a different finding_type_id and severity.
        finding_type_ids = [f.finding_type_id for f in findings]
        assert finding_type_ids == [
            "S3_PUBLIC_VIA_ACL",
            "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            "S3_ENCRYPTION_DISABLED",
            "S3_VERSIONING_DISABLED",
            "S3_LOGGING_DISABLED",
            "S3_LIFECYCLE_MISSING",
        ]

    def test_scans_multiple_buckets_independently(self):
        # Two buckets: one secure, one with the public-ACL problem.
        # The secure bucket must not contaminate the results — and
        # vice versa.
        topology = {
            "nodes": [
                _bucket(
                    "secure",
                    is_public_via_acl=False,
                    public_access_block_fully_enabled=True,
                    encryption_enabled=True,
                    versioning_enabled=True,
                    logging_enabled=True,
                    lifecycle_configured=True,
                ),
                _bucket(
                    "leaky",
                    is_public_via_acl=True,
                    public_access_block_fully_enabled=True,
                    encryption_enabled=True,
                    versioning_enabled=True,
                    logging_enabled=True,
                    lifecycle_configured=True,
                ),
            ]
        }
        findings = scan_s3_buckets(topology)
        assert len(findings) == 1
        assert findings[0].resource_id == "leaky"
        assert findings[0].finding_type_id == "S3_PUBLIC_VIA_ACL"
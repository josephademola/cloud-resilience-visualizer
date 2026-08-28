"""
S3 misconfiguration scanner.

Walks every S3 bucket in a topology and produces Finding objects
for each rule that fails.

Current rules:
    - Public via ACL (AllUsers grant)          -> CRITICAL
    - Public Access Block not fully enabled    -> MEDIUM
    - Server-side encryption not configured    -> HIGH
    - Encrypted, but not with a dedicated KMS
      key (SSE-S3, or the AWS-managed default
      key rather than a customer-managed one)  -> LOW
    - Versioning not enabled                   -> MEDIUM
    - Access logging not enabled               -> LOW
    - Lifecycle policy not configured          -> LOW
    - Lifecycle policy configured but disabled -> LOW
    - TLS not enforced by bucket policy        -> MEDIUM

Design notes:

- One function per rule. Each takes a bucket node dict and returns
  either a Finding or None. Adding a fourth rule is a matter of
  adding a new function, not editing scan_s3_buckets.

- Rules return findings; the scanner never prints, logs, or writes
  to disk. Presentation is the caller's job.

- Finding titles, descriptions, remediation text, and severities
  come from finding_content.json (via content_loader). Framework
  references come from the mapping files (via mapping loader).
  The scanner itself contains only detection LOGIC, no content —
  edit content JSON to change what findings say, edit this file to
  change what gets detected.

- Idempotent by design. Scanning the same topology twice produces
  identical findings in identical order.

- Missing-property semantics differ by rule type:
    * Detection signals (e.g. is_public_via_acl): missing -> no
      finding. We don't invent detected problems out of missing data.
    * Protection signals (e.g. encryption_enabled): missing -> fail
      closed. If we can't confirm protection is on, flag it. Matches
      how production CSPM tools behave.
"""

from __future__ import annotations

from typing import Any

from app.mappings.loader import get_framework_references
from app.models.finding import Finding, Severity
from app.scanners.content_loader import get_content


def scan_s3_buckets(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk every S3 bucket in the topology and return all findings.
    """
    findings: list[Finding] = []

    rules = (
        _check_public_via_acl,
        _check_public_access_block,
        _check_encryption,
        _check_encryption_uses_dedicated_kms_key,
        _check_versioning,
        _check_logging,
        _check_lifecycle,
        _check_lifecycle_rule_disabled,
        _check_tls_enforced,
    )

    for node in topology.get("nodes", []):
        if node.get("type") != "s3_bucket":
            continue

        for rule in rules:
            finding = rule(node)
            if finding is not None:
                findings.append(finding)

    return findings


# ---- Individual rules ----
# Each rule detects a specific condition and delegates all content
# construction to _build_finding.


def _check_public_via_acl(bucket: dict[str, Any]) -> Finding | None:
    """Bucket must not have AllUsers ACL grant."""
    props = bucket.get("properties", {})
    if not props.get("is_public_via_acl", False):
        return None
    return _build_finding("S3_PUBLIC_VIA_ACL", bucket["id"])


def _check_public_access_block(bucket: dict[str, Any]) -> Finding | None:
    """All four Public Access Block flags must be enabled."""
    props = bucket.get("properties", {})
    if props.get("public_access_block_fully_enabled", False):
        return None
    return _build_finding("S3_PUBLIC_ACCESS_BLOCK_DISABLED", bucket["id"])


def _check_encryption(bucket: dict[str, Any]) -> Finding | None:
    """Server-side encryption must be configured."""
    props = bucket.get("properties", {})
    if props.get("encryption_enabled", False):
        return None
    return _build_finding("S3_ENCRYPTION_DISABLED", bucket["id"])


def _check_encryption_uses_dedicated_kms_key(bucket: dict[str, Any]) -> Finding | None:
    """
    If encrypted, a bucket should use a dedicated customer-managed
    KMS key -- not SSE-S3, and not SSE-KMS with the AWS-managed
    default key implied by omitting a key ID.

    Skipped entirely when encryption isn't enabled at all --
    _check_encryption already covers that case, and this rule only
    has an opinion about WHICH encryption is used, not whether any is.
    A customer-managed key can be revoked, its policy scoped, its
    usage tracked in CloudTrail, and its rotation controlled; SSE-S3
    and the shared AWS-managed default key offer none of that.
    """
    props = bucket.get("properties", {})
    if not props.get("encryption_enabled", False):
        return None
    if props.get("encryption_algorithm") == "aws:kms" and props.get(
        "encryption_kms_key_id"
    ):
        return None
    return _build_finding("S3_ENCRYPTION_NOT_DEDICATED_KMS_KEY", bucket["id"])


def _check_versioning(bucket: dict[str, Any]) -> Finding | None:
    """Bucket versioning must be enabled."""
    props = bucket.get("properties", {})
    if props.get("versioning_enabled", False):
        return None
    return _build_finding("S3_VERSIONING_DISABLED", bucket["id"])


def _check_logging(bucket: dict[str, Any]) -> Finding | None:
    """Server access logging must be enabled."""
    props = bucket.get("properties", {})
    if props.get("logging_enabled", False):
        return None
    return _build_finding("S3_LOGGING_DISABLED", bucket["id"])


def _check_lifecycle(bucket: dict[str, Any]) -> Finding | None:
    """Bucket must have at least one lifecycle rule configured."""
    props = bucket.get("properties", {})
    if props.get("lifecycle_configured", False):
        return None
    return _build_finding("S3_LIFECYCLE_MISSING", bucket["id"])


def _check_lifecycle_rule_disabled(bucket: dict[str, Any]) -> Finding | None:
    """
    If a lifecycle rule exists, at least one must actually be Enabled.

    Skipped entirely when no rule exists at all -- S3_LIFECYCLE_MISSING
    already owns that case. This rule only has an opinion about
    whether a CONFIGURED lifecycle policy is actually switched on, not
    whether one exists.
    """
    props = bucket.get("properties", {})
    if not props.get("lifecycle_configured", False):
        return None
    if props.get("lifecycle_rule_enabled", False):
        return None
    return _build_finding("S3_LIFECYCLE_RULE_DISABLED", bucket["id"])


def _check_tls_enforced(bucket: dict[str, Any]) -> Finding | None:
    """Bucket policy must deny non-TLS (HTTP) requests."""
    props = bucket.get("properties", {})
    if props.get("tls_enforced", False):
        return None
    return _build_finding("S3_TLS_NOT_ENFORCED", bucket["id"])


# ---- Shared finding constructor ----

def _build_finding(finding_type_id: str, resource_id: str) -> Finding:
    """
    Construct a Finding by combining detection metadata (finding_type_id
    and resource_id) with content from content_loader and framework
    references from mapping loader.

    All Findings the scanner produces flow through here — a single
    source of truth for how the pieces are assembled.
    """
    content = get_content(finding_type_id)
    return Finding(
        finding_type_id=finding_type_id,
        title=content["title"],
        severity=Severity(content["severity"]),
        resource_id=resource_id,
        description=content["description"],
        remediation=content["remediation"],
        framework_references=get_framework_references(finding_type_id),
    )
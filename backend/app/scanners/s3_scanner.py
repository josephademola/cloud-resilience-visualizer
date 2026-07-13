"""
S3 misconfiguration scanner.

Walks every S3 bucket in a topology and produces Finding objects
for each rule that fails.

Current rules:
    - Public via ACL (AllUsers grant)          -> CRITICAL
    - Public Access Block not fully enabled    -> MEDIUM
    - Server-side encryption not configured    -> HIGH

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
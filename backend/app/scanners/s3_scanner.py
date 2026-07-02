"""
S3 misconfiguration scanner.

Walks every S3 bucket in a topology and produces Finding objects
for each rule that fails.

Current rules:
    - Public via ACL (AllUsers grant)          -> CRITICAL
    - Public Access Block not fully enabled    -> MEDIUM
    - Server-side encryption not configured    -> HIGH

Design notes:

- One function per rule. _check_public_via_acl, _check_encryption,
  etc. Each takes a bucket node dict and returns either a Finding
  or None. This means adding a fourth rule is a matter of adding a
  new function, not editing scan_s3_buckets. Testing is also easier
  — one test class per rule.

- Rules return findings; the scanner never prints, logs, or writes
  to disk. Presentation is the caller's job. Keeps the scanner
  testable and composable.

- Framework references come from the mapping loader, not hardcoded
  in each rule. This means editing a mapping file updates every
  finding for that type on the next scan, no code change needed.

- Idempotent by design. Scanning the same topology twice produces
  identical findings in identical order. This matters for
  compliance work — auditors need deterministic output.

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


def scan_s3_buckets(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk every S3 bucket in the topology and return all findings.

    A bucket with all three problems produces three findings, each
    with its own severity and its own set of framework references.
    A well-configured bucket produces zero findings.

    Output order is deterministic: buckets in topology order,
    findings per bucket in rule-definition order (public ACL,
    then PAB, then encryption).
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
# Each rule takes a bucket node dict and returns a Finding or None.


def _check_public_via_acl(bucket: dict[str, Any]) -> Finding | None:
    """
    Rule: bucket must not have AllUsers ACL grant. Critical if it does.
    """
    props = bucket.get("properties", {})
    if not props.get("is_public_via_acl", False):
        return None

    return Finding(
        finding_type_id="S3_PUBLIC_VIA_ACL",
        title="Bucket publicly readable via ACL",
        severity=Severity.CRITICAL,
        resource_id=bucket["id"],
        description=(
            "A grant to the AllUsers group in the bucket ACL means "
            "anyone on the internet can read objects in this bucket. "
            "This is one of the most common causes of accidental data "
            "leaks from AWS environments."
        ),
        remediation=(
            "Remove the AllUsers grant via the AWS Console "
            "(S3 -> bucket -> Permissions -> Access Control List) or "
            "by running 'aws s3api put-bucket-acl' with a policy that "
            "omits the AllUsers grantee. Verify by re-running "
            "'aws s3api get-bucket-acl' and confirming no AllUsers entry."
        ),
        framework_references=get_framework_references("S3_PUBLIC_VIA_ACL"),
    )


def _check_public_access_block(bucket: dict[str, Any]) -> Finding | None:
    """
    Rule: all four Public Access Block flags must be enabled.
    Medium if any are off.
    """
    props = bucket.get("properties", {})
    if props.get("public_access_block_fully_enabled", False):
        return None

    return Finding(
        finding_type_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
        title="Public Access Block not fully enabled",
        severity=Severity.MEDIUM,
        resource_id=bucket["id"],
        description=(
            "Public Access Block is the safety net that overrides "
            "accidentally-public bucket ACLs and policies. One or more "
            "of the four flags (BlockPublicAcls, IgnorePublicAcls, "
            "BlockPublicPolicy, RestrictPublicBuckets) is not enabled, "
            "weakening the account's ability to prevent future accidental "
            "exposures."
        ),
        remediation=(
            "Enable all four Public Access Block flags on the bucket "
            "via the AWS Console (S3 -> bucket -> Permissions -> Block "
            "public access) or by running 'aws s3api "
            "put-public-access-block' with all four flags set to true."
        ),
        framework_references=get_framework_references(
            "S3_PUBLIC_ACCESS_BLOCK_DISABLED"
        ),
    )


def _check_encryption(bucket: dict[str, Any]) -> Finding | None:
    """
    Rule: server-side encryption must be configured. High if not.
    """
    props = bucket.get("properties", {})
    if props.get("encryption_enabled", False):
        return None

    return Finding(
        finding_type_id="S3_ENCRYPTION_DISABLED",
        title="Server-side encryption not configured",
        severity=Severity.HIGH,
        resource_id=bucket["id"],
        description=(
            "Objects in this bucket are stored unencrypted at rest. "
            "AWS provides free default encryption (AES256), so an "
            "unencrypted bucket typically indicates either a "
            "misconfiguration or an outdated bucket that predates the "
            "encryption default becoming automatic."
        ),
        remediation=(
            "Configure default encryption on the bucket via the AWS "
            "Console (S3 -> bucket -> Properties -> Default encryption) "
            "or by running 'aws s3api put-bucket-encryption'. Use "
            "AES256 for the simplest case, or SSE-KMS with a "
            "customer-managed key for compliance-sensitive data."
        ),
        framework_references=get_framework_references("S3_ENCRYPTION_DISABLED"),
    )
"""
Account-level misconfiguration scanner.

Produces Finding objects for account-wide facts that come from AWS
services other than IAM — CloudTrail coverage, account-level S3
Public Access Block, and anything else that describes the account as
a whole rather than one specific resource.

Current rules:
    - No trail actively logging the account         -> CRITICAL
    - Account-level S3 Public Access Block disabled -> HIGH

Design notes:

- Same 'account' node the first three iam_scanner.py rules target
  (see aws_normalizer._normalize_account). Split into its own file
  by source AWS service (CloudTrail, S3 account-level PAB) rather
  than folded into iam_scanner.py, following the project's
  one-scanner-file-per-service convention — but both files target
  the same node type, since "the account" isn't owned by IAM any
  more than it's owned by CloudTrail.

- cloudtrail_logging_enabled is a simplified check: it asks "does at
  least one trail exist and is it currently logging", not "is there
  a trail specifically covering this account's home region". Full
  region-aware trail coverage would need the topology to track a
  concept — "the account's region" — that doesn't exist anywhere
  else in this codebase. Documented here rather than silently
  narrowed.

- account_s3_block_public_access_enabled is computed in the
  normaliser by reusing _is_pab_fully_enabled's four-flag logic
  directly against s3control's response, since it's the identical
  check at account scope instead of bucket scope. No separate
  account-level implementation of the same four-flag comparison.

- Same _build_finding pattern as the other scanners.
"""

from __future__ import annotations

from typing import Any

from app.mappings.loader import get_framework_references
from app.models.finding import Finding, Severity
from app.scanners.content_loader import get_content


def scan_account(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk the account node in the topology and return all findings.
    """
    findings: list[Finding] = []

    rules = (
        _check_cloudtrail_logging,
        _check_s3_account_pab,
    )

    for node in topology.get("nodes", []):
        if node.get("type") != "account":
            continue

        for rule in rules:
            finding = rule(node)
            if finding is not None:
                findings.append(finding)

    return findings


# ---- Individual rules ----


def _check_cloudtrail_logging(account: dict[str, Any]) -> Finding | None:
    """At least one CloudTrail trail must be actively logging."""
    props = account.get("properties", {})
    if props.get("cloudtrail_logging_enabled", False):
        return None
    return _build_finding("ACCOUNT_CLOUDTRAIL_DISABLED", account["id"])


def _check_s3_account_pab(account: dict[str, Any]) -> Finding | None:
    """All four account-level S3 Public Access Block flags must be enabled."""
    props = account.get("properties", {})
    if props.get("account_s3_block_public_access_enabled", False):
        return None
    return _build_finding("ACCOUNT_S3_BLOCK_PUBLIC_ACCESS_DISABLED", account["id"])


# ---- Shared finding constructor ----

def _build_finding(finding_type_id: str, resource_id: str) -> Finding:
    """
    Construct a Finding by combining detection metadata (finding_type_id
    and resource_id) with content from content_loader and framework
    references from mapping loader.
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

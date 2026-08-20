"""
IAM misconfiguration scanner.

Produces Finding objects for account-wide IAM misconfigurations.

Current rules:
    - Root user has active access keys         -> CRITICAL
    - Root user does not have MFA enabled       -> HIGH

Design notes:

- Unlike s3_scanner.py and kms_scanner.py, this scanner doesn't walk
  a list of resources — there is at most one 'account' node in the
  topology (see aws_normalizer._normalize_account), representing the
  whole AWS account. Findings here are facts about the account as a
  whole, not about any specific bucket, key, or instance.

- Same _build_finding pattern as the other scanners: content from
  finding_content.json, framework references from the mapping
  loader.

- root_access_keys_present is a protection-adjacent signal in the
  same fail-closed spirit as the S3/KMS boolean checks, but it's
  computed upstream in the normaliser from AccountAccessKeysPresent
  (missing -> 0 -> False -> not flagged, since AWS's own API treats
  an absent count as zero keys, not unknown state).

- account_mfa_enabled is a genuine protection signal: missing ->
  fail closed (flag it), same semantic as encryption_enabled in the
  S3 scanner. If we can't confirm root has MFA, we don't assume it
  does.
"""

from __future__ import annotations

from typing import Any

from app.mappings.loader import get_framework_references
from app.models.finding import Finding, Severity
from app.scanners.content_loader import get_content


def scan_iam(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk the account node in the topology and return all findings.
    """
    findings: list[Finding] = []

    rules = (
        _check_root_access_keys,
        _check_account_mfa,
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


def _check_root_access_keys(account: dict[str, Any]) -> Finding | None:
    """The root user must not have active access keys."""
    props = account.get("properties", {})
    if not props.get("root_access_keys_present", False):
        return None
    return _build_finding("IAM_ROOT_ACCESS_KEYS_ACTIVE", account["id"])


def _check_account_mfa(account: dict[str, Any]) -> Finding | None:
    """The root user must have MFA enabled."""
    props = account.get("properties", {})
    if props.get("account_mfa_enabled", False):
        return None
    return _build_finding("IAM_ACCOUNT_MFA_NOT_ENABLED", account["id"])


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

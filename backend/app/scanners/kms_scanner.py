"""
KMS misconfiguration scanner.

Walks every KMS key in a topology and produces Finding objects for
each rule that fails.

Current rules:
    - Key rotation not enabled                 -> HIGH
    - Key scheduled for deletion                -> CRITICAL

Design notes:

- Same pattern as s3_scanner.py: one function per rule, each taking a
  key node dict and returning either a Finding or None. Content and
  framework references are assembled the same way, through the same
  content_loader and mapping loader.

- Only customer-managed keys ever appear as kms_key nodes in the
  topology — the normalizer filters out AWS-managed keys before this
  scanner ever sees them, since their rotation setting is not
  something the account owner controls. See docs/design_decisions.md
  #9. This scanner does not need to re-check KeyManager itself.

- Missing-property semantics differ by rule type, same distinction
  s3_scanner.py draws:
    * key_rotation_enabled is a protection signal: missing -> fail
      closed (flag it), same semantic as encryption_enabled and
      versioning_enabled in the S3 scanner.
    * key_state is a detection signal: missing/unknown -> fail open
      (don't flag), same semantic as is_public_via_acl. An unknown
      state is not evidence of a pending deletion; inventing one out
      of missing data would be a false positive.
"""

from __future__ import annotations

from typing import Any

from app.mappings.loader import get_framework_references
from app.models.finding import Finding, Severity
from app.scanners.content_loader import get_content


def scan_kms_keys(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk every KMS key in the topology and return all findings.
    """
    findings: list[Finding] = []

    rules = (
        _check_key_rotation,
        _check_pending_deletion,
    )

    for node in topology.get("nodes", []):
        if node.get("type") != "kms_key":
            continue

        for rule in rules:
            finding = rule(node)
            if finding is not None:
                findings.append(finding)

    return findings


# ---- Individual rules ----


def _check_key_rotation(key: dict[str, Any]) -> Finding | None:
    """Customer-managed keys must have automatic rotation enabled."""
    props = key.get("properties", {})
    if props.get("key_rotation_enabled", False):
        return None
    return _build_finding("KMS_KEY_ROTATION_DISABLED", key["id"])


def _check_pending_deletion(key: dict[str, Any]) -> Finding | None:
    """A key must not be scheduled for deletion."""
    props = key.get("properties", {})
    if props.get("key_state") != "PendingDeletion":
        return None
    return _build_finding("KMS_KEY_PENDING_DELETION", key["id"])


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

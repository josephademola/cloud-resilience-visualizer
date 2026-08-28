"""
KMS misconfiguration scanner.

Walks every KMS key in a topology and produces Finding objects for
each rule that fails.

Current rules:
    - Key rotation not enabled                 -> HIGH
    - Key scheduled for deletion                -> CRITICAL
    - Key has no alias pointing to it           -> LOW
    - Key policy grants an unconditioned
      wildcard principal                        -> HIGH

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
    * has_alias is a protection-adjacent signal: missing -> fail
      closed (flag it), same semantic as key_rotation_enabled. If we
      can't confirm a key has an alias, we don't assume it does.

- has_alias is computed account-wide in the normaliser (KMS has no
  per-key "list aliases" API, only "list every alias in the account
  and see which key each one targets") rather than checking for one
  specific expected alias name -- this codebase never hardcodes
  resource names, so "zero aliases point to this key" is the
  generalisable stand-in for "does this key's alias still correctly
  target it". An alias that got silently repointed to a different
  key would show up as this key having none.

- key_policy_overly_broad is a detection signal, not a protection
  signal: missing/unparseable policy data means we don't know, and we
  don't invent a wildcard grant out of that absence, same semantic as
  key_state. Every key policy legitimately includes a root-account
  grant ({"AWS": "arn:...:root"}) -- that's a specific principal, not
  a wildcard, and isn't what this flags. Only an Allow statement
  granting "*" or {"AWS": "*"} with no Condition narrowing it back
  down counts.
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
        _check_has_alias,
        _check_key_policy_overly_broad,
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


def _check_has_alias(key: dict[str, Any]) -> Finding | None:
    """A customer-managed key should have at least one alias pointing to it."""
    props = key.get("properties", {})
    if props.get("has_alias", False):
        return None
    return _build_finding("KMS_KEY_MISSING_ALIAS", key["id"])


def _check_key_policy_overly_broad(key: dict[str, Any]) -> Finding | None:
    """Key policy must not grant an unconditioned wildcard principal."""
    props = key.get("properties", {})
    if not props.get("key_policy_overly_broad", False):
        return None
    return _build_finding("KMS_KEY_POLICY_OVERLY_BROAD", key["id"])


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

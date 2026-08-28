"""
IAM misconfiguration scanner.

Produces Finding objects for account-wide IAM misconfigurations and
per-user IAM hygiene issues.

Current rules:
    - Root user has active access keys         -> CRITICAL
    - Root user does not have MFA enabled       -> HIGH
    - Account password policy is weak/missing  -> MEDIUM
    - Active access key older than 90 days     -> MEDIUM
    - User has a console login profile         -> MEDIUM

Design notes:

- Two different node shapes, two different rule groups. The first
  three rules walk the single 'account' node in the topology (see
  aws_normalizer._normalize_account) — facts about the whole AWS
  account, not any specific resource. The remaining rules walk
  'iam_user' nodes instead (see aws_normalizer._normalize_iam_users),
  one per IAM user, the same per-resource shape as S3 buckets or KMS
  keys. scan_iam() dispatches on node type to the matching rule group.

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

- password_policy_min_length is stored as a raw value (int or None),
  not a pre-computed boolean, matching how aws_normalizer stores
  RDS's backup_retention_days. The "what counts as weak" threshold
  is a policy judgment call that belongs in the scanner rule, not
  baked silently into the normaliser. None (no policy configured at
  all) is treated as weak — fail-closed.

- _check_access_key_age is the only rule in this codebase that reads
  the current time. That is confined here deliberately, never in the
  normaliser — see docs/design_decisions.md #10 for why an age-based
  check is a narrow, documented exception to "deterministic output
  everywhere."
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.mappings.loader import get_framework_references
from app.models.finding import Finding, Severity
from app.scanners.content_loader import get_content


def scan_iam(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk the account and IAM user nodes in the topology and return
    all findings.
    """
    findings: list[Finding] = []

    account_rules = (
        _check_root_access_keys,
        _check_account_mfa,
        _check_password_policy,
    )
    user_rules = (
        _check_access_key_age,
        _check_console_login_profile,
    )

    for node in topology.get("nodes", []):
        node_type = node.get("type")
        if node_type == "account":
            rules = account_rules
        elif node_type == "iam_user":
            rules = user_rules
        else:
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


# NCSC and NIST's current baseline recommendation for minimum
# password length. A hardcoded constant, not a magic number, so the
# threshold is visible and changeable in one place.
_MIN_PASSWORD_LENGTH = 14


def _check_password_policy(account: dict[str, Any]) -> Finding | None:
    """The account password policy must require at least 14 characters."""
    props = account.get("properties", {})
    min_length = props.get("password_policy_min_length")
    if min_length is not None and min_length >= _MIN_PASSWORD_LENGTH:
        return None
    return _build_finding("IAM_PASSWORD_POLICY_WEAK", account["id"])


# Industry-standard rotation window. Also a hardcoded, visible
# constant rather than a magic number.
_MAX_ACCESS_KEY_AGE_DAYS = 90


def _check_access_key_age(user: dict[str, Any]) -> Finding | None:
    """
    A user must not have any active access key older than 90 days.

    One finding per user, not per key: if any active key is too old,
    the user gets flagged, the same per-resource granularity every
    other scanner in this codebase uses. A user is fail-closed
    against an unparseable creation date the same way a missing
    protection-signal property would be — if we can't confirm a key
    is recent, we don't assume it is.
    """
    props = user.get("properties", {})
    now = datetime.now(timezone.utc)

    for key in props.get("access_keys", []):
        if key.get("status") != "Active":
            continue

        create_date = _parse_iso_datetime(key.get("create_date"))
        if create_date is None:
            return _build_finding("IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS", user["id"])

        age_days = (now - create_date).days
        if age_days > _MAX_ACCESS_KEY_AGE_DAYS:
            return _build_finding("IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS", user["id"])

    return None


def _check_console_login_profile(user: dict[str, Any]) -> Finding | None:
    """
    A user must not have a console login profile.

    Not every IAM user needs to be programmatic-only in general, but
    every user this scanner sees is a service/application identity
    (this codebase has no concept of a human-operator IAM user
    distinct from a service account), so a console login profile
    existing at all is unexpected attack surface -- password-based
    console access on a credential that should only ever be used by
    code. has_console_login is a detection signal, not a protection
    signal: missing data means we don't know, and we don't invent a
    login profile out of that absence, same semantic as
    is_public_via_acl.
    """
    props = user.get("properties", {})
    if not props.get("has_console_login", False):
        return None
    return _build_finding("IAM_CONSOLE_LOGIN_ENABLED", user["id"])


def _parse_iso_datetime(value: Any) -> datetime | None:
    """Parse an ISO-8601 string into a timezone-aware datetime, or None."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


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

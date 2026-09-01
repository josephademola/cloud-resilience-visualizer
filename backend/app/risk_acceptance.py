"""
Risk acceptance / suppression mechanism.

Phase 4 (gap-analysis-driven build, 2026-08-28): every finding CRV
produces has always been present-or-absent, with no way for a
compliance officer to consciously accept a known risk and have that
decision reflected inside the tool. This module is that mechanism.

Scoped down deliberately, matching how Phase 3 was scoped: this is
NOT a workflow (no approval chain, no UI to create an acceptance) --
it's a data-driven mechanism. An acceptance is a fact recorded in a
JSON file; this module reads that file and applies it. Building an
actual approval workflow would be a much bigger, separate feature.

Design, matching the constitution's AUDITABILITY OVER CONVENIENCE
principle: an accepted finding is never deleted or hidden from
/api/findings -- it is still returned, still counted in evidence
totals, just tagged with WHO accepted it, WHY, and UNTIL WHEN (see
app.models.finding.Finding.risk_acceptance). Only /api/compliance's
"still failing" view treats it as resolved, since a consciously
accepted risk is no longer an open compliance gap by definition --
the same distinction a real GRC risk register draws between "open"
and "accepted" risk. See app.compliance.build_compliance_view.

The acceptance data itself (who accepted what, and why) can be at
least as sensitive as the confidential client's control catalogue --
it names real people, real resource IDs, and real business
justifications -- so it follows the exact same gitignored-by-default,
tolerate-absence pattern as app/mappings/confidential_controls.json
(see architecture decision #7 in CLAUDE_HANDOVER.md). Nothing here
ever requires the file to exist; its absence just means zero
acceptances, the safe default -- fail-closed in the sense that matters
here: no acceptance data means every finding stays active and visible.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import dataclasses

from app.models.finding import Finding

logger = logging.getLogger(__name__)

# Gitignored, same as app/mappings/confidential_controls.json -- see
# module docstring. Absence is the normal, safe default in every
# environment that has no acceptances configured (mock mode, CI, a
# fresh checkout).
RISK_ACCEPTANCES_PATH = Path(__file__).parent / "data" / "risk_acceptances.json"


def load_risk_acceptances(path: Path | None = None) -> list[dict[str, Any]]:
    """
    Read the risk-acceptances file and return its list of acceptance
    entries, or an empty list if the file doesn't exist -- the same
    tolerance app.mappings.loader applies to a missing confidential
    control catalogue.

    path defaults to the module-level RISK_ACCEPTANCES_PATH, read
    inside the function body rather than bound as the parameter's
    default value -- the same pattern app.mappings.loader uses for
    _MAPPINGS_DIR, so a test can monkeypatch this module's
    RISK_ACCEPTANCES_PATH and have a no-argument call pick it up. A
    default bound at function-definition time would freeze the
    original path forever, since Python resolves default argument
    values once, at import, not per call.

    A file that exists but fails to parse is NOT swallowed the same
    way: that's a real configuration error worth surfacing loudly
    (raises) rather than silently scanning as if no acceptances were
    configured, which would be the unsafe direction to fail in.
    """
    if path is None:
        path = RISK_ACCEPTANCES_PATH
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("acceptances", [])


def find_acceptance(
    finding_type_id: str,
    resource_id: str,
    acceptances: list[dict[str, Any]],
    *,
    today: date | None = None,
) -> dict[str, Any] | None:
    """
    Return the acceptance entry covering this finding, or None.

    Matches on finding_type_id always, and resource_id either exactly
    or via the "*" wildcard -- accepting a finding type across every
    resource at once (e.g. "we've accepted
    IAM_MULTIPLE_ACTIVE_ACCESS_KEYS account-wide for the duration of a
    migration"), rather than requiring one entry per resource.

    An acceptance with a past 'expires' date no longer applies -- it
    lapses back to an active finding automatically rather than needing
    to be manually removed, the same fail-closed instinct as every
    protection signal in this codebase: an accepted risk nobody
    renewed goes back to being flagged, not silently staying accepted
    forever. expires is optional; omitted or null means indefinite.

    today is injectable for deterministic testing, the same narrow,
    confined exception to "no code reads the current time in the
    normaliser/scanner layer" that _check_access_key_age already
    establishes (docs/design_decisions.md #10) -- this lives outside
    that layer entirely, in the same spirit.
    """
    if today is None:
        today = datetime.now(timezone.utc).date()

    for acceptance in acceptances:
        if acceptance.get("finding_type_id") != finding_type_id:
            continue

        acceptance_resource = acceptance.get("resource_id")
        if acceptance_resource != resource_id and acceptance_resource != "*":
            continue

        expires = acceptance.get("expires")
        if expires:
            try:
                expires_date = date.fromisoformat(expires)
            except (TypeError, ValueError):
                logger.warning(
                    "Risk acceptance for %s/%s has an unparseable expires "
                    "date %r; treating it as expired rather than accepted.",
                    finding_type_id, resource_id, expires,
                )
                continue
            if expires_date < today:
                continue

        return acceptance

    return None


def apply_risk_acceptances(
    findings: list[Finding],
    acceptances: list[dict[str, Any]],
    *,
    today: date | None = None,
) -> list[Finding]:
    """
    Return a new findings list with risk_acceptance attached wherever
    an unexpired acceptance covers that finding.

    Findings are never removed or hidden here -- only annotated -- so
    /api/findings and the evidence record stay a complete, auditable
    record regardless of what has been consciously accepted. Downstream
    consumers that want to treat an accepted risk as resolved (see
    app.compliance.build_compliance_view) filter on
    finding.risk_acceptance themselves.
    """
    if not acceptances:
        return findings

    return [
        _attach_if_covered(finding, acceptances, today) for finding in findings
    ]


def _attach_if_covered(
    finding: Finding, acceptances: list[dict[str, Any]], today: date | None
) -> Finding:
    acceptance = find_acceptance(
        finding.finding_type_id, finding.resource_id, acceptances, today=today
    )
    if acceptance is None:
        return finding

    return dataclasses.replace(
        finding,
        risk_acceptance={
            "reason": acceptance.get("reason"),
            "accepted_by": acceptance.get("accepted_by"),
            "accepted_date": acceptance.get("accepted_date"),
            "expires": acceptance.get("expires"),
        },
    )

"""
Scan evidence builder.

For every scan the CSPM runs, this module produces a structured
audit record that can be handed to an auditor as chain-of-custody
proof that the scan happened, when it happened, against what data,
and what it found.

Real GRC work is 60% proving you did something, not just doing it.
An auditor doesn't just want findings — they want:
  - When was this scan run?
  - What version of the tool ran it?
  - What was the scope (which account, which region)?
  - Can I verify the input data hasn't been tampered with?
  - What did it find, in summary?

This module produces exactly that record. The integrity_hash at the
end covers the entire record contents, so any post-hoc modification
of the record is detectable.

Design notes:

- Returns a plain dict (JSON-serialisable) so the API can return it
  directly and callers can also write it to disk or attach it to a
  PDF without coupling to this module's internals.

- The integrity hash covers the content fields, not the hash field
  itself (which is set after). This is standard practice — you hash
  the content, then store the hash alongside it.

- IAM identity is optional. When running in mock mode there's no
  real AWS identity, so we default to 'mock-mode'. When live, the
  caller passes in the IAM ARN from sts.get_caller_identity. This
  keeps the module usable in both contexts without special-casing.

- Tool version is read from a VERSION constant here so there's a
  single source of truth. Update it when making breaking changes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from app.models.finding import Finding


# Single source of truth for the tool version. Matches what the
# FastAPI app reports in /docs and what gets stamped on every
# audit record.
TOOL_VERSION = "0.1.0"


def build_evidence_record(
    topology: dict[str, Any],
    findings: list[Finding],
    *,
    iam_identity: str = "mock-mode",
    data_source: str = "mock",
    project_tag: str | None = None,
) -> dict[str, Any]:
    """
    Produce an audit evidence record for a completed scan.

    Parameters:
        topology      -- the normalised topology dict from the scan
        findings      -- the list of Finding objects the scanner produced
        iam_identity  -- IAM ARN of the identity used to fetch data
                         (pass sts.get_caller_identity()['Arn'] in live mode)
        data_source   -- 'mock' or 'live' — records which data path was used
        project_tag   -- optional "Key=Value" tag the scan was scoped to
                         (Phase 9a Feature 4, e.g. "Project=<tag-value>").
                         None when the scan covered the whole account.
                         Recorded in scope, not as a new top-level key,
                         since it describes what was scanned, the same
                         thing node_count and resource_types describe.

    Returns a plain dict ready for json.dumps or API response.
    """
    generated_at = datetime.now(timezone.utc).isoformat()

    scope = _build_scope(topology, project_tag)
    findings_summary = _build_findings_summary(findings)

    # Hash the raw topology as proof of what was scanned.
    input_hash = _sha256_dict(topology)

    record: dict[str, Any] = {
        "schema_version": "1.0",
        "tool_version": TOOL_VERSION,
        "generated_at": generated_at,
        "data_source": data_source,
        "iam_identity": iam_identity,
        "scope": scope,
        "findings_summary": findings_summary,
        "input_hash": f"sha256:{input_hash}",
    }

    # Integrity hash covers the full record content.
    record["integrity_hash"] = f"sha256:{_sha256_dict(record)}"

    return record


def _build_scope(
    topology: dict[str, Any], project_tag: str | None = None
) -> dict[str, Any]:
    """Extract scope metadata from the topology."""
    nodes = topology.get("nodes", [])
    resource_types = sorted({n.get("type", "unknown") for n in nodes})
    region = topology.get("metadata", {}).get("region", "unknown")

    return {
        "node_count": len(nodes),
        "security_group_count": len(topology.get("security_groups", [])),
        "resource_types": resource_types,
        "region_hint": region,
        "project_tag": project_tag,
    }


def _build_findings_summary(findings: list[Finding]) -> dict[str, Any]:
    """Summarise findings by count and severity."""
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    affected = set()

    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        affected.add(f.resource_id)

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "affected_resources": sorted(affected),
    }


def _sha256_dict(data: dict) -> str:
    """
    Produce a stable SHA-256 hash of a dict.

    Uses sort_keys=True so the serialised form is deterministic
    regardless of insertion order.
    """
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
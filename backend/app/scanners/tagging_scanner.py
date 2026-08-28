"""
Resource tagging scanner.

Walks every taggable resource in a topology (S3 buckets, KMS keys,
IAM users -- see aws_normalizer.TAGGABLE_NODE_TYPES) and flags any
with no tags at all.

Current rules:
    - Resource has no tags of any kind        -> LOW

Design notes:

- This finding exists specifically for UNSCOPED scans. Tag-based
  target selection (Phase 9a Feature 1) already filters a scoped
  scan's topology down to resources matching the requested tag
  (aws_normalizer.filter_topology_by_tag), so every taggable node
  that survives a scoped scan trivially already has a tag -- this
  rule can never fire there by construction, not because the check
  is skipped. It's the unscoped, whole-account scan where an
  untagged resource is actually visible and worth flagging: tag-based
  discovery has a structural blind spot (a resource nobody remembered
  to tag is invisible to a scoped scan, full stop, indistinguishable
  from a resource that doesn't exist), and this is the closest thing
  to catching that -- not by finding the specific missing resource
  for a specific project (impossible without guessing), but by
  surfacing every untagged candidate for a human to review.

- has_any_tags is set in the normaliser (_apply_tag_presence) from
  the Resource Groups Tagging API's get_resources() response, called
  unconditionally on every scan now (previously gated on project_tag
  being given) -- see docs/design_decisions.md #12.

- A resource with zero tags never appears in get_resources() at all;
  that's real API behaviour, not missing/unknown data. So
  has_any_tags is a plain fact, not a detection/protection signal
  with a missing-data judgment call the way most other properties in
  this codebase are.

- Spans three node types in one file, same precedent as
  iam_scanner.py spanning 'account' and 'iam_user': this is grouped
  by concern (tagging hygiene) rather than by AWS service, since the
  same one rule applies identically across all three resource types.
"""

from __future__ import annotations

from typing import Any

from app.aws_normalizer import TAGGABLE_NODE_TYPES
from app.mappings.loader import get_framework_references
from app.models.finding import Finding, Severity
from app.scanners.content_loader import get_content


def scan_tagging(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk every taggable resource in the topology and return all
    findings.
    """
    findings: list[Finding] = []

    for node in topology.get("nodes", []):
        if node.get("type") not in TAGGABLE_NODE_TYPES:
            continue

        finding = _check_has_any_tags(node)
        if finding is not None:
            findings.append(finding)

    return findings


def _check_has_any_tags(resource: dict[str, Any]) -> Finding | None:
    """A taggable resource should have at least one tag."""
    props = resource.get("properties", {})
    if props.get("has_any_tags", False):
        return None
    return _build_finding("RESOURCE_MISSING_TAGS", resource["id"])


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

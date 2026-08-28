"""
Compliance aggregator.

Takes a flat list of Finding objects and reshapes it into a
framework-grouped view suitable for the compliance dashboard.

The topology + findings view answers 'which of my resources have
problems?'. This aggregator answers the opposite question: 'which
framework requirements are failing, and which findings cause each
failure?'. Same underlying data, orthogonal perspective — the one a
GRC officer or auditor wants.

Design notes:

- Framework order and framework-specific display metadata are
  hardcoded here rather than read from the mapping files. There are
  seven of them, they're stable, and pulling them into a separate
  configuration file would be over-engineering. Adding a framework
  (a confidential client baseline, then ISO 27001 and DORA) means
  updating both this file and the mapping loader — the change surface
  is small and both places are obvious to a maintainer.

- unit_label per framework is deliberately different. NIS2 has
  'articles', CAF has 'outcomes', MITRE has 'techniques enabled'
  (not 'failing' — MITRE is a threat framework), Cyber Essentials
  has 'themes'. Framework-native language matters for credibility
  with users who know each framework.

- Output is deterministic. Frameworks in fixed order, requirements
  sorted by reference_id alphabetically. Same input -> identical
  output on every call. Matches the discipline the scanner and
  normaliser already follow.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.mappings.loader import get_confidential_framework_display_names
from app.models.finding import Finding


# Framework display order for the compliance dashboard. NIS2 first
# (broadest EU coverage), then the other EU/UK published standards,
# the confidential client baseline last of all — it's an
# engagement-specific control catalogue, not a published external
# standard like the other six.
_FRAMEWORK_ORDER = (
    "nis2",
    "ncsc_caf",
    "mitre_attack",
    "cyber_essentials",
    "iso27001",
    "dora",
    "confidential",
)

# Per-framework display metadata. full_name shows in the section
# heading; unit_label appears under the score card number.
_FRAMEWORK_META = {
    "nis2": {
        "full_name": "EU NIS2 Directive (2022/2555)",
        "unit_label": "articles failing",
    },
    "ncsc_caf": {
        "full_name": "NCSC Cyber Assessment Framework v4.0",
        "unit_label": "outcomes failing",
    },
    "mitre_attack": {
        "full_name": "MITRE ATT&CK Enterprise (Cloud IaaS)",
        "unit_label": "techniques enabled",
    },
    "cyber_essentials": {
        "full_name": "UK Cyber Essentials",
        "unit_label": "themes failing",
    },
    "iso27001": {
        "full_name": "ISO/IEC 27001:2022 Annex A",
        "unit_label": "controls failing",
    },
    "dora": {
        "full_name": "EU Digital Operational Resilience Act (2022/2554)",
        "unit_label": "articles failing",
    },
    "confidential": {
        "full_name": "Confidential Client Control Baseline",
        "unit_label": "controls failing",
    },
}


def build_compliance_view(
    findings: list[Finding], *, include_confidential: bool = False
) -> dict[str, Any]:
    """
    Reshape a flat list of findings into per-framework requirement
    groupings suitable for the compliance dashboard.

    include_confidential defaults to False — fail-closed, the same
    semantic every protection signal in this codebase uses. Callers
    must explicitly pass True, and only after confirming the scan is
    actually scoped to the confidential client's tagged project. That
    client's control catalogue is client-confidential — it must never
    appear in an unscoped scan's dashboard, or one scoped to a
    different tagged project, and a caller that forgets to pass this
    parameter should get the safe behaviour, not the exposing one.
    The section is omitted entirely rather than shown empty, so an
    unrelated scan doesn't even reveal that a "confidential" framework
    exists.

    Return shape:
        {
            "metadata": {
                "schema_version": "1.0",
                "total_findings": <int>,
                "framework_count": 7,
            },
            "frameworks": [
                {
                    "framework": "nis2",
                    "framework_full_name": "EU NIS2 Directive (2022/2555)",
                    "unit_label": "articles failing",
                    "failing_count": <int>,
                    "failing_requirements": [
                        {
                            "reference_id": "Article 21(2)(i)",
                            "label": "Access control policies and asset management",
                            "findings": [
                                {
                                    "finding_type_id": "S3_PUBLIC_VIA_ACL",
                                    "resource_id": "cloudres-fintech-uploads",
                                    "severity": "critical",
                                    "title": "Bucket publicly readable via legacy ACL"
                                }
                            ]
                        },
                        ...
                    ]
                },
                ...
            ]
        }
    """
    frameworks_output = []
    framework_order = (
        _FRAMEWORK_ORDER
        if include_confidential
        else tuple(f for f in _FRAMEWORK_ORDER if f != "confidential")
    )

    for framework_name in framework_order:
        meta = _FRAMEWORK_META[framework_name]
        failing_requirements = _group_findings_by_requirement(
            findings, framework_name
        )
        entry = {
            "framework": framework_name,
            "framework_full_name": meta["full_name"],
            "unit_label": meta["unit_label"],
            "failing_count": len(failing_requirements),
            "failing_requirements": failing_requirements,
        }

        # The confidential framework's display name can be overridden
        # by its own (gitignored) mapping file's _meta block -- e.g. a
        # real engagement's control catalogue can call itself
        # "Acme Corp Internal Control Baseline" in its own private
        # content, without that name ever appearing in this repo's
        # code. Falls back to the generic default above when the file
        # doesn't exist or doesn't specify one (mock mode, CI, etc).
        if framework_name == "confidential":
            override = get_confidential_framework_display_names()
            if override:
                if override.get("full_name"):
                    entry["framework_full_name"] = override["full_name"]
                if override.get("short_name"):
                    entry["framework_short_name"] = override["short_name"]

        frameworks_output.append(entry)

    return {
        "metadata": {
            "schema_version": "1.0",
            "total_findings": len(findings),
            "framework_count": len(frameworks_output),
        },
        "frameworks": frameworks_output,
    }


def _group_findings_by_requirement(
    findings: list[Finding],
    framework_name: str,
) -> list[dict[str, Any]]:
    """
    For a single framework, walk every finding and group them under
    the reference_ids they violate. Returns the failing_requirements
    list — one entry per unique requirement, sorted by reference_id.
    """
    # reference_id -> {"label": str, "findings": [finding_summary, ...]}
    by_reference: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"label": "", "findings": []}
    )

    for finding in findings:
        for ref in finding.framework_references:
            if ref.framework != framework_name:
                continue
            entry = by_reference[ref.reference_id]
            entry["label"] = ref.label
            entry["findings"].append({
                "finding_type_id": finding.finding_type_id,
                "resource_id": finding.resource_id,
                "severity": finding.severity.value,
                "title": finding.title,
            })

    return [
        {
            "reference_id": ref_id,
            "label": data["label"],
            "findings": data["findings"],
        }
        for ref_id, data in sorted(by_reference.items())
    ]
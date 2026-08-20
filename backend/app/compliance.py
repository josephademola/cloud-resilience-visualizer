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
  five of them, they're stable, and pulling them into a separate
  configuration file would be over-engineering. Adding a framework
  (ShiftCommute was the first addition, Phase 9a Feature 2) means
  updating both this file and the mapping loader — the change
  surface is small and both places are obvious to a maintainer.

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

from app.models.finding import Finding


# Framework display order for the compliance dashboard. NIS2 first
# (broadest EU coverage), Cyber Essentials last (UK-specific baseline),
# ShiftCommute last of all — it's an engagement-specific control
# catalogue, not a published external standard like the other four.
_FRAMEWORK_ORDER = (
    "nis2",
    "ncsc_caf",
    "mitre_attack",
    "cyber_essentials",
    "shiftcommute",
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
    "shiftcommute": {
        "full_name": "ShiftCommute Internal Control Baseline",
        "unit_label": "controls failing",
    },
}


def build_compliance_view(findings: list[Finding]) -> dict[str, Any]:
    """
    Reshape a flat list of findings into per-framework requirement
    groupings suitable for the compliance dashboard.

    Return shape:
        {
            "metadata": {
                "schema_version": "1.0",
                "total_findings": <int>,
                "framework_count": 5,
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

    for framework_name in _FRAMEWORK_ORDER:
        meta = _FRAMEWORK_META[framework_name]
        failing_requirements = _group_findings_by_requirement(
            findings, framework_name
        )
        frameworks_output.append({
            "framework": framework_name,
            "framework_full_name": meta["full_name"],
            "unit_label": meta["unit_label"],
            "failing_count": len(failing_requirements),
            "failing_requirements": failing_requirements,
        })

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
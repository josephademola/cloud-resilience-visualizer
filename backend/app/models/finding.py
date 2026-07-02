"""
Finding dataclass — the canonical shape of one security problem.

A Finding is what the scanner produces. Every finding must have a
stable ID (finding_type_id), a human-readable title, a severity
level, the resource it applies to, plain-English description and
remediation, and a list of references to compliance frameworks it
violates.

Design decisions embedded in this module:

- @dataclass(frozen=True) — Findings are immutable after creation.
  Once the scanner emits one, no other code can silently mutate its
  severity or remediation text. Prevents a whole class of bugs where
  downstream code changes the data before the frontend displays it.

- Severity is a string enum, not a free string. The four valid
  values are locked in. Typos like "hgih" raise instead of silently
  passing through.

- finding_type_id is a stable machine identifier like
  "S3_PUBLIC_VIA_ACL", not the free-text title. The title can be
  reworded later without breaking any mapping file or test that
  references the ID.

- Framework references are their own small dataclass, so each has
  the same shape (framework name + reference ID + short label)
  regardless of which framework it's from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """
    Four-level severity scale matching what CSPM tools (Wiz,
    Lacework, Prowler, AWS Security Hub) use.

    Ordering low -> medium -> high -> critical is meaningful: any
    code that ranks findings can rely on this order.

    Inheriting from `str` means Severity.HIGH serialises to the
    string "high" when written to JSON — no custom encoder needed.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class FrameworkReference:
    """
    One reference to a compliance framework requirement.

    Example:
        FrameworkReference(
            framework="nis2",
            reference_id="Article 21(2)(d)",
            label="Supply chain security",
        )

    The `framework` field is a short identifier ("nis2", "ncsc_caf",
    "mitre_attack", "cyber_essentials"), matching the JSON mapping
    file names in app/mappings/.
    """

    framework: str
    reference_id: str
    label: str


@dataclass(frozen=True)
class Finding:
    """
    One security problem detected against one AWS resource.

    Fields:
        finding_type_id: stable machine ID (e.g. "S3_PUBLIC_VIA_ACL").
            Used to look up framework references in the mapping files.
        title: short human-readable heading, sentence case.
        severity: one of Severity.LOW / MEDIUM / HIGH / CRITICAL.
        resource_id: ID of the topology node this finding applies to
            (e.g. "cloudres-fintech-uploads", "i-0aaa1bbb2ccc3ddd4").
        description: plain-English explanation of what the problem is
            and why it matters. One or two sentences.
        remediation: plain-English hint for how to fix it. One or two
            sentences, action-focused.
        framework_references: list of FrameworkReference objects
            populated from the mapping files. Empty list is valid
            (means the finding hasn't been mapped yet — should never
            happen in normal operation).

    Fields have no defaults on purpose: forgetting one is a bug we
    want the constructor to catch loudly.
    """

    finding_type_id: str
    title: str
    severity: Severity
    resource_id: str
    description: str
    remediation: str
    framework_references: tuple[FrameworkReference, ...] = field(
        default_factory=tuple
    )
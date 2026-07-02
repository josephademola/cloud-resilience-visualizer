"""
Framework mapping loader.

Reads every mapping file in app/mappings/*.json and combines them
into a single lookup structure. Given a finding_type_id like
"S3_PUBLIC_VIA_ACL", returns the full list of FrameworkReference
objects from every framework that maps that finding type.

Design notes:

- Lazy loading (cached on first call, not at import time). Import
  is cheap; the file I/O happens the first time a scanner asks for
  references. This means importing this module in a test doesn't
  fail if mapping files are temporarily missing.

- Keys starting with underscore ("_meta") are skipped when
  iterating mapping data. They're documentation, not finding types.

- Returns tuple, not list. Matches the immutable-by-default shape
  of the Finding dataclass; callers can pass the result straight
  into Finding(framework_references=...).
"""

from __future__ import annotations

import json
from pathlib import Path

from app.models.finding import FrameworkReference

# The mapping files live alongside this loader in app/mappings/.
_MAPPINGS_DIR = Path(__file__).parent

# Files loaded (order doesn't matter — references from all four
# get combined into one list per finding-type-id).
_FRAMEWORK_FILES = (
    "nis2.json",
    "ncsc_caf.json",
    "mitre_attack.json",
    "cyber_essentials.json",
)

# Cache populated on first call to _get_mappings().
_MAPPINGS_CACHE: dict[str, list[FrameworkReference]] | None = None


def get_framework_references(
    finding_type_id: str,
) -> tuple[FrameworkReference, ...]:
    """
    Return all framework references for a given finding type ID.

    Combines entries across all four mapping files. If a finding
    type appears in three of the four files, this returns references
    from all three, in file-load order.

    Returns an empty tuple if the finding type has no mapping at all
    — which shouldn't happen for anything the scanner produces, since
    every finding type the scanner emits must be declared in at
    least one mapping file.
    """
    refs = _get_mappings().get(finding_type_id, [])
    return tuple(refs)


def _get_mappings() -> dict[str, list[FrameworkReference]]:
    """Return the cached mapping dict, loading from disk on first call."""
    global _MAPPINGS_CACHE
    if _MAPPINGS_CACHE is None:
        _MAPPINGS_CACHE = _load_all_mappings()
    return _MAPPINGS_CACHE


def _load_all_mappings() -> dict[str, list[FrameworkReference]]:
    """
    Read every mapping file and combine into one lookup dict.

    Return shape:
        {
            "S3_PUBLIC_VIA_ACL": [
                FrameworkReference(framework="nis2", ...),
                FrameworkReference(framework="ncsc_caf", ...),
                FrameworkReference(framework="mitre_attack", ...),
                FrameworkReference(framework="cyber_essentials", ...),
            ],
            ...
        }
    """
    combined: dict[str, list[FrameworkReference]] = {}

    for filename in _FRAMEWORK_FILES:
        path = _MAPPINGS_DIR / filename
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        for finding_type_id, references in data.items():
            # Skip _meta and any other underscore-prefixed keys.
            if finding_type_id.startswith("_"):
                continue

            if finding_type_id not in combined:
                combined[finding_type_id] = []

            for ref_dict in references:
                combined[finding_type_id].append(
                    FrameworkReference(
                        framework=ref_dict["framework"],
                        reference_id=ref_dict["reference_id"],
                        label=ref_dict["label"],
                    )
                )

    return combined
"""
Finding content loader.

Reads finding_content.json from disk and provides content lookup by
finding_type_id. Content includes the title, severity, description,
and remediation text for each finding.

Design notes:

- Lazy loading with cache. Same pattern as the mapping loader: file
  I/O happens on first call, not at module import.

- Underscore-prefixed keys ("_meta") are excluded when iterating
  content data. They document the file, not finding types.

- get_content() RAISES on unknown finding_type_id rather than
  returning a default. Content is not optional the way framework
  references are — a Finding without content is broken. Failing
  fast catches bugs like typos in finding_type_ids or missing
  content entries at rule-writing time.
"""

from __future__ import annotations

import json
from pathlib import Path

_CONTENT_FILE = Path(__file__).parent / "finding_content.json"
_CONTENT_CACHE: dict[str, dict] | None = None


def get_content(finding_type_id: str) -> dict:
    """
    Return the content dict for a given finding type ID.

    Return shape:
        {
            "title": "...",
            "severity": "critical" | "high" | "medium" | "low",
            "description": "...",
            "remediation": "...",
        }

    Raises KeyError if the finding type has no content entry. This
    is intentional: content is a required part of every Finding.
    A missing entry is a bug the scanner author needs to fix, not
    something to paper over with defaults.
    """
    return _get_all_content()[finding_type_id]


def _get_all_content() -> dict[str, dict]:
    """Return the cached content dict, loading from disk on first call."""
    global _CONTENT_CACHE
    if _CONTENT_CACHE is None:
        _CONTENT_CACHE = _load_content()
    return _CONTENT_CACHE


def _load_content() -> dict[str, dict]:
    """
    Read finding_content.json and return the finding-type entries.
    Skips underscore-prefixed keys (documentation, not entries).
    """
    with open(_CONTENT_FILE, encoding="utf-8") as fh:
        data = json.load(fh)

    return {
        key: value
        for key, value in data.items()
        if not key.startswith("_")
    }
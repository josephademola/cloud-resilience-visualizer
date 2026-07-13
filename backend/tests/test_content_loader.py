"""
Unit tests for app.scanners.content_loader.

The content loader reads finding_content.json and provides a lookup
of title, severity, description, and remediation by finding_type_id.
Same lazy-load + cache pattern as the mapping loader.

These tests verify:
  - Known finding types return the full content dict.
  - Unknown finding types raise KeyError (fail-fast — a Finding
    without content is a broken Finding).
  - Meta keys are excluded from the exposed lookup.
"""

import pytest

from app.scanners.content_loader import get_content


# --- get_content ------------------------------------------------------
class TestGetContent:

    def test_returns_all_required_fields_for_known_finding_type(self):
        # The scanner reads title, severity, description, remediation
        # from the content dict. If any of these is missing, the
        # Finding constructor will raise. Lock all four in.
        content = get_content("S3_PUBLIC_VIA_ACL")
        assert set(content.keys()) >= {
            "title", "severity", "description", "remediation"
        }

    def test_returns_content_for_all_three_s3_finding_types(self):
        # Each of the three current S3 finding types must have a
        # content entry — the scanner rules assume it. If someone
        # deletes or renames a content entry, the scanner would
        # crash at runtime; this test surfaces that at test time.
        for finding_type_id in [
            "S3_PUBLIC_VIA_ACL",
            "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            "S3_ENCRYPTION_DISABLED",
        ]:
            content = get_content(finding_type_id)
            assert content["title"], f"{finding_type_id} has empty title"
            assert content["severity"] in {"low", "medium", "high", "critical"}
            assert len(content["description"]) > 50  # not a stub
            assert len(content["remediation"]) > 50  # not a stub

    def test_raises_key_error_for_unknown_finding_type(self):
        # Content is a hard requirement — a Finding without a title,
        # description, and remediation is broken. Fail fast rather
        # than return an empty/default content dict that would
        # silently propagate through the scanner into the UI.
        with pytest.raises(KeyError):
            get_content("NONSENSE_FINDING_TYPE_XYZ")

    def test_skips_meta_keys(self):
        # The _meta key documents the file structure. It must not
        # be exposed as if it were a finding type.
        with pytest.raises(KeyError):
            get_content("_meta")
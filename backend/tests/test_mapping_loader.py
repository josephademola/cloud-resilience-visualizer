"""
Unit tests for app.mappings.loader.

The loader reads all four framework JSON files and provides a single
lookup by finding_type_id. These tests verify:

  - Known finding types return references from every framework that
    maps them (the "combining" behaviour).
  - Unknown finding types return an empty tuple, not raise.
  - Meta keys ("_meta") are excluded — they document files, they
    aren't finding entries.
  - The returned value is a tuple (immutable) so callers can pass it
    directly to Finding(framework_references=...).

These tests read the real mapping files in app/mappings/ rather than
mocking them. Small project, static content, no reason to fake it.
"""

from app.mappings.loader import get_framework_references
from app.models.finding import FrameworkReference


# --- get_framework_references ----------------------------------------
class TestGetFrameworkReferences:

    def test_returns_references_for_known_finding_type(self):
        # S3_PUBLIC_VIA_ACL is mapped in every mapping file we ship.
        # The loader combines all of them into one flat list.
        refs = get_framework_references("S3_PUBLIC_VIA_ACL")
        assert len(refs) > 0

    def test_combines_references_from_all_four_frameworks(self):
        # S3_PUBLIC_VIA_ACL has entries in nis2, ncsc_caf, mitre_attack,
        # and cyber_essentials mapping files. The loader must combine
        # them so a downstream reader sees all four framework names.
        refs = get_framework_references("S3_PUBLIC_VIA_ACL")
        frameworks_present = {r.framework for r in refs}
        assert frameworks_present == {
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
        }

    def test_returns_empty_tuple_for_unknown_finding_type(self):
        # An ID that doesn't exist in any mapping file should give
        # back an empty tuple rather than raise. The scanner will
        # normally only ask for IDs it just emitted, so this is
        # defensive — but wrong IDs shouldn't crash the whole run.
        refs = get_framework_references("NONSENSE_FINDING_TYPE_XYZ")
        assert refs == ()

    def test_skips_meta_keys_when_iterating(self):
        # Each mapping file starts with a "_meta" block that documents
        # the framework. It must NOT be exposed as if it were a
        # finding type — asking for "_meta" should return nothing.
        refs = get_framework_references("_meta")
        assert refs == ()

    def test_returns_tuple_not_list(self):
        # The scanner passes the return value straight into a
        # frozen Finding dataclass, which expects a tuple. Locking in
        # the tuple type here means a refactor can't silently turn
        # this into a list and break the frozen invariant downstream.
        refs = get_framework_references("S3_PUBLIC_VIA_ACL")
        assert isinstance(refs, tuple)
        # Each item is itself a FrameworkReference dataclass instance
        # (also frozen), not a raw dict.
        for ref in refs:
            assert isinstance(ref, FrameworkReference)
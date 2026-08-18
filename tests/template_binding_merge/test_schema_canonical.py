from __future__ import annotations

from copy import deepcopy
import unittest

import yaml

from template_binding_merge.canonical import (
    canonical_merge_bytes,
    canonical_source_map_bytes,
    merge_digest,
    source_map_digest,
)
from template_binding_merge.validate import (
    validate_bound_source,
    validate_merge,
    validate_source_map,
)
from tests.template_binding_merge.common import ROOT, built, reidentify


class ClosedSchemaTests(unittest.TestCase):
    def test_five_schema_documents_are_closed_at_root(self) -> None:
        names = (
            "merge.schema.yaml", "bound_source.schema.yaml", "source_map.schema.yaml",
            "adaptation_proposal.schema.yaml", "validation.schema.yaml",
        )
        for name in names:
            with self.subTest(name=name):
                schema = yaml.safe_load((ROOT / "template_binding_merge" / name).read_text(encoding="utf-8"))
                self.assertFalse(schema["additionalProperties"])
                self.assertIn("required", schema)

    def test_recursive_unknown_merge_field_is_rejected(self) -> None:
        _, merge, _ = built()
        merge["slot_bindings"][0]["provider_confidence"] = 1
        self.assertTrue(any("unknown field" in error or "forbidden" in error for error in validate_merge(merge)))

    def test_recursive_unknown_source_map_field_is_rejected(self) -> None:
        _, _, rendered = built()
        source_map = deepcopy(rendered.source_map)
        source_map["regions"][0]["mystery"] = True
        self.assertTrue(any("unknown field" in error for error in validate_source_map(source_map)))

    def test_closed_enum_is_rejected(self) -> None:
        _, merge, _ = built()
        merge["adaptation_holes"][0]["resolver"] = "LLM_DECIDES"
        self.assertTrue(any("unknown value" in error for error in validate_merge(merge)))

    def test_forbidden_verdict_field_is_rejected_recursively(self) -> None:
        _, merge, _ = built()
        merge["construction"]["verdict"] = "SATISFIED"
        errors = validate_merge(merge)
        self.assertTrue(any("forbidden" in error for error in errors))

    def test_bound_source_repo_relative_path_is_enforced(self) -> None:
        _, _, rendered = built()
        value = deepcopy(rendered.bound_source)
        value["source_artifact_ref"] = "/tmp/escaped.c"
        self.assertTrue(any("repo-relative" in error for error in validate_bound_source(value)))


class CanonicalTests(unittest.TestCase):
    def test_merge_canonical_bytes_and_digest_are_stable(self) -> None:
        _, merge, _ = built()
        self.assertEqual(canonical_merge_bytes(merge), canonical_merge_bytes(deepcopy(merge)))
        self.assertEqual(merge_digest(merge), merge_digest(deepcopy(merge)))

    def test_set_and_record_order_do_not_change_merge_identity(self) -> None:
        _, merge, _ = built()
        reordered = deepcopy(merge)
        reordered["slot_bindings"].reverse()
        reordered["construction"]["canonical_upstream_refs"].reverse()
        reordered["merge_id"] = merge["merge_id"]
        self.assertEqual(canonical_merge_bytes(merge), canonical_merge_bytes(reordered))

    def test_semantic_change_changes_merge_identity(self) -> None:
        _, merge, _ = built()
        changed = deepcopy(merge)
        changed["slot_bindings"][0]["target_semantic_ref"] = "semantic:different"
        changed = reidentify(changed)
        self.assertNotEqual(merge["merge_id"], changed["merge_id"])

    def test_source_map_region_input_order_is_canonical(self) -> None:
        _, _, rendered = built()
        reordered = deepcopy(rendered.source_map)
        reordered["regions"].reverse()
        self.assertEqual(canonical_source_map_bytes(rendered.source_map), canonical_source_map_bytes(reordered))
        self.assertEqual(source_map_digest(rendered.source_map), source_map_digest(reordered))


if __name__ == "__main__":
    unittest.main()

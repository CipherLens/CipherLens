import ast
import copy
import hashlib
import unittest
from pathlib import Path

from real_campaign_bridge.c1_fix10 import FIX2, FIX9
from template_binding_merge.executable_completion import (
    CAPTURE_REGION_REF,
    ExecutableCompletionBlocked,
    render_executable_bound_source,
)


ROOT = Path(__file__).resolve().parents[2]


def _load_json(ref):
    import json

    return json.loads((ROOT / ref).read_text(encoding="utf-8"))


class ExecutableCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = (ROOT / FIX2 / "bound_source.c").read_bytes()
        cls.values = _load_json(FIX9 / "resolved_template_values.json")
        cls.captures = _load_json(FIX9 / "capture_binding_materialization.json")
        cls.merge = _load_json(FIX2 / "merge.json")
        cls.candidate = _load_json(FIX2 / "candidate_binding.json")

    def _render(self, values=None, captures=None):
        return render_executable_bound_source(
            self.base,
            values or self.values,
            captures or self.captures,
            self.merge,
            self.candidate,
        )

    def test_declared_spec_materializes_an_executable_source(self):
        completion = self._render()
        self.assertNotEqual(self.base, completion.source_bytes)
        self.assertEqual(5, len(completion.hole_records))
        self.assertEqual(3, len(completion.capture_records))
        self.assertIn(b"CIPHERLENS_CAPTURE_V0_1", completion.source_bytes)

    def test_unresolved_semantic_hole_blocks_generation(self):
        values = copy.deepcopy(self.values)
        values["status"] = "BLOCKED"
        with self.assertRaisesRegex(ExecutableCompletionBlocked, "EXECUTION_BLOCKING_HOLE_UNRESOLVED"):
            self._render(values=values)

    def test_syntax_only_completion_is_allowed_but_semantic_choice_is_not(self):
        self._render()
        values = copy.deepcopy(self.values)
        item = next(value for value in values["resolved_values"] if value["hole_ref"] == "hole:DER_KIND")
        item["resolved_value"] = "public"
        payload = {key: value for key, value in item.items() if key != "digest"}
        from target_knowledge.canonical import canonical_json_bytes

        item["digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        with self.assertRaisesRegex(ExecutableCompletionBlocked, "SEMANTIC_CHOICE_CHANGE_REQUIRES_WHOLE_BINDING_SWITCH"):
            self._render(values=values)

    def test_missing_declared_capture_region_blocks_generation(self):
        captures = copy.deepcopy(self.captures)
        captures["capture_bindings"][0]["capture_region_ref"] = "region:outside-declared-overlay"
        with self.assertRaisesRegex(ExecutableCompletionBlocked, "CAPTURE_INSERTION_OUTSIDE_DECLARED_REGION"):
            self._render(captures=captures)

    def test_all_protected_chunks_remain_byte_identical(self):
        completion = self._render()
        for region in completion.protected_regions:
            before = self.base[region["base_byte_start"]:region["base_byte_end"]]
            after = completion.source_bytes[region["output_byte_start"]:region["output_byte_end"]]
            self.assertEqual(before, after)
            self.assertEqual(region["digest"], hashlib.sha256(before).hexdigest())

    def test_output_and_generated_region_digests_are_stable(self):
        first = self._render()
        second = self._render()
        self.assertEqual(
            hashlib.sha256(first.source_bytes).hexdigest(),
            hashlib.sha256(second.source_bytes).hexdigest(),
        )
        self.assertEqual(first.generated_regions, second.generated_regions)

    def test_capture_records_are_bound_to_the_declared_region(self):
        completion = self._render()
        self.assertEqual(
            {"operation_outcome", "consumed_length", "input_length"},
            {item["semantic_role"] for item in completion.capture_records},
        )
        self.assertTrue(all(item["capture_region_ref"] == CAPTURE_REGION_REF for item in completion.capture_records))

    def test_renderer_has_no_search_regex_or_legacy_filler_dependency(self):
        source = (ROOT / "template_binding_merge/executable_completion.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertFalse(any(name == "re" or "adapter_filler" in name for name in modules))
        self.assertNotIn(".find(", source)
        self.assertNotIn(".index(", source)


if __name__ == "__main__":
    unittest.main()

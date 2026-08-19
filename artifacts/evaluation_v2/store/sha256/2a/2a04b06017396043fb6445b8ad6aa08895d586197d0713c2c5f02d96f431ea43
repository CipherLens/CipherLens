from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from transfer_signature.canonical import validate_signature
from transfer_signature.registry import CONSTRAINT_REGISTRY

from tests.transfer_signature.common import CASES, ROOT, TS_GOLDEN, golden_profile, load_yaml


class LegacyBoundaryTests(unittest.TestCase):
    def test_legacy_names_are_not_canonical_constraints(self):
        forbidden = {"score", "fidelity", "oracle", "rag_evidence", "adapter_validation_rule"}
        self.assertFalse(forbidden.intersection(CONSTRAINT_REGISTRY))

    def test_fidelity_cannot_be_renamed_into_ts(self):
        value = load_yaml(TS_GOLDEN / CASES[0] / "expected.ts.yaml")
        value["fidelity"] = {"target_states": []}
        errors = validate_signature(value, ROOT)
        self.assertTrue(any("fidelity: unknown field" in item for item in errors), errors)

    def test_ts_foundation_has_no_migration_or_rag_runtime_dependency(self):
        package = ROOT / "transfer_signature"
        text = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
        for forbidden in (
            "migration.candidate_mapper",
            "migration.evidence_collector",
            "knowledge.rag",
            "adapter_filler",
            "adapter_validate",
        ):
            self.assertNotIn(forbidden, text)

    def test_legacy_hint_must_remain_non_verified(self):
        value = golden_profile(CASES[0], "eligible")
        value["evidence"][0]["kind"] = "adapter_recipe"
        for fact in value["facts"]:
            fact["epistemic_status"] = "INFERRED"
        from transfer_signature.profile import validate_profile

        self.assertEqual([], validate_profile(value, ROOT))


if __name__ == "__main__":
    unittest.main()

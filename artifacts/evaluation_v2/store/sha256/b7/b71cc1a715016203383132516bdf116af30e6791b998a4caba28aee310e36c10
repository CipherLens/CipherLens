from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

import yaml

from contract_miner.schema import canonical_vc_bytes, validate_vc


ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).parent / "fixtures" / "golden"


def contracts():
    for path in sorted(GOLDEN.glob("*/expected.vc.yaml")):
        yield path, yaml.safe_load(path.read_text(encoding="utf-8"))


class V03SchemaTests(unittest.TestCase):
    def test_all_golden_contracts_validate(self):
        for path, contract in contracts():
            with self.subTest(path=path):
                self.assertEqual([], validate_vc(contract, repo_root=ROOT))

    def test_unknown_nested_field_is_rejected(self):
        _, contract = next(contracts())
        value = deepcopy(contract)
        value["context"]["objects"][0]["surprise"] = True
        errors = validate_vc(value, repo_root=ROOT)
        self.assertTrue(any("surprise: unknown field" in item for item in errors), errors)

    def test_dangling_observable_ref_is_rejected(self):
        path = GOLDEN / "mbedtls_poc_0020" / "expected.vc.yaml"
        value = yaml.safe_load(path.read_text())
        value["expected_relation"]["relations"][0]["operands"]["consumed_length_ref"] = "MISSING"
        errors = validate_vc(value, repo_root=ROOT)
        self.assertTrue(any("dangling reference 'MISSING'" in item for item in errors), errors)

    def test_dangling_step_and_state_refs_are_rejected(self):
        _, contract = next(contracts())
        value = deepcopy(contract)
        value["observable_evidence"]["observables"][0]["source"]["step_ref"] = "MISSING_STEP"
        value["execution"]["steps"][0]["pre_state_ref"] = "MISSING_STATE"
        errors = validate_vc(value, repo_root=ROOT)
        self.assertTrue(any("MISSING_STEP" in item for item in errors), errors)
        self.assertTrue(any("MISSING_STATE" in item for item in errors), errors)

    def test_absolute_evidence_path_is_rejected(self):
        _, contract = next(contracts())
        value = deepcopy(contract)
        value["provenance"]["evidence"][0]["path"] = "/tmp/not-canonical"
        errors = validate_vc(value, repo_root=ROOT)
        self.assertTrue(any("must be repo-relative" in item for item in errors), errors)

    def test_digest_mismatch_is_rejected(self):
        _, contract = next(contracts())
        value = deepcopy(contract)
        value["provenance"]["evidence"][0]["sha256"] = "0" * 64
        errors = validate_vc(value, repo_root=ROOT)
        self.assertTrue(any("digest mismatch" in item for item in errors), errors)

    def test_canonical_serialization_is_byte_stable(self):
        for path, contract in contracts():
            with self.subTest(path=path):
                first = canonical_vc_bytes(contract)
                second = canonical_vc_bytes(yaml.safe_load(first))
                self.assertEqual(first, second)
                self.assertEqual(path.read_bytes(), first)

    def test_contract_has_no_target_verdict_or_legacy_truth_fields(self):
        forbidden = {"roles", "states", "transitions", "guards", "mutation", "oracle", "effect", "fidelity", "verdict"}
        for _, contract in contracts():
            self.assertFalse(forbidden & set(contract))


if __name__ == "__main__":
    unittest.main()

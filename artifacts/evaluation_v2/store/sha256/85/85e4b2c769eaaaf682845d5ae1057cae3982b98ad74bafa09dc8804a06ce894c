from __future__ import annotations

import unittest

from tests.transfer_signature.common import CASES, derive_case


class ProvenanceTests(unittest.TestCase):
    def test_every_constraint_has_field_level_derivation(self):
        for case in CASES:
            signature, _, _ = derive_case(case)
            derivations = {item["derivation_id"]: item for item in signature["provenance"]["derivations"]}
            constraints = signature["required_capabilities"] + signature["excluded_semantics"] + signature["required_observability"]
            for constraint in constraints:
                with self.subTest(case=case, constraint=constraint["constraint_id"]):
                    self.assertTrue(constraint["derivation_refs"])
                    for ref in constraint["derivation_refs"]:
                        self.assertEqual(constraint["constraint_id"], derivations[ref]["constraint_ref"])
                        self.assertTrue(any(source.startswith("contract:/") for source in derivations[ref]["source_refs"]))

    def test_exclusions_are_family_derived_and_observability_references_contract_o(self):
        for case in CASES:
            signature, _, _ = derive_case(case)
            derivations = {item["constraint_ref"]: item for item in signature["provenance"]["derivations"]}
            for constraint in signature["excluded_semantics"]:
                self.assertEqual("family_rule", derivations[constraint["constraint_id"]]["method"])
            for constraint in signature["required_observability"]:
                if constraint["type"] == "contract_observable_resolvable":
                    self.assertEqual({"observable_ref"}, set(constraint["parameters"]))


if __name__ == "__main__":
    unittest.main()

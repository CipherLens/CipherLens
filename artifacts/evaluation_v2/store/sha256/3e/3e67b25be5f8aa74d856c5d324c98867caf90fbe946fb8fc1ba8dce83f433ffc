import unittest

from contract_miner.family_rules import RULE_IDS, apply_family_rule
from contract_miner.relations import RELATION_TYPES


class FamilyRuleTests(unittest.TestCase):
    def test_rules_emit_only_registered_library_independent_relations(self):
        params = {
            "parser_full_consumption_v1": {"parse_step_ref": "PARSE"},
            "failure_output_preservation_v1": {"final_step_ref": "FINAL"},
            "pointer_length_state_consistency_v1": {"zero_update_step_ref": "ZERO", "reuse_step_ref": "REUSE"},
        }
        self.assertEqual(set(params), set(RULE_IDS))
        for rule_id, values in params.items():
            p, o = apply_family_rule(rule_id, values, ["EVIDENCE"])
            self.assertTrue(p["relations"])
            self.assertTrue(o["observables"])
            for relation in p["relations"]:
                self.assertIn(relation["type"], RELATION_TYPES)
                self.assertNotIn(rule_id, relation["type"])


if __name__ == "__main__":
    unittest.main()

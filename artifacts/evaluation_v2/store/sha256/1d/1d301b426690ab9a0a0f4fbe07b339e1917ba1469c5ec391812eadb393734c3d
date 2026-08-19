import unittest

from contract_miner.relations import Observation, evaluate_relation


def obs(name, value, value_type="integer", present=True):
    return Observation(name, present, value, value_type, "fixture")


def rel(relation_id, relation_type, **operands):
    return {"relation_id": relation_id, "type": relation_type, "criticality": "primary", "operands": operands}


class RelationEvaluationTests(unittest.TestCase):
    def test_outcome_requirement(self):
        relation = rel("R", "outcome_requirement", outcome_ref="O", expectation="reject")
        self.assertEqual("HOLDS", evaluate_relation(relation, {"O": obs("O", "reject", "outcome")}).result)
        self.assertEqual("BROKEN", evaluate_relation(relation, {"O": obs("O", "success", "outcome")}).result)

    def test_full_consumption_and_conditional_reject(self):
        relation = rel("R", "full_consumption_on_success", outcome_ref="O", consumed_length_ref="C", input_length_ref="I")
        values = {"O": obs("O", "success", "outcome"), "C": obs("C", 7), "I": obs("I", 9)}
        self.assertEqual("BROKEN", evaluate_relation(relation, values).result)
        rejected = {"O": obs("O", "reject", "outcome")}
        result = evaluate_relation(relation, rejected)
        self.assertEqual("HOLDS", result.result)
        self.assertEqual("RELATION_NOT_ACTIVATED_NO_VIOLATION", result.reason_code)

    def test_output_preserved_on_failure(self):
        relation = rel("R", "output_preserved_on_failure", outcome_ref="O", before_ref="B", after_ref="A")
        values = {"O": obs("O", "reject", "outcome"), "B": obs("B", 0), "A": obs("A", 4)}
        self.assertEqual("BROKEN", evaluate_relation(relation, values).result)
        values["A"] = obs("A", 0)
        self.assertEqual("HOLDS", evaluate_relation(relation, values).result)

    def test_state_invariant(self):
        relation = rel("R", "state_invariant", invariant_id="buffer_absent_implies_length_zero", buffer_present_ref="P", length_ref="L")
        values = {"P": obs("P", False, "boolean"), "L": obs("L", 4)}
        self.assertEqual("BROKEN", evaluate_relation(relation, values).result)
        values["L"] = obs("L", 0)
        self.assertEqual("HOLDS", evaluate_relation(relation, values).result)

    def test_transition_constraint(self):
        relation = rel("R", "transition_constraint", outcome_ref="O", state_before_ref="B", state_after_ref="A", expected_state_ref="FINALIZED", policy="required")
        values = {"O": obs("O", "success", "outcome"), "B": obs("B", "UPDATED", "state"), "A": obs("A", "FINALIZED", "state")}
        self.assertEqual("HOLDS", evaluate_relation(relation, values).result)
        values["A"] = obs("A", "UPDATED", "state")
        self.assertEqual("BROKEN", evaluate_relation(relation, values).result)

    def test_failure_propagation(self):
        relation = rel("R", "failure_propagation", inner_outcome_ref="INNER", outer_outcome_ref="OUTER")
        values = {"INNER": obs("INNER", "reject", "outcome"), "OUTER": obs("OUTER", "success", "outcome")}
        self.assertEqual("BROKEN", evaluate_relation(relation, values).result)
        values["OUTER"] = obs("OUTER", "reject", "outcome")
        self.assertEqual("HOLDS", evaluate_relation(relation, values).result)

    def test_null_event_is_present_and_distinct_from_missing(self):
        relation = rel("R", "no_fatal_event", fatal_event_ref="F")
        present_null = {"F": obs("F", None, "event", present=True)}
        self.assertEqual("HOLDS", evaluate_relation(relation, present_null).result)
        fatal = {"F": obs("F", "signal_sigsegv", "event", present=True)}
        self.assertEqual("BROKEN", evaluate_relation(relation, fatal).result)
        missing = evaluate_relation(relation, {})
        self.assertEqual("NOT_EVALUABLE", missing.result)
        self.assertEqual(("F",), missing.missing_observables)

    def test_wrong_observable_type_is_not_evaluable(self):
        relation = rel("R", "full_consumption_on_success", outcome_ref="O", consumed_length_ref="C", input_length_ref="I")
        values = {"O": obs("O", "success", "outcome"), "C": obs("C", "7", "integer"), "I": obs("I", 7)}
        result = evaluate_relation(relation, values)
        self.assertEqual("NOT_EVALUABLE", result.result)
        self.assertEqual("WRONG_OBSERVABLE_TYPE", result.reason_code)


if __name__ == "__main__":
    unittest.main()

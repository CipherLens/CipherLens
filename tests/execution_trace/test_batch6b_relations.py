from __future__ import annotations

from copy import deepcopy
import unittest

from contract_miner.relation_instance import evaluate_relation_instance_observations, evaluate_source_trace_relations
from contract_miner.relations import Observation
from contract_miner.trace import load_trace
from execution_model.canonical import artifact_digest
from execution_trace.closure import build_unknown_closure
from execution_trace.legacy_import import import_legacy_result
from execution_trace.verdict import aggregate_execution_verdict
from tests.execution_support import chain
from tests.template_binding_merge.common import ROOT


def obs(ref: str, value, kind: str = "state") -> Observation:
    return Observation(ref, True, value, kind, "synthetic")


class RelationAndVerdictTests(unittest.TestCase):
    def test_44_outcome_requirement_h_b_ne(self) -> None:
        self.assertEqual("SATISFIED", chain("mbedtls_poc_0004", values={"FINAL_OUTCOME": "reject"})["verdict"]["verdict"])
        broken = chain("mbedtls_poc_0004", values={"FINAL_OUTCOME": "success"})["evaluations"][0]
        ne = chain("mbedtls_poc_0004", statuses={"FINAL_OUTCOME": "INVALID_VALUE"})["evaluations"][0]
        self.assertEqual(("BROKEN", "NOT_EVALUABLE"), (broken["result"], ne["result"]))

    def test_45_full_consumption_h_b_ne(self) -> None:
        holds = chain(values={"CONSUMED_LENGTH": 10}); broken = chain(values={"CONSUMED_LENGTH": 7}); ne = chain(statuses={"CONSUMED_LENGTH": "ACQUISITION_FAILED"})
        self.assertEqual(["HOLDS", "BROKEN", "NOT_EVALUABLE"], [holds["evaluations"][0]["result"], broken["evaluations"][0]["result"], ne["evaluations"][0]["result"]])

    def test_46_output_preserved_h_b_ne(self) -> None:
        holds = chain("mbedtls_poc_0004"); broken = chain("mbedtls_poc_0004", values={"OUTPUT_LENGTH_AFTER": 4}); ne = chain("mbedtls_poc_0004", values={"FINAL_OUTCOME": "success"})
        self.assertEqual(["HOLDS", "BROKEN", "NOT_EVALUABLE"], [holds["evaluations"][1]["result"], broken["evaluations"][1]["result"], ne["evaluations"][1]["result"]])

    def test_47_state_invariant_h_b_ne(self) -> None:
        holds = chain("mbedtls_poc_0005", statuses={"REUSE_FATAL_EVENT": "OBSERVED_ABSENCE"}); broken = chain("mbedtls_poc_0005", values={"STORED_LENGTH_AFTER_ZERO": 4}, statuses={"REUSE_FATAL_EVENT": "NOT_REACHED"}); ne = chain("mbedtls_poc_0005", values={"STORED_LENGTH_AFTER_ZERO": -1}, statuses={"REUSE_FATAL_EVENT": "NOT_REACHED"})
        self.assertEqual(["HOLDS", "BROKEN", "NOT_EVALUABLE"], [holds["evaluations"][0]["result"], broken["evaluations"][0]["result"], ne["evaluations"][0]["result"]])

    def test_48_transition_constraint_h_b_ne(self) -> None:
        relation = {"relation_id": "R", "type": "transition_constraint", "operands": {"outcome_ref": "O", "state_before_ref": "B", "state_after_ref": "A", "expected_state_ref": "ready", "policy": "required"}}
        base = {"O": obs("O", "success", "outcome"), "B": obs("B", "init"), "A": obs("A", "ready")}
        holds = evaluate_relation_instance_observations(relation, base)
        broken = evaluate_relation_instance_observations(relation, {**base, "A": obs("A", "bad")})
        ne = evaluate_relation_instance_observations(relation, {"O": base["O"]})
        self.assertEqual(["HOLDS", "BROKEN", "NOT_EVALUABLE"], [holds.result, broken.result, ne.result])

    def test_49_failure_propagation_h_b_ne(self) -> None:
        relation = {"relation_id": "R", "type": "failure_propagation", "operands": {"inner_outcome_ref": "I", "outer_outcome_ref": "O"}}
        holds = evaluate_relation_instance_observations(relation, {"I": obs("I", "reject", "outcome"), "O": obs("O", "reject", "outcome")})
        broken = evaluate_relation_instance_observations(relation, {"I": obs("I", "reject", "outcome"), "O": obs("O", "success", "outcome")})
        ne = evaluate_relation_instance_observations(relation, {"I": obs("I", "reject", "outcome")})
        self.assertEqual(["HOLDS", "BROKEN", "NOT_EVALUABLE"], [holds.result, broken.result, ne.result])

    def test_50_no_fatal_event_h_b_ne(self) -> None:
        holds = chain("mbedtls_poc_0005", statuses={"REUSE_FATAL_EVENT": "OBSERVED_ABSENCE"})
        broken = chain("mbedtls_poc_0005", values={"REUSE_FATAL_EVENT": "SIGSEGV"})
        ne = chain("mbedtls_poc_0005", statuses={"REUSE_FATAL_EVENT": "NOT_REACHED"})
        self.assertEqual(["HOLDS", "BROKEN", "NOT_EVALUABLE"], [holds["evaluations"][1]["result"], broken["evaluations"][1]["result"], ne["evaluations"][1]["result"]])

    def test_51_guard_not_met_ne(self) -> None:
        evaluation = chain(values={"PARSE_OUTCOME": "reject"})["evaluations"][0]
        self.assertEqual(("NOT_EVALUABLE", "PRECONDITION_NOT_MET"), (evaluation["result"], evaluation["reason_code"]))

    def test_52_consumed_greater_than_input_ne(self) -> None:
        self.assertEqual("NOT_EVALUABLE", chain(values={"CONSUMED_LENGTH": 11})["evaluations"][0]["result"])

    def test_53_negative_length_ne(self) -> None:
        self.assertEqual("NOT_EVALUABLE", chain(values={"CONSUMED_LENGTH": -1})["evaluations"][0]["result"])

    def test_54_no_fatal_channel_unavailable_ne(self) -> None:
        evaluation = chain("mbedtls_poc_0005", statuses={"REUSE_FATAL_EVENT": "CHANNEL_UNAVAILABLE"})["evaluations"][1]
        self.assertEqual(("NOT_EVALUABLE", "CHANNEL_UNAVAILABLE"), (evaluation["result"], evaluation["reason_code"]))

    def test_55_any_admissible_broken_violates(self) -> None:
        self.assertEqual("VIOLATED", chain(values={"CONSUMED_LENGTH": 7})["verdict"]["verdict"])

    def test_56_all_required_hold_satisfies(self) -> None:
        self.assertEqual("SATISFIED", chain()["verdict"]["verdict"])

    def test_57_no_broken_plus_ne_unknown(self) -> None:
        self.assertEqual("UNKNOWN", chain(statuses={"CONSUMED_LENGTH": "NOT_REACHED"})["verdict"]["verdict"])

    def test_58_broken_beats_unrelated_ne(self) -> None:
        data = chain("mbedtls_poc_0005", values={"STORED_LENGTH_AFTER_ZERO": 4}, statuses={"REUSE_FATAL_EVENT": "NOT_REACHED"})
        self.assertEqual(("VIOLATED", ["BROKEN", "NOT_EVALUABLE"]), (data["verdict"]["verdict"], [x["result"] for x in data["evaluations"]]))

    def test_59_no_witness_no_verdict_artifact(self) -> None:
        data = chain(); self.assertIsNone(aggregate_execution_verdict(data["contract"], data["binding"], data["merge"], None, None, data["evaluations"]))

    def test_60_unknown_same_binding_rerun(self) -> None:
        verdict = chain(statuses={"CONSUMED_LENGTH": "ACQUISITION_FAILED"})["verdict"]
        closure = build_unknown_closure(verdict, reason_codes=["ACQUISITION_FAILED"], missing_evidence=["CONSUMED_LENGTH"])
        self.assertEqual("SAME_BINDING_RERUN", closure["plan"]["route"])

    def test_61_unknown_instrumentation_repair(self) -> None:
        verdict = chain(statuses={"CONSUMED_LENGTH": "NOT_REACHED"})["verdict"]
        closure = build_unknown_closure(verdict, reason_codes=["OBSERVATION_NOT_REACHED"], missing_evidence=["CONSUMED_LENGTH"])
        self.assertEqual("INSTRUMENTATION_REPAIR", closure["plan"]["route"])

    def test_62_whole_binding_switch(self) -> None:
        verdict = chain(statuses={"CONSUMED_LENGTH": "CHANNEL_UNAVAILABLE"})["verdict"]
        closure = build_unknown_closure(verdict, reason_codes=["CHANNEL_UNAVAILABLE"], missing_evidence=["CONSUMED_LENGTH"])
        self.assertEqual(("WHOLE_BINDING_SWITCH", True), (closure["plan"]["route"], closure["plan"]["matcher_reentry_required"]))

    def test_63_candidate_binding_immutable(self) -> None:
        data = chain(statuses={"CONSUMED_LENGTH": "CHANNEL_UNAVAILABLE"}); before = artifact_digest_compat(data["binding"])
        build_unknown_closure(data["verdict"], reason_codes=["CHANNEL_UNAVAILABLE"], missing_evidence=["CONSUMED_LENGTH"])
        self.assertEqual(before, artifact_digest_compat(data["binding"]))

    def test_64_merge_immutable(self) -> None:
        data = chain(statuses={"CONSUMED_LENGTH": "NOT_REACHED"}); before = artifact_digest_compat(data["merge"])
        build_unknown_closure(data["verdict"], reason_codes=["OBSERVATION_NOT_REACHED"], missing_evidence=["CONSUMED_LENGTH"])
        self.assertEqual(before, artifact_digest_compat(data["merge"]))

    def test_65_runtime_evidence_cannot_mutate_ts_profile(self) -> None:
        legacy = import_legacy_result({"verdict": "migrated_bug_candidate", "sanitizer": "crash"})
        self.assertFalse(legacy["may_decide_execution_verdict"]); self.assertEqual("NONE", legacy["authority"])

    def test_source_and_target_share_guard_aware_api(self) -> None:
        data = chain(); _, events = load_trace(ROOT / "tests/contract_miner/fixtures/golden/mbedtls_poc_0020/fixed.trace.jsonl")
        results, errors = evaluate_source_trace_relations(data["contract"], events)
        self.assertEqual([], errors); self.assertEqual(("NOT_EVALUABLE", "PRECONDITION_NOT_MET"), (results[0].result, results[0].reason_code))


def artifact_digest_compat(value) -> str:
    if "binding_id" in value:
        from candidate_binding.canonical import candidate_binding_digest
        return candidate_binding_digest(value)
    from template_binding_merge.canonical import merge_digest
    return merge_digest(value)


if __name__ == "__main__":
    unittest.main()

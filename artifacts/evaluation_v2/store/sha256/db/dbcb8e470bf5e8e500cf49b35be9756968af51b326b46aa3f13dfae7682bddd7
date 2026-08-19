from __future__ import annotations

from copy import deepcopy
import unittest

from execution_model.canonical import artifact_digest, identify
from execution_model.model import ObservationStatus, PROCESS_EVIDENCE_TYPES, SEMANTIC_EVIDENCE_TYPES
from execution_trace.projection import project_contract_evidence
from execution_trace.relation_eval import evaluate_contract_relations
from tests.execution_support import chain


class TraceProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = chain()

    def project(self, trace):
        return project_contract_evidence(self.data["contract"], self.data["binding"], self.data["merge"], self.data["source_map"], trace)

    def evaluate(self, trace, projection):
        return evaluate_contract_relations(self.data["contract"], self.data["witness"], trace, projection)

    def test_18_trace_canonical_stability(self) -> None:
        self.assertEqual(artifact_digest(self.data["trace"]), artifact_digest(deepcopy(self.data["trace"])))

    def test_19_telemetry_excluded_from_semantic_digest(self) -> None:
        self.assertNotIn("command", self.data["run_record"]); self.assertNotIn("duration", self.data["trace"])

    def test_20_raw_log_is_not_trace(self) -> None:
        text = repr(self.data["trace"]); self.assertNotIn("raw stdout contents", text); self.assertIn("evidence_refs", text)

    def test_21_trace_is_not_verdict(self) -> None:
        self.assertNotIn("verdict", self.data["trace"]); self.assertNotIn("result", self.data["trace"])

    def test_22_present(self) -> None:
        self.assertTrue(all(x["status"] == "PRESENT" for x in self.data["trace"]["semantic_observations"]))

    def test_23_observed_absence(self) -> None:
        data = chain("mbedtls_poc_0005", statuses={"REUSE_FATAL_EVENT": "OBSERVED_ABSENCE"})
        entry = next(x for x in data["projection"]["entries"] if x["contract_observable_ref"] == "REUSE_FATAL_EVENT")
        self.assertEqual(("OBSERVED_ABSENCE", "SUFFICIENT"), (entry["observation_status"], entry["sufficiency"]))

    def test_24_not_reached(self) -> None:
        data = chain(statuses={"CONSUMED_LENGTH": "NOT_REACHED"})
        self.assertEqual("OBSERVATION_NOT_REACHED", data["evaluations"][0]["reason_code"])

    def test_25_channel_unavailable(self) -> None:
        data = chain(statuses={"CONSUMED_LENGTH": "CHANNEL_UNAVAILABLE"})
        self.assertEqual("CHANNEL_UNAVAILABLE", data["evaluations"][0]["reason_code"])

    def test_26_acquisition_failed(self) -> None:
        data = chain(statuses={"CONSUMED_LENGTH": "ACQUISITION_FAILED"})
        self.assertEqual("ACQUISITION_FAILED", data["evaluations"][0]["reason_code"])

    def test_27_invalid_value(self) -> None:
        data = chain(statuses={"CONSUMED_LENGTH": "INVALID_VALUE"})
        self.assertEqual("INVALID_VALUE", data["evaluations"][0]["reason_code"])

    def test_28_conflicting_evidence(self) -> None:
        trace = deepcopy(self.data["trace"]); duplicate = deepcopy(trace["semantic_observations"][1]); duplicate["observation_id"] = "trace-observation:duplicate"; duplicate["value"] = 7; trace["semantic_observations"].append(duplicate); trace = identify(trace)
        projection = self.project(trace); entry = next(x for x in projection["entries"] if x["contract_observable_ref"] == duplicate["contract_observable_ref"])
        self.assertEqual(("CONFLICTING_EVIDENCE", "CONFLICTING"), (entry["observation_status"], entry["sufficiency"]))

    def test_29_present_explicit_null_is_not_missing(self) -> None:
        data = chain("mbedtls_poc_0005")
        entry = next(x for x in data["projection"]["entries"] if x["contract_observable_ref"] == "REUSE_FATAL_EVENT")
        self.assertEqual(("PRESENT", "EXPLICIT_NULL", "SUFFICIENT"), (entry["observation_status"], entry["value_presence"], entry["sufficiency"]))

    def test_30_operation_outcome_is_not_process_exit(self) -> None:
        data = chain(statuses={"PARSE_OUTCOME": "CHANNEL_UNAVAILABLE"})
        self.assertTrue(data["trace"]["process_evidence"]); self.assertEqual("NOT_EVALUABLE", data["evaluations"][0]["result"])

    def test_31_signal_does_not_establish_operation_outcome(self) -> None:
        self.assertIn("signal", PROCESS_EVIDENCE_TYPES); self.assertNotIn("signal", SEMANTIC_EVIDENCE_TYPES)

    def test_32_sanitizer_does_not_establish_verdict(self) -> None:
        self.assertIn("sanitizer_event", PROCESS_EVIDENCE_TYPES); self.assertNotIn("sanitizer_event", SEMANTIC_EVIDENCE_TYPES)

    def test_33_correlation_subject_mismatch(self) -> None:
        trace = deepcopy(self.data["trace"]); trace["semantic_observations"][0]["subject_ref"] = "subject:other"; trace = identify(trace); projection = self.project(trace)
        self.assertEqual("NOT_EVALUABLE", self.evaluate(trace, projection)[0]["result"])

    def test_34_correlation_identity_mismatch(self) -> None:
        trace = deepcopy(self.data["trace"]); trace["semantic_observations"][0]["identity_group_ref"] = "identity:other"; trace = identify(trace); projection = self.project(trace)
        evaluation = self.evaluate(trace, projection)[0]; self.assertEqual(("NOT_EVALUABLE", "IDENTITY_MISMATCH"), (evaluation["result"], evaluation["reason_code"]))

    def test_35_correlation_operation_mismatch(self) -> None:
        trace = deepcopy(self.data["trace"]); trace["semantic_observations"][0]["operation_ref"] = "operation:other"; trace = identify(trace); projection = self.project(trace)
        self.assertEqual("NOT_EVALUABLE", self.evaluate(trace, projection)[0]["result"])

    def test_36_correlation_phase_mismatch(self) -> None:
        trace = deepcopy(self.data["trace"]); trace["semantic_observations"][0]["phase"] = "FOLLOWUP"; trace = identify(trace); projection = self.project(trace)
        self.assertEqual("NOT_EVALUABLE", self.evaluate(trace, projection)[0]["result"])

    def test_37_correlation_witness_mismatch(self) -> None:
        trace = deepcopy(self.data["trace"]); trace["witness_ref"] = "witness:other"; trace = identify(trace); projection = self.project(trace)
        self.assertEqual("WITNESS_LINEAGE_MISMATCH", self.evaluate(trace, projection)[0]["reason_code"])

    def test_38_evidence_conflict_never_votes(self) -> None:
        data = chain(statuses={"CONSUMED_LENGTH": "CONFLICTING_EVIDENCE"})
        self.assertEqual(("NOT_EVALUABLE", "UNKNOWN"), (data["evaluations"][0]["result"], data["verdict"]["verdict"]))

    def test_39_contract_o_exact_projection(self) -> None:
        for entry in self.data["projection"]["entries"]:
            self.assertTrue(entry["observation_binding_ref"] and entry["merge_capture_ref"] and entry["source_map_capture_ref"])

    def test_40_projection_missing_observable(self) -> None:
        data = chain(statuses={"INPUT_LENGTH": "ACQUISITION_FAILED"}); entry = next(x for x in data["projection"]["entries"] if x["contract_observable_ref"] == "INPUT_LENGTH")
        self.assertEqual(("INSUFFICIENT", ["INPUT_LENGTH"]), (entry["sufficiency"], entry["missing_requirements"]))

    def test_41_projection_invalid_correlation(self) -> None:
        trace = deepcopy(self.data["trace"])
        for item in trace["semantic_observations"]: item["correlation_group_ref"] = "correlation:undeclared"
        trace = identify(trace); projection = self.project(trace)
        self.assertTrue(all(x["correlation_state"] == "INVALID" for x in projection["entries"]))

    def test_42_no_fuzzy_projection(self) -> None:
        trace = deepcopy(self.data["trace"]); trace["semantic_observations"][0]["contract_observable_ref"] += "_SIMILAR"; trace = identify(trace); projection = self.project(trace)
        self.assertIn("ACQUISITION_FAILED", {x["observation_status"] for x in projection["entries"]})

    def test_43_no_llm_projection(self) -> None:
        self.assertNotIn("llm", repr(self.data["projection"]).lower()); self.assertNotIn("ranking", repr(self.data["projection"]).lower())


if __name__ == "__main__":
    unittest.main()

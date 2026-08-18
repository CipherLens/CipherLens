from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

import yaml

from binding_proposal.validate import validate_payload
from candidate_binding.validate import validate_candidate_binding
from contract_miner.schema import validate_vc
from execution_model.canonical import artifact_digest
from execution_trace.legacy_import import import_legacy_result
from impact_bridge.caller_bridge import build_caller_impact_bridge, verified_call_site
from impact_bridge.violation_package import build_violation_evidence_package
from matcher.orchestrate import run_matcher
from template_binding_merge.canonical import merge_digest
from transfer_signature.canonical import validate_signature
from tests.execution_support import chain
from tests.matcher.common import case_request
from tests.template_binding_merge.common import ROOT


def violation_package(data):
    return build_violation_evidence_package(
        contract=data["contract"], candidate_binding=data["binding"], merge=data["merge"],
        merge_validation=data["validation"], bound_source=data["bound_source"], source_map=data["source_map"],
        build_spec=data["build_spec"], build_record=data["build_record"], run_spec=data["run_spec"],
        run_record=data["run_record"], witness=data["witness"], trace=data["trace"],
        evaluations=data["evaluations"], verdict=data["verdict"],
        supporting_raw_artifacts=[{"artifact_ref": "raw:run.stdout", "artifact_digest": data["run_record"]["raw_artifacts"][0]["artifact_digest"]}],
        reproduction_metadata_refs=["reproduction:synthetic-replay"],
    )


def caller_bridge(data, package, advisory=()):
    evidence = verified_call_site(repository_revision="ef244896", file_path=ROOT / "runner" / "family_compile_runner.py", repository_root=ROOT, line=1, symbol="run", callee="target")
    return build_caller_impact_bridge(
        package, data["verdict"], repository_snapshot={"repository_ref": "repo:cipherlens", "revision": "ef244896", "tree_digest": "a" * 64},
        verified_caller_evidence=[evidence], advisory_impact=advisory,
    )


class ImpactAndGoldenTests(unittest.TestCase):
    def test_66_violation_package_only_from_violated(self) -> None:
        violated = chain(values={"CONSUMED_LENGTH": 7}); self.assertTrue(violation_package(violated)["package_id"])
        satisfied = chain()
        with self.assertRaises(ValueError): violation_package(satisfied)

    def test_67_caller_bridge_is_one_way(self) -> None:
        data = chain(values={"CONSUMED_LENGTH": 7}); bridge = caller_bridge(data, violation_package(data))
        self.assertTrue(bridge["claim_policy"]["one_way"]); self.assertEqual(data["verdict"]["verdict_id"], bridge["execution_verdict_ref"])

    def test_68_legacy_caller_verdict_shortcut_rejected(self) -> None:
        imported = import_legacy_result({"verdict": "vulnerability_confirmed", "sanitizer": "SIGSEGV"})
        self.assertEqual("NONE", imported["authority"]); self.assertFalse(imported["may_decide_execution_verdict"])

    def test_69_advisory_impact_cannot_modify_verdict(self) -> None:
        data = chain(values={"CONSUMED_LENGTH": 7}); before = artifact_digest(data["verdict"])
        bridge = caller_bridge(data, violation_package(data), advisory=[{"provider": "ImpactLiftReplay", "interpretation": "possible reachability"}])
        self.assertEqual(before, artifact_digest(data["verdict"])); self.assertFalse(bridge["advisory_impact"][0]["may_modify_execution_verdict"])

    def test_70_0020_golden(self) -> None:
        scenarios = load_scenarios("mbedtls_poc_0020")
        for item in scenarios.values():
            values = {k: v for k, v in item.items() if k in {"PARSE_OUTCOME", "CONSUMED_LENGTH", "INPUT_LENGTH"}}
            data = chain(values=values); self.assertEqual(item["expected_relation"], data["evaluations"][0]["result"])
            if "expected_verdict" in item: self.assertEqual(item["expected_verdict"], data["verdict"]["verdict"])

    def test_71_0004_golden(self) -> None:
        scenarios = load_scenarios("mbedtls_poc_0004")
        for item in scenarios.values():
            values = {k: v for k, v in item.items() if k in {"FINAL_OUTCOME", "OUTPUT_LENGTH_BEFORE", "OUTPUT_LENGTH_AFTER"}}
            data = chain("mbedtls_poc_0004", values=values)
            self.assertEqual(item["expected_relations"], [x["result"] for x in data["evaluations"]]); self.assertEqual(item["expected_verdict"], data["verdict"]["verdict"])

    def test_72_0005_golden(self) -> None:
        scenarios = load_scenarios("mbedtls_poc_0005")
        for item in scenarios.values():
            values = {k: v for k, v in item.items() if k in {"BUFFER_PRESENT_AFTER_ZERO", "STORED_LENGTH_AFTER_ZERO", "REUSE_FATAL_EVENT"}}
            data = chain("mbedtls_poc_0005", values=values, statuses={"REUSE_FATAL_EVENT": item["fatal_status"]})
            self.assertEqual(item["expected_relations"], [x["result"] for x in data["evaluations"]]); self.assertEqual(item["expected_verdict"], data["verdict"]["verdict"])

    def test_73_contract_regression(self) -> None:
        data = chain(); self.assertEqual([], validate_vc(data["contract"], repo_root=ROOT))

    def test_74_transfer_signature_regression(self) -> None:
        value = yaml.safe_load((ROOT / "tests/transfer_signature/fixtures/golden/mbedtls_poc_0020/expected.ts.yaml").read_text())
        self.assertEqual([], validate_signature(value))

    def test_75_binding_proposal_regression(self) -> None:
        payload = json.loads((ROOT / "tests/binding_proposal/fixtures/replay_payload.json").read_text())
        self.assertEqual([], validate_payload(payload))

    def test_76_candidate_binding_regression(self) -> None:
        value = yaml.safe_load((ROOT / "tests/candidate_binding/fixtures/golden/mbedtls_poc_0020/valid.binding.yaml").read_text())
        self.assertEqual([], validate_candidate_binding(value))

    def test_77_matcher_regression(self) -> None:
        request, replay, backend = case_request("mbedtls_poc_0020"); result = run_matcher(request)
        self.assertEqual("MATCH_FOUND", result.outcome.value); self.assertEqual(0, backend.network_call_count)

    def test_78_merge_regression(self) -> None:
        data = chain(); self.assertEqual(data["handoff"]["merge_digest"], merge_digest(data["merge"]))


def load_scenarios(family: str):
    path = ROOT / "tests" / "execution_trace" / "fixtures" / "golden" / family / "scenarios.yaml"
    return yaml.safe_load(path.read_text())["scenarios"]


if __name__ == "__main__":
    unittest.main()

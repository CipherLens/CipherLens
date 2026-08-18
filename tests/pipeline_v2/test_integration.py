from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from dataclasses import replace
from contract_miner.schema import contract_digest
from template_binding_merge.adaptation import build_adaptation_proposal

from pipeline_v2.artifact_store import ArtifactIntegrityError, ArtifactStore
from pipeline_v2.attempt import PipelineAttempt
from pipeline_v2.campaign import CampaignPolicy, CampaignState, CampaignSummary, dispatch_retry
from pipeline_v2.console import CanonicalConsoleAdapter
from pipeline_v2.matcher_merge import match_then_merge
from pipeline_v2.knowledge_adapter import MatcherReentryKnowledgeAdapter
from pipeline_v2.impact import bridge_violation
from pipeline_v2.merge_execution import prepare_merge_execution
from pipeline_v2.replay import replay_attempt
from pipeline_v2.routing import BudgetState, route_unknown_with_budget
from pipeline_v2.model import RetryBudget
from pipeline_v2.runner_backend import PipelineRunnerBackend, RunnerConfiguration
from tests.matcher.common import ROOT, case_request
from tests.template_binding_merge.common import built, inputs, proposal_hole


def _configuration() -> RunnerConfiguration:
    return RunnerConfiguration(
        toolchain={"compiler": "cc", "version_profile_digest": "1" * 64},
        compile_flags=("-std=c11",), link_flags=(),
        expected_output={"artifact_ref": "build:synthetic-binary", "kind": "EXECUTABLE"},
        instrumentation_profile={"profile_ref": "instrumentation:none", "profile_digest": "2" * 64},
        environment_profile={"profile_ref": "environment:controlled", "profile_digest": "3" * 64},
        working_directory_profile={"profile_ref": "cwd:isolated", "logical_directory": "run"},
        timeout_policy={"policy_ref": "timeout:short", "limit_seconds": 10}, compiler_path="cc",
    )


class _FakeRunner:
    def __init__(self, captures: dict[str, str], values: dict[str, object], statuses: dict[str, str], stderr: str = "", failure: str = "") -> None:
        self.captures, self.values, self.statuses, self.stderr, self.failure = captures, values, statuses, stderr, failure

    def __call__(self, command: list[str], **kwargs: object) -> SimpleNamespace:
        if "-c" in command:
            if self.failure == "compile": return SimpleNamespace(returncode=1, stdout="", stderr="compile failed")
            Path(command[command.index("-o") + 1]).write_bytes(b"synthetic-object")
        elif "-o" in command:
            if self.failure == "link": return SimpleNamespace(returncode=1, stdout="", stderr="link failed")
            Path(command[command.index("-o") + 1]).write_bytes(b"synthetic-binary")
        else:
            if self.failure == "run": raise FileNotFoundError("synthetic launch failure")
            records = []
            for index, (observable, capture) in enumerate(sorted(self.captures.items())):
                status = self.statuses.get(observable, "PRESENT")
                value = self.values.get(observable)
                presence = "NONE" if status != "PRESENT" else ("EXPLICIT_NULL" if value is None else "VALUE")
                records.append("ORACLE_EVENT " + json.dumps({
                    "capture_binding_ref": capture, "status": status, "value_presence": presence,
                    "value": value if presence != "NONE" else None, "sequence_index": index,
                    "channel_active": status != "CHANNEL_UNAVAILABLE", "phase_reached": status != "NOT_REACHED",
                }))
            return SimpleNamespace(returncode=0, stdout="\n".join(records) + "\n", stderr=self.stderr)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _pipeline_context(family: str, *, values: dict[str, object] | None = None, statuses: dict[str, str] | None = None, stderr: str = "", failure: str = ""):
    request, _, _ = case_request(family)
    bundle = inputs(family)[0]
    bridge = match_then_merge(request, bundle)
    prepared = prepare_merge_execution(contract=request.contract, gate=bridge.merge_gate, merge=bridge.merge, repo_root=ROOT)
    captures = {item["contract_observable_ref"]: item["capture_binding_id"] for item in prepared.merge["observation_capture_bindings"]}
    defaults = {
        "PARSE_OUTCOME": "success", "CONSUMED_LENGTH": 10, "INPUT_LENGTH": 10,
        "FINAL_OUTCOME": "reject", "OUTPUT_LENGTH_BEFORE": 0, "OUTPUT_LENGTH_AFTER": 0,
        "BUFFER_PRESENT_AFTER_ZERO": False, "STORED_LENGTH_AFTER_ZERO": 0, "REUSE_FATAL_EVENT": None,
    }
    defaults.update(values or {})
    temp = tempfile.TemporaryDirectory()
    store = ArtifactStore(Path(temp.name) / "store")
    backend = PipelineRunnerBackend(store, _configuration(), runner=_FakeRunner(captures, defaults, statuses or {}, stderr, failure))
    return temp, store, PipelineAttempt(store, backend), request, bundle


def _run_pipeline(family: str, *, values: dict[str, object] | None = None, statuses: dict[str, str] | None = None, stderr: str = ""):
    temp, store, pipeline, request, bundle = _pipeline_context(family, values=values, statuses=statuses, stderr=stderr)
    result = pipeline.run(attempt_id="attempt:" + family, request=request, bundle=bundle)
    return temp, store, result


class ArtifactStoreTests(unittest.TestCase):
    def test_content_addressed_immutable_ref_digest_checked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ArtifactStore(directory)
            artifact = store.put_raw("raw/example", b"abc")
            self.assertEqual(b"abc", store.get(artifact.ref, artifact.digest))
            self.assertTrue(store.exists(artifact.ref, artifact.digest))
            self.assertEqual(artifact, store.put_raw("raw/example", b"abc"))
            with self.assertRaises(ArtifactIntegrityError): store.put_raw("raw/example", b"different")
            with self.assertRaises(ArtifactIntegrityError): store.get("raw/other", artifact.digest)
            with self.assertRaises(ArtifactIntegrityError): store.put_raw("../escape", b"x")
            with self.assertRaises(ArtifactIntegrityError): store.put_raw("/absolute", b"x")

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            store = ArtifactStore(directory)
            digest = __import__("hashlib").sha256(b"x").hexdigest()
            target = Path(directory) / "store" / "sha256" / digest[:2]
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.symlink(outside, target)
            except FileExistsError:
                self.skipTest("platform pre-created content shard")
            with self.assertRaises(ArtifactIntegrityError): store.put_raw("raw/x", b"x")


class EndToEndIntegrationTests(unittest.TestCase):
    def test_merge_execution_routes_completion_then_constrained_adaptation(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020")
        replacement = "/* exact syntax glue */"
        gated, merge, _ = built(additional_holes=[proposal_hole(replacement)])
        phases: list[str] = []

        def provider(current_merge: dict, rendered: object) -> dict:
            edit = {
                "edit_id": "edit:proposal-declaration",
                "edit_type": "FILL_HOLE",
                "hole_ref": "hole:proposal-declaration",
                "base_source_digest": rendered.bound_source["source_digest"],
                "expected_syntax_kind": "C_DECLARATION",
                "replacement": replacement,
            }
            return build_adaptation_proposal(
                current_merge,
                rendered.bound_source,
                [edit],
                provider_id="provider:test",
                provider_version="v0.1",
                request_digest="1" * 64,
            )

        prepared = prepare_merge_execution(
            contract=request.contract,
            gate=gated,
            merge=merge,
            repo_root=ROOT,
            adaptation_provider=provider,
            phase_callback=phases.append,
        )
        self.assertEqual(["COMPLETING", "ADAPTING"], phases)
        self.assertEqual("VALID", prepared.validation["status"])
        self.assertEqual("EXECUTION_HANDOFF", prepared.validation["routing"])
        self.assertIsNotNone(prepared.handoff)

    def test_execution_backend_requires_canonical_handoff_and_has_no_source_shortcut(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ArtifactStore(Path(directory) / "store")
            backend = PipelineRunnerBackend(store, _configuration(), runner=lambda *args, **kwargs: None)
            with self.assertRaises(ValueError):
                backend.execute({}, source_bytes=b"int main(void){return 0;}", workspace=Path(directory) / "run", artifact_namespace="attempt:invalid")
            self.assertFalse(hasattr(backend, "run_source_path")); self.assertFalse(hasattr(backend, "execute_source"))

    def test_build_and_launch_failures_never_create_verdict(self) -> None:
        for failure, expected in (("compile", "BUILD_FAILURE"), ("link", "BUILD_FAILURE"), ("run", "RUN_LAUNCH_FAILURE")):
            temp, _, pipeline, request, bundle = _pipeline_context("mbedtls_poc_0004", failure=failure)
            self.addCleanup(temp.cleanup)
            result = pipeline.run(attempt_id=f"attempt:{failure}", request=request, bundle=bundle)
            self.assertEqual(expected, result.outcome.value)
            self.assertIsNone(result.verdict)
            self.assertNotIn("execution_verdict", result.artifacts)

    def test_matcher_merge_rejects_no_match_and_reentry_excludes_prior_surface(self) -> None:
        request, _, _ = case_request("mbedtls_poc_0020")
        bundle = inputs("mbedtls_poc_0020")[0]
        first = match_then_merge(request, bundle)
        self.assertIsNotNone(first.merge)
        reentered = replace(request, knowledge=MatcherReentryKnowledgeAdapter(request.knowledge, excluded_seed_refs=first.excluded_seed_refs))
        second = match_then_merge(reentered, bundle)
        self.assertIsNone(second.merge)
        invalid_request, _, _ = case_request("mbedtls_poc_0020", binding_label="invalid")
        self.assertIsNone(match_then_merge(invalid_request, bundle).merge)

    def test_0020_violated_through_matcher_to_verdict(self) -> None:
        temp, store, result = _run_pipeline("mbedtls_poc_0020", values={"CONSUMED_LENGTH": 7, "INPUT_LENGTH": 10})
        self.addCleanup(temp.cleanup)
        self.assertEqual("VIOLATED_WITNESS", result.outcome.value)
        self.assertEqual("VIOLATED", result.verdict["verdict"])
        request, _, _ = case_request("mbedtls_poc_0020")
        self.assertEqual(contract_digest(request.contract), result.artifacts["contract"].digest)
        self.assertIn("violation_package", result.artifacts)
        self.assertTrue(store.verify(result.artifacts["raw_4"].ref, result.artifacts["raw_4"].digest))
        before = dict(result.verdict)
        caller_bridge, impact_error, discovery = bridge_violation(
            violation_package=result.violation_package, verdict=result.verdict,
            repository_root=ROOT, callee="cipherlens_missing_synthetic_callee",
            symbol="synthetic-caller", build_provenance_refs=["build:test"],
            impact_provider=lambda package, callers: (_ for _ in ()).throw(RuntimeError("offline fake failure")),
        )
        self.assertEqual("RuntimeError", impact_error)
        self.assertEqual(before, result.verdict)
        self.assertEqual(result.verdict["verdict_id"], caller_bridge["execution_verdict_ref"])
        self.assertEqual(0, discovery["caller_count"])

    def test_0004_satisfied_does_not_create_global_safe(self) -> None:
        temp, _, result = _run_pipeline("mbedtls_poc_0004")
        self.addCleanup(temp.cleanup)
        self.assertEqual("SATISFIED_WITNESS", result.outcome.value)
        self.assertEqual("SATISFIED", result.verdict["verdict"])
        self.assertNotIn("global_safe", result.manifest)
        events = result.manifest["events"]
        self.assertEqual(list(range(1, len(events) + 1)), [item["sequence"] for item in events])
        self.assertEqual("CREATED", events[0]["event_type"]); self.assertEqual("CLOSED", events[-1]["event_type"])
        self.assertIn("COMPLETING", [item["event_type"] for item in events])
        self.assertNotIn("verdict", result.manifest)

    def test_0004_violated_and_0005_unknown_and_violated(self) -> None:
        temp1, _, violated = _run_pipeline("mbedtls_poc_0004", values={"OUTPUT_LENGTH_AFTER": 4})
        temp2, _, unknown = _run_pipeline("mbedtls_poc_0005", statuses={"REUSE_FATAL_EVENT": "CHANNEL_UNAVAILABLE"})
        temp3, _, state_broken = _run_pipeline("mbedtls_poc_0005", values={"STORED_LENGTH_AFTER_ZERO": 4})
        self.addCleanup(temp1.cleanup); self.addCleanup(temp2.cleanup); self.addCleanup(temp3.cleanup)
        self.assertEqual("VIOLATED", violated.verdict["verdict"])
        self.assertEqual("UNKNOWN", unknown.verdict["verdict"])
        self.assertIsNotNone(unknown.closure)
        self.assertEqual("VIOLATED", state_broken.verdict["verdict"])

    def test_sanitizer_bytes_are_persisted_but_do_not_shortcut_verdict(self) -> None:
        temp, _, result = _run_pipeline("mbedtls_poc_0004", stderr="ERROR: AddressSanitizer: synthetic")
        self.addCleanup(temp.cleanup)
        self.assertEqual("SATISFIED", result.verdict["verdict"])
        self.assertTrue(any(ref.ref.endswith("/raw:run.sanitizer") for ref in result.artifacts.values()))

    def test_retry_budget_replay_and_console_are_non_authoritative(self) -> None:
        temp, store, pipeline, request, bundle = _pipeline_context("mbedtls_poc_0005", statuses={"REUSE_FATAL_EVENT": "CHANNEL_UNAVAILABLE"})
        self.addCleanup(temp.cleanup)
        result = pipeline.run(attempt_id="attempt:unknown", request=request, bundle=bundle)
        closure, route = route_unknown_with_budget(verdict=result.verdict, state=BudgetState(), budget=CampaignPolicy().retry_budget, reason_codes=["MISSING_REQUIRED_OBSERVABLE"], missing_evidence=["REUSE_FATAL_EVENT"], candidate_ref="binding", merge_ref="merge")
        self.assertEqual("SAME_BINDING_RERUN", route)
        self.assertEqual("SAME_BINDING_RERUN", closure["plan"]["route"])
        state = CampaignState("campaign:unknown")
        instruction = state.schedule_unknown(attempt_id=result.attempt_id, verdict=result.verdict, candidate_ref="binding", merge_ref="merge", binding_ref="binding", reason_codes=["MISSING_REQUIRED_OBSERVABLE"], missing_evidence=["REUSE_FATAL_EVENT"])
        self.assertNotEqual(result.attempt_id, instruction.attempt_id)
        retried = dispatch_retry(instruction, {"SAME_BINDING_RERUN": lambda item: pipeline.run(attempt_id=item.attempt_id, request=request, bundle=bundle)})
        self.assertEqual(result.artifacts["candidate_binding"], retried.artifacts["candidate_binding"])
        self.assertEqual(result.artifacts["merge"], retried.artifacts["merge"])
        self.assertNotEqual(result.attempt_id, retried.attempt_id)
        completion = state.schedule_unknown(attempt_id=result.attempt_id, verdict=result.verdict, candidate_ref="binding", merge_ref="merge", binding_ref="binding", reason_codes=["MISSING_REQUIRED_OBSERVABLE"], missing_evidence=["hole"], merge_completion_available=True)
        repair = state.schedule_unknown(attempt_id=result.attempt_id, verdict=result.verdict, candidate_ref="binding", merge_ref="merge", binding_ref="binding", reason_codes=["OBSERVATION_NOT_REACHED"], missing_evidence=["capture"])
        bridge = match_then_merge(request, bundle)
        binding_ref = result.artifacts["candidate_binding"].ref
        switch = state.schedule_unknown(attempt_id=result.attempt_id, verdict=result.verdict, candidate_ref=binding_ref, merge_ref=result.artifacts["merge"].ref, binding_ref=binding_ref, surface_refs=bridge.excluded_seed_refs, reason_codes=["CHANNEL_UNAVAILABLE"], missing_evidence=["channel"])
        self.assertEqual(("SAME_MERGE_COMPLETION", "INSTRUMENTATION_REPAIR", "WHOLE_BINDING_SWITCH"), (completion.route, repair.route, switch.route))
        self.assertTrue(all(item.attempt_id and item.attempt_id != result.attempt_id for item in (completion, repair, switch)))
        self.assertEqual((binding_ref,), switch.excluded_binding_refs)
        self.assertEqual(tuple(sorted(bridge.excluded_seed_refs)), switch.excluded_surface_refs)
        completion_result = dispatch_retry(completion, {"SAME_MERGE_COMPLETION": lambda item: pipeline.run(attempt_id=item.attempt_id, request=request, bundle=bundle)})
        original_runner = pipeline.runner_backend.runner
        repaired_config = replace(_configuration(), instrumentation_profile={"profile_ref": "instrumentation:repair", "profile_digest": "4" * 64})
        repaired_backend = PipelineRunnerBackend(store, repaired_config, runner=_FakeRunner(original_runner.captures, original_runner.values, {}))
        repaired_pipeline = PipelineAttempt(store, repaired_backend)
        repair_result = dispatch_retry(repair, {"INSTRUMENTATION_REPAIR": lambda item: repaired_pipeline.run(attempt_id=item.attempt_id, request=request, bundle=bundle)})
        switch_request = replace(request, knowledge=MatcherReentryKnowledgeAdapter(request.knowledge, excluded_seed_refs=switch.excluded_surface_refs, excluded_candidate_refs=switch.excluded_binding_refs))
        switch_result = dispatch_retry(switch, {"WHOLE_BINDING_SWITCH": lambda item: pipeline.run(attempt_id=item.attempt_id, request=switch_request, bundle=bundle)})
        for routed in (completion_result, repair_result):
            self.assertEqual(result.artifacts["candidate_binding"], routed.artifacts["candidate_binding"])
            self.assertEqual(result.artifacts["merge"], routed.artifacts["merge"])
            self.assertNotEqual(result.artifacts["raw_0"].ref, routed.artifacts["raw_0"].ref)
        self.assertNotEqual(result.artifacts["build_spec"], repair_result.artifacts["build_spec"])
        self.assertEqual("MATCHER_NO_MATCH", switch_result.outcome.value)
        self.assertNotIn("candidate_binding", switch_result.artifacts)
        replay = replay_attempt(pipeline=pipeline, attempt_id="attempt:replay", request=request, bundle=bundle, prior_attempt_id=result.attempt_id, prior_verdict={"verdict": "VIOLATED"})
        self.assertTrue(replay.divergence); self.assertEqual("REPLAY_DIVERGENCE", replay.reason_code)
        self.assertEqual("attempt:replay", replay.new_attempt.attempt_id)
        policy = RetryBudget()
        self.assertEqual((2, 1, 3, 4, 12, 1, 1), (policy.max_same_binding_reruns, policy.max_instrumentation_repairs, policy.max_whole_binding_switches, policy.max_execution_attempts_per_candidate, policy.max_total_attempts_per_contract_target, policy.max_programmatic_completion_rounds, policy.max_constrained_adaptations_per_merge))
        _, exhausted = route_unknown_with_budget(verdict=result.verdict, state=BudgetState(total_attempts=12), budget=policy, reason_codes=["MISSING_REQUIRED_OBSERVABLE"], missing_evidence=[], candidate_ref="binding", merge_ref="merge")
        self.assertEqual("ATTEMPT_BUDGET_EXHAUSTED", exhausted)
        console = CanonicalConsoleAdapter(store)
        label = console.legacy_display_label("migrated_safe")
        self.assertEqual("legacy_display_only", label["authority"])

    def test_campaign_summary_has_no_security_authority_fields(self) -> None:
        state = CampaignState("campaign:test", CampaignPolicy(stop_on_first_violated=True))
        state.record_attempt({"attempt_id": "a1", "outcome": "VIOLATED_WITNESS", "execution_verdict": "VIOLATED", "violation_package_ref": "package:x"})
        summary = CampaignSummary.from_state(state).to_dict()
        self.assertEqual("POLICY_STOPPED", summary["terminal_control_outcome"])
        self.assertNotIn("library_safe", summary); self.assertNotIn("vulnerability_confirmed", summary)


if __name__ == "__main__":
    unittest.main()

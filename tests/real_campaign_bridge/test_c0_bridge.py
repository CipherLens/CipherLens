from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from candidate_binding.canonical import candidate_binding_digest, validation_digest
from execution_model.canonical import artifact_digest
from execution_pipeline.collect_adapter import oracle_event_acquisitions, sanitizer_evidence
from pipeline_v2.runner_backend import configuration_from_build_profile_mapping
from execution_trace.normalize import build_structured_trace
from execution_trace.projection import project_contract_evidence
from execution_trace.relation_eval import evaluate_contract_relations
from execution_trace.witness import form_execution_witness
from real_campaign_bridge.build_mapping import (
    build_spec_from_profile_mapping,
    map_build_environment_profile,
    mapping_semantic_digest,
)
from real_campaign_bridge.capture_bridge import event_line, make_oracle_event
from real_campaign_bridge.claim_gate_adapter import evaluate_c0_bridge
from real_campaign_bridge.replay_lineage import make_c0_replay_lineage
from real_campaign_bridge.build_profile import make_build_environment_profile
from target_knowledge.canonical import canonical_json_bytes
from template_binding_merge.canonical import (
    bound_source_digest,
    merge_digest,
    merge_validation_digest,
    source_map_digest,
)
from tests.execution_support import built_record, run_record, run_spec, upstream
from tests.template_binding_merge.common import inputs


ROOT = Path(__file__).parents[2]
SHA = "a" * 64


def _profile(*, library: bool = True, missing: bool = False) -> dict:
    fixture_root = ROOT / "tests" / "real_campaign_bridge" / "fixtures" / "c0"

    def fixture_edge(name: str) -> dict[str, str]:
        path = fixture_root / name
        return {"ref": str(path.relative_to(ROOT)), "digest": hashlib.sha256(path.read_bytes()).hexdigest()}

    return make_build_environment_profile(
        source_root=fixture_edge("source_identity.json"),
        source_identity="fixture:c0:0020-fixed", source_tree_digest=fixture_edge("source_identity.json")["digest"],
        compiler_identity={"logical_name": "cc"},
        compiler_version_evidence=fixture_edge("compiler_cc.json"),
        architecture="x86_64", build_system_config=fixture_edge("build_config.json"),
        compile_flags=["-std=c11", "-O0"], link_flags=["-lfixture-c0"],
        include_roots=["fixture:c0:include"], include_path_evidence=[fixture_edge("include_manifest.json")],
        library_inputs=([fixture_edge("library_input.txt")] if library else []),
        artifact_outputs=["fixture:c0:binary"], sanitizer_profile="none", dependencies=[],
        controlled_environment="C0_REPLAY_ONLY", timeout_seconds=10, target_options={},
        input_artifact_digests=[], reproducibility_status="FIXTURE_ONLY",
        missing_artifacts=([{"expected_future_artifact_type": "resolved_library_input", "preparation_status": "MISSING_ARTIFACT"}] if missing else []),
        missing_requirements=[], telemetry={"local_path": "/tmp/c0-replay-only"},
    )


def _edge(ref: str, digest: str) -> dict[str, str]:
    return {"ref": ref, "digest": digest}


class C0BridgeTests(unittest.TestCase):
    def _mapping(self, profile: dict | None = None) -> dict:
        profile = profile or _profile()
        return map_build_environment_profile(
            profile, profile_ref="c0_replay/build_profiles/0020.fixed.fixture.json",
            profile_digest=hashlib.sha256(canonical_json_bytes(profile)).hexdigest(),
        )

    def _v01_events(self, data: dict) -> bytes:
        values = {"PARSE_OUTCOME": "success", "CONSUMED_LENGTH": 10, "INPUT_LENGTH": 10}
        bindings = {item["observation_binding_id"]: item for item in data["binding"]["observation_bindings"]}
        lines = []
        for index, capture in enumerate(data["merge"]["observation_capture_bindings"]):
            binding = bindings[capture["observation_binding_ref"]]
            lines.append(event_line(make_oracle_event(
                witness_ref="fixture:witness:c0", contract_observable_ref=capture["contract_observable_ref"],
                observation_binding_ref=capture["observation_binding_ref"], merge_capture_ref=capture["capture_binding_id"],
                semantic_role=binding["observable_role"], acquisition_kind=capture["acquisition_kind"], phase=capture["phase"],
                subject_ref=capture["target_subject_binding_ref"], operation_ref=capture["target_operation_binding_ref"],
                correlation_group_ref=capture["correlation_refs"][0], status="PRESENT", value_type=capture["value_type"],
                value=values[capture["contract_observable_ref"]], sequence_index=index,
                channel_active=True, phase_reached=True, evidence_digest=hashlib.sha256(f"marker:{index}".encode()).hexdigest(),
            )))
        return ("\n".join(lines) + "\n").encode()

    def _replay_chain(self) -> dict:
        data = upstream("mbedtls_poc_0020")
        mapping = self._mapping()
        spec = build_spec_from_profile_mapping(
            data["handoff"], mapping,
            compile_units=[{"artifact_ref": data["handoff"]["source_artifact_ref"], "artifact_digest": data["handoff"]["source_artifact_digest"], "language": "c"}],
            expected_output={"artifact_ref": "fixture:c0:binary", "kind": "EXECUTABLE"},
            instrumentation_profile={"profile_ref": "fixture:instrumentation:none", "profile_digest": "1" * 64},
            environment_profile={"profile_ref": "fixture:environment:controlled", "profile_digest": "2" * 64},
        )
        build = built_record(spec)
        run = run_spec(spec, build, data["handoff"]["observation_capture_refs"])
        record = run_record(run)
        _, witness = form_execution_witness(
            contract_ref=data["handoff"]["contract_ref"], contract_digest=data["handoff"]["contract_digest"],
            candidate_binding_ref=data["handoff"]["candidate_binding_ref"], candidate_binding_digest=data["handoff"]["candidate_binding_digest"],
            merge_ref=data["merge"]["merge_id"], merge_digest=merge_digest(data["merge"]),
            merge_validation_ref=data["validation"]["validation_id"], merge_validation_digest=merge_validation_digest(data["validation"]),
            bound_source_ref=data["bound_source"]["bound_source_id"], bound_source_digest=bound_source_digest(data["bound_source"]),
            source_map_ref=data["source_map"]["source_map_id"], source_map_digest=source_map_digest(data["source_map"]),
            build_spec=spec, build_record=build, run_spec=run, run_record=record,
            source_artifact_digest=data["handoff"]["source_artifact_digest"],
            acquisition_integrity={"framework_complete": True, "artifact_integrity": True, "lineage_integrity": True, "required_channels_complete": True},
        )
        self.assertIsNotNone(witness)
        _, acquisitions = oracle_event_acquisitions("raw:c0:replay.stdout", self._v01_events(data), allowed_capture_refs=data["handoff"]["observation_capture_refs"])
        trace = build_structured_trace(witness, record, data["merge"], data["binding"], data["contract"], data["source_map"], acquisitions, record["process_events"])
        projection = project_contract_evidence(data["contract"], data["binding"], data["merge"], data["source_map"], trace)
        evaluations = evaluate_contract_relations(data["contract"], witness, trace, projection)
        return {**data, "mapping": mapping, "build_spec": spec, "build_record": build, "run_spec": run, "run_record": record, "witness": witness, "trace": trace, "projection": projection, "evaluations": evaluations}

    def test_profile_mapping_is_path_free_and_does_not_build(self) -> None:
        profile = _profile()
        with patch("execution_pipeline.build_adapter.subprocess.run") as run:
            mapping = self._mapping(profile)
        run.assert_not_called()
        self.assertEqual(mapping["library_inputs"][0]["artifact_ref"], "tests/real_campaign_bridge/fixtures/c0/library_input.txt")
        changed = deepcopy(profile); changed["compile_flags"] = ["-std=c11", "-O2"]
        self.assertNotEqual(mapping_semantic_digest(mapping), mapping_semantic_digest(self._mapping(changed)))
        moved = deepcopy(profile); moved["telemetry"] = {"local_path": "/private/other"}
        self.assertEqual(mapping_semantic_digest(mapping), mapping_semantic_digest(self._mapping(moved)))

    def test_missing_library_stays_an_explicit_blocker(self) -> None:
        mapping = self._mapping(_profile(library=False, missing=True))
        self.assertEqual("MISSING_EXECUTION_INPUTS", mapping["status"])
        self.assertTrue(mapping["missing_artifacts"])
        with self.assertRaises(ValueError):
            build_spec_from_profile_mapping({}, mapping, compile_units=[], expected_output={}, instrumentation_profile={}, environment_profile={})

    def test_mapping_controls_canonical_build_spec_edges_and_flags(self) -> None:
        data = upstream("mbedtls_poc_0020")
        spec = build_spec_from_profile_mapping(
            data["handoff"], self._mapping(),
            compile_units=[{"artifact_ref": data["handoff"]["source_artifact_ref"], "artifact_digest": data["handoff"]["source_artifact_digest"], "language": "c"}],
            expected_output={"artifact_ref": "fixture:c0:binary", "kind": "EXECUTABLE"},
            instrumentation_profile={"profile_ref": "fixture:instrumentation:none", "profile_digest": "1" * 64},
            environment_profile={"profile_ref": "fixture:environment:controlled", "profile_digest": "2" * 64},
        )
        changed = _profile(); changed["compile_flags"] = ["-std=c11", "-O2"]
        other = build_spec_from_profile_mapping(
            data["handoff"], self._mapping(changed), compile_units=spec["compile_units"],
            expected_output=spec["expected_output"], instrumentation_profile=spec["instrumentation_profile"], environment_profile=spec["environment_profile"],
        )
        self.assertEqual("tests/real_campaign_bridge/fixtures/c0/library_input.txt", spec["library_inputs"][0]["artifact_ref"])
        self.assertNotEqual(artifact_digest(spec), artifact_digest(other))
        config = configuration_from_build_profile_mapping(
            self._mapping(), expected_output=spec["expected_output"],
            instrumentation_profile=spec["instrumentation_profile"], environment_profile=spec["environment_profile"],
            working_directory_profile={"profile_ref": "fixture:cwd", "logical_directory": "replay"},
            timeout_policy={"policy_ref": "fixture:timeout", "limit_seconds": 10}, compiler_path="cc",
        )
        self.assertEqual(tuple(spec["include_configs"]), config.include_configs)
        self.assertEqual(tuple(spec["library_inputs"]), config.library_inputs)

    def test_v01_replay_reaches_trace_projection_and_relation_dry_run(self) -> None:
        data = self._replay_chain()
        self.assertEqual("HOLDS", data["evaluations"][0]["result"])
        self.assertEqual("SUFFICIENT", next(item for item in data["projection"]["entries"] if item["contract_observable_ref"] == "CONSUMED_LENGTH")["sufficiency"])
        self.assertNotIn("verdict", data)

    def test_malformed_unknown_or_tampered_v01_event_fails_closed(self) -> None:
        event = make_oracle_event(witness_ref="w", contract_observable_ref="o", observation_binding_ref="b", merge_capture_ref="m", semantic_role="operation_outcome", acquisition_kind="RETURN_VALUE", phase="AFTER_STEP", subject_ref="s", operation_ref="op", correlation_group_ref="g", status="PRESENT", value_type="outcome", value="success")
        line = event_line({**event, "event_digest": "0" * 64})
        with self.assertRaises(ValueError):
            oracle_event_acquisitions("raw:x", line.encode(), allowed_capture_refs=["m"])
        with self.assertRaises(ValueError):
            make_oracle_event(witness_ref="w", contract_observable_ref="o", observation_binding_ref="b", merge_capture_ref="m", semantic_role="unknown", acquisition_kind="RETURN_VALUE", phase="AFTER_STEP", subject_ref="s", operation_ref="op", correlation_group_ref="g", status="PRESENT", value_type="outcome", value="success")

    def test_v01_0004_and_0005_shapes_and_safety_boundaries(self) -> None:
        def event(role: str, *, phase: str, status: str, value=None) -> str:
            return event_line(make_oracle_event(witness_ref="w", contract_observable_ref=f"o:{role}:{phase}", observation_binding_ref=f"b:{role}:{phase}", merge_capture_ref=f"m:{role}:{phase}", semantic_role=role, acquisition_kind="STATE_PROBE", phase=phase, subject_ref="s", operation_ref="op", correlation_group_ref="g", status=status, value_type="integer" if role == "output_length" else "state", value=value, channel_active=True, phase_reached=True))
        logs = "\n".join([event("output_length", phase="BEFORE_STEP", status="PRESENT", value=0), event("output_length", phase="AFTER_STEP", status="PRESENT", value=0), event("object_state", phase="AFTER_STEP", status="PRESENT", value="ready"), event("fatal_event", phase="PROCESS_END", status="OBSERVED_ABSENCE")]).encode()
        allowed = ["m:output_length:BEFORE_STEP", "m:output_length:AFTER_STEP", "m:object_state:AFTER_STEP", "m:fatal_event:PROCESS_END"]
        _, acquisitions = oracle_event_acquisitions("raw:shapes", logs, allowed_capture_refs=allowed)
        self.assertEqual(4, len(acquisitions))
        self.assertEqual("NONE", acquisitions[-1]["value_presence"])
        with self.assertRaises(ValueError):
            oracle_event_acquisitions("raw:absence", event_line(make_oracle_event(witness_ref="w", contract_observable_ref="o", observation_binding_ref="b", merge_capture_ref="m", semantic_role="fatal_event", acquisition_kind="PROCESS_EVENT", phase="PROCESS_END", subject_ref="s", operation_ref="op", correlation_group_ref="g", status="OBSERVED_ABSENCE", value_type="event", channel_active=False, phase_reached=True)).encode(), allowed_capture_refs=["m"])
        _, sanitizer = sanitizer_evidence("raw:sanitizer", b"AddressSanitizer replay-only")
        self.assertEqual("sanitizer_event", sanitizer[0]["evidence_type"])

    def test_c0_lineage_and_claim_gate_are_fixture_only(self) -> None:
        data = self._replay_chain()
        artifacts = {
            "candidate_binding": _edge(data["binding"]["binding_id"], candidate_binding_digest(data["binding"])),
            "candidate_binding_validation": _edge(inputs("mbedtls_poc_0020")[3]["validation_id"], validation_digest(inputs("mbedtls_poc_0020")[3])),
            "merge": _edge(data["merge"]["merge_id"], merge_digest(data["merge"])),
            "bound_source": _edge(data["bound_source"]["bound_source_id"], bound_source_digest(data["bound_source"])),
            "source_map": _edge(data["source_map"]["source_map_id"], source_map_digest(data["source_map"])),
            "execution_handoff": _edge(data["handoff"]["handoff_id"], artifact_digest(data["handoff"])),
            "build_spec": _edge(data["build_spec"]["build_spec_id"], artifact_digest(data["build_spec"])),
            "run_spec": _edge(data["run_spec"]["run_spec_id"], artifact_digest(data["run_spec"])),
            "run_record": _edge(data["run_record"]["run_record_id"], artifact_digest(data["run_record"])),
            "execution_witness": _edge(data["witness"]["witness_id"], artifact_digest(data["witness"])),
            "structured_execution_trace": _edge(data["trace"]["trace_id"], artifact_digest(data["trace"])),
            "contract_projection": _edge(data["projection"]["projection_id"], artifact_digest(data["projection"])),
            "relation_evaluation": _edge(data["evaluations"][0]["evaluation_id"], artifact_digest(data["evaluations"][0])),
        }
        lineage = make_c0_replay_lineage(unit_id="unit:track-a:0020:fixed", source_identity=_profile()["source_root"], build_profile=_edge("c0_replay/build_profiles/0020.fixed.fixture.json", hashlib.sha256(canonical_json_bytes(_profile())).hexdigest()), artifacts=artifacts, relation_result=data["evaluations"][0]["result"])
        population = json.loads((ROOT / "artifacts/pipeline_v2/real_campaign_preflight/population_manifests/CLV2-RQ4-PILOT-001.json").read_text())
        claim = evaluate_c0_bridge(population_manifest=population, profile_mapping=data["mapping"], replay_lineage=lineage)
        artifact_root = ROOT / "artifacts" / "pipeline_v2" / "c0_replay"
        profile_path = artifact_root / "build_profiles" / "0020.fixed.fixture.json"
        stored_profile = json.loads(profile_path.read_text())
        self.assertEqual(_profile(), stored_profile)
        self.assertEqual(hashlib.sha256(profile_path.read_bytes()).hexdigest(), data["mapping"]["profile_digest"])
        for edge in (stored_profile["source_root"], stored_profile["compiler_version_evidence"], stored_profile["build_system_config"], stored_profile["include_path_evidence"][0], stored_profile["library_inputs"][0]):
            self.assertEqual(hashlib.sha256((ROOT / edge["ref"]).read_bytes()).hexdigest(), edge["digest"])
        self.assertEqual(data["mapping"], json.loads((artifact_root / "build_profile_mappings" / "0020.fixed.fixture.json").read_text()))
        self.assertEqual(lineage, json.loads((artifact_root / "replay_lineages" / "0020.fixed.json").read_text()))
        self.assertEqual(claim, json.loads((artifact_root / "claim_gate" / "readiness.json").read_text()))
        self.assertEqual("C0_BRIDGE_COMPLETED", claim["status"])
        self.assertFalse(claim["real_execution_completed"])
        self.assertFalse(claim["report_real_number_allowed"])
        self.assertIn("SECURITY_FINDING_CLAIM", claim["forbidden_claim_levels"])


if __name__ == "__main__":
    unittest.main()

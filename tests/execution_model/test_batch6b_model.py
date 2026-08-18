from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest

import yaml

from execution_model.canonical import artifact_digest, canonical_json_bytes, identify
from execution_model.model import ExecutionAttemptOutcome, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact, validate_artifact_or_raise
from execution_pipeline.build_adapter import execute_build
from execution_pipeline.runner_adapter import attempt_outcome
from execution_trace.verdict import aggregate_execution_verdict
from execution_trace.witness import form_execution_witness
from tests.execution_support import build_spec, built_record, chain, phase, run_record, run_spec, upstream


class Completed:
    def __init__(self, code: int = 0) -> None:
        self.returncode = code; self.stdout = ""; self.stderr = ""


class ModelAndPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = chain()

    def test_01_build_spec_canonical_stability(self) -> None:
        self.assertEqual(canonical_json_bytes(self.data["build_spec"]), canonical_json_bytes(deepcopy(self.data["build_spec"])))

    def test_02_build_record_canonical_stability(self) -> None:
        self.assertEqual(artifact_digest(self.data["build_record"]), artifact_digest(deepcopy(self.data["build_record"])))

    def test_03_run_spec_canonical_stability(self) -> None:
        self.assertEqual(artifact_digest(self.data["run_spec"]), artifact_digest(deepcopy(self.data["run_spec"])))

    def test_04_run_record_canonical_stability(self) -> None:
        self.assertEqual(artifact_digest(self.data["run_record"]), artifact_digest(deepcopy(self.data["run_record"])))

    def test_05_ref_digest_integrity(self) -> None:
        changed = deepcopy(self.data["run_spec"]); changed["build_record_digest"] = "0" * 64
        changed = identify(changed)
        self.assertNotEqual(changed["build_record_digest"], artifact_digest(self.data["build_record"]))

    def test_06_compile_link_separation(self) -> None:
        calls: list[list[str]] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "x.c"; source.write_text("int main(void){return 0;}\n")
            spec = deepcopy(self.data["build_spec"])
            spec["compile_units"] = [{"artifact_ref": "source:x.c", "artifact_digest": hashlib.sha256(source.read_bytes()).hexdigest(), "language": "c"}]
            spec = identify(spec)
            def runner(command, **_):
                calls.append(command); Path(command[-1]).write_bytes(b"object" if "-c" in command else b"binary"); return Completed()
            record, _ = execute_build(spec, source_paths=[source], object_paths=[root / "x.o"], binary_path=root / "x", compiler_path="cc", runner=runner)
        self.assertEqual("BUILT", record["result"]); self.assertIn("-c", calls[0]); self.assertNotIn("-c", calls[1])

    def test_07_build_intent_seed_compatibility(self) -> None:
        handoff = self.data["handoff"]; spec = self.data["build_spec"]
        self.assertEqual(handoff["build_intent_seed"]["seed_ref"], spec["build_intent_seed_ref"])
        self.assertNotEqual(handoff["build_intent_seed"]["hints"], spec)

    def test_08_no_witness_no_verdict(self) -> None:
        self.assertIsNone(aggregate_execution_verdict(self.data["contract"], self.data["binding"], self.data["merge"], None, None, []))

    def test_09_compile_failure_no_verdict(self) -> None:
        failed = built_record(self.data["build_spec"], result="COMPILE_FAILED")
        self.assertEqual("COMPILE_FAILED", attempt_outcome(failed, None))

    def test_10_link_failure_no_verdict(self) -> None:
        failed = built_record(self.data["build_spec"], result="LINK_FAILED")
        self.assertEqual("LINK_FAILED", attempt_outcome(failed, None))

    def test_11_run_launch_failure_no_verdict(self) -> None:
        launch = run_record(self.data["run_spec"], collection="FAILED", started=False)
        self.assertEqual("RUN_LAUNCH_FAILED", attempt_outcome(self.data["build_record"], launch))

    def test_12_all_twelve_schemas_present_and_closed(self) -> None:
        root = Path(__file__).resolve().parents[2] / "execution_model" / "schemas"
        schemas = list(root.glob("*.schema.yaml")); self.assertEqual(12, len(schemas))
        for path in schemas:
            self.assertFalse(yaml.safe_load(path.read_text())["additionalProperties"])

    def test_13_recursive_unknown_field_rejected(self) -> None:
        changed = deepcopy(self.data["build_spec"]); changed["toolchain"]["host_path"] = "/usr/bin/cc"; changed = identify(changed)
        self.assertTrue(any("toolchain.host_path" in item for item in validate_artifact(changed)))

    def test_14_operational_telemetry_rejected(self) -> None:
        changed = deepcopy(self.data["run_record"]); changed["pid"] = 1; changed = identify(changed)
        self.assertTrue(any("pid" in item for item in validate_artifact(changed)))

    def test_15_floating_point_semantics_rejected(self) -> None:
        changed = deepcopy(self.data["run_spec"]); changed["timeout_policy"]["limit_seconds"] = 1.5
        with self.assertRaises(ValueError): identify(changed)

    def test_16_attempt_outcome_enum_is_closed(self) -> None:
        self.assertEqual(10, len(ExecutionAttemptOutcome)); self.assertNotIn("UNKNOWN", {x.value for x in ExecutionAttemptOutcome})

    def test_17_invalid_build_record_cannot_claim_binary(self) -> None:
        changed = deepcopy(self.data["build_record"]); changed["result"] = "LINK_FAILED"; changed = identify(changed)
        self.assertTrue(any("forbidden unless BUILT" in item for item in validate_artifact(changed)))

    def test_witness_canonical_stability(self) -> None:
        self.assertEqual(artifact_digest(self.data["witness"]), artifact_digest(deepcopy(self.data["witness"])))

    def test_valid_and_partial_witness_statuses(self) -> None:
        self.assertEqual("VALID_WITNESS", self.data["witness"]["status"])
        self.assertEqual("PARTIAL_WITNESS", chain(partial=True)["witness"]["status"])

    def test_invalid_witness_has_no_verdict(self) -> None:
        witness = deepcopy(self.data["witness"]); witness["status"] = "INVALID_WITNESS"; witness = identify(witness)
        self.assertIsNone(aggregate_execution_verdict(self.data["contract"], self.data["binding"], self.data["merge"], witness, self.data["trace"], self.data["evaluations"]))

    def test_partial_witness_cannot_satisfy(self) -> None:
        self.assertEqual("UNKNOWN", chain(partial=True)["verdict"]["verdict"])

    def test_partial_admissible_broken_violates(self) -> None:
        data = chain(values={"CONSUMED_LENGTH": 7}, partial=True)
        self.assertTrue(data["evaluations"][0]["admissibility"]["broken_admissible"])
        self.assertEqual("VIOLATED", data["verdict"]["verdict"])

    def test_partial_without_broken_is_unknown(self) -> None:
        data = chain(partial=True); self.assertEqual(("HOLDS", "UNKNOWN"), (data["evaluations"][0]["result"], data["verdict"]["verdict"]))


if __name__ == "__main__":
    unittest.main()

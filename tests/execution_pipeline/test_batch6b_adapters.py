from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from execution_model.canonical import identify
from execution_model.registry import validate_artifact
from execution_pipeline.handoff import HandoffRejected, create_execution_handoff
from execution_pipeline.collect_adapter import oracle_event_acquisitions, sanitizer_evidence
from execution_pipeline.runner_adapter import build_run_spec, execute_run
from tests.execution_support import built_record, chain


class AdapterBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.data = chain()

    def test_handoff_rejects_changed_source_bytes(self) -> None:
        d = self.data
        with self.assertRaises(HandoffRejected):
            create_execution_handoff(d["contract"], d["binding"], d["merge"], d["validation"], d["bound_source"], d["source_map"], d["source_bytes"] + b"x")

    def test_build_spec_forbids_absolute_compiler_identity(self) -> None:
        changed = deepcopy(self.data["build_spec"]); changed["toolchain"]["compiler"] = "/usr/bin/cc"; changed = identify(changed)
        self.assertTrue(any("absolute path forbidden" in item for item in validate_artifact(changed)))

    def test_run_spec_rejects_failed_build(self) -> None:
        failed = built_record(self.data["build_spec"], result="LINK_FAILED")
        with self.assertRaises(ValueError):
            build_run_spec(self.data["build_spec"], failed, environment_profile={"profile_ref": "e", "profile_digest": "1" * 64}, working_directory_profile={"profile_ref": "w", "logical_directory": "run"}, timeout_policy={"policy_ref": "t", "limit_seconds": 1}, instrumentation_profile={"profile_ref": "i", "profile_digest": "2" * 64}, required_capture_refs=[], expected_phases=[])

    def test_run_adapter_checks_binary_integrity_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"; path.write_bytes(b"wrong")
            with self.assertRaises(ValueError):
                execute_run(self.data["run_spec"], binary_path=path, controlled_env={}, working_directory=Path(directory), timeout_seconds=1)

    def test_observed_absence_requires_reached_active_channel(self) -> None:
        from execution_trace.normalize import build_structured_trace
        capture = self.data["merge"]["observation_capture_bindings"][0]
        acquisition = {"capture_binding_ref": capture["capture_binding_id"], "status": "OBSERVED_ABSENCE", "value_presence": "NONE", "value": None, "channel_active": False, "phase_reached": True}
        with self.assertRaises(ValueError):
            build_structured_trace(self.data["witness"], self.data["run_record"], self.data["merge"], self.data["binding"], self.data["contract"], self.data["source_map"], [acquisition])

    def test_sanitizer_parser_produces_process_evidence_only(self) -> None:
        _, events = sanitizer_evidence("raw:sanitizer", b"ERROR: AddressSanitizer: heap-buffer-overflow")
        self.assertEqual("sanitizer_event", events[0]["evidence_type"]); self.assertNotIn("verdict", events[0])

    def test_oracle_event_parser_requires_declared_capture(self) -> None:
        capture = self.data["handoff"]["observation_capture_refs"][0]
        raw = ('ORACLE_EVENT {"capture_binding_ref":"%s","status":"PRESENT","value_presence":"VALUE","value":"success","sequence_index":0,"channel_active":true,"phase_reached":true}\n' % capture).encode()
        _, acquisitions = oracle_event_acquisitions("raw:stdout", raw, allowed_capture_refs=[capture])
        self.assertEqual(capture, acquisitions[0]["capture_binding_ref"])


if __name__ == "__main__":
    unittest.main()

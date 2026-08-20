import ast
import json
import unittest
from pathlib import Path

from execution_pipeline.capture_protocol import PREFIX, parse_target_capture_line, target_capture_to_runtime_event


ROOT = Path(__file__).resolve().parents[2]


def _payload():
    return {
        "protocol_version": "0.1",
        "capture_binding_ref": "capture:0020:input-length",
        "contract_observable_ref": "contract-observable:input-length",
        "observation_binding_ref": "observation:0020:input-length",
        "semantic_role": "input_length",
        "acquisition_kind": "BOUND_VALUE",
        "phase": "POST_OPERATION",
        "subject_ref": "subject:target",
        "operation_ref": "operation:parse",
        "correlation_group_ref": "correlation:0020",
        "status": "PRESENT",
        "value_type": "integer",
        "value": 17,
        "sequence_index": 2,
    }


class CaptureProtocolTests(unittest.TestCase):
    def test_exact_target_payload_parses_and_delegates_to_frozen_emitter(self):
        payload = _payload()
        parsed = parse_target_capture_line(PREFIX + json.dumps(payload, sort_keys=True, separators=(",", ":")))
        self.assertEqual(payload, parsed)
        event = target_capture_to_runtime_event(parsed, execution_attempt_ref="attempt:dry", evidence_ref="evidence:raw")
        self.assertEqual("input_length", event["semantic_role"])
        self.assertEqual("PRESENT", event["status"])
        self.assertEqual(["evidence:raw"], event["evidence_refs"])

    def test_closed_schema_rejects_wrong_prefix_or_unknown_field(self):
        with self.assertRaises(ValueError):
            parse_target_capture_line("stdout: {}")
        payload = _payload()
        payload["unexpected"] = True
        with self.assertRaises(ValueError):
            parse_target_capture_line(PREFIX + json.dumps(payload))

    def test_capture_bridge_has_no_regex_dependency(self):
        source = (ROOT / "execution_pipeline/capture_protocol.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules.update(alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names)
        self.assertNotIn("re", modules)


if __name__ == "__main__":
    unittest.main()

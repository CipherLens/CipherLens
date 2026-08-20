import unittest
from runtime_event.emitter import emit_runtime_event_v0_1
from runtime_event.attachment import attach_runtime_event
def fields(): return dict(execution_attempt_ref="attempt:0020",contract_observable_ref="PARSE_OUTCOME",observation_binding_ref="OBSERVATION_0_PARSE_OUTCOME",merge_capture_ref="observation-capture:x",semantic_role="operation_outcome",acquisition_kind="RETURN_VALUE",phase="AFTER_STEP",subject_ref="SUBJECT_CHANNEL_0",operation_ref="OPERATION_0_PARSE_KEY",correlation_group_ref="CORRELATION_PRIMARY",status="PRESENT",value_type="outcome",value="success",evidence_refs=[],producer={"emitter_name":"c1","emitter_version":"v0.1"})
class T(unittest.TestCase):
 def test_identity_and_attachment(self):
  a=emit_runtime_event_v0_1(**fields()); b=emit_runtime_event_v0_1(**fields()); self.assertEqual(a,b)
  edge=attach_runtime_event(a,"witness:real",1); self.assertEqual(a["runtime_event_id"],edge["runtime_event_ref"])
 def test_forbidden(self):
  x=fields();x["verdict"]="x"
  with self.assertRaises(ValueError):emit_runtime_event_v0_1(**x)

import unittest
from runtime_event.adapters import legacy_oracle_to_runtime_event, runtime_event_observation
class T(unittest.TestCase):
 def test_legacy_has_no_future_witness(self):
  e={"witness_ref":"pending:x","contract_observable_ref":"O","observation_binding_ref":"B","merge_capture_ref":"C","semantic_role":"input_length","acquisition_kind":"BOUND_VALUE","phase":"AFTER_STEP","subject_ref":"S","operation_ref":"P","correlation_group_ref":"G","status":"PRESENT","value_type":"integer","value":3,"evidence_refs":[],"producer":{"emitter_name":"x","emitter_version":"1"}}
  r=legacy_oracle_to_runtime_event(e,"attempt:x");self.assertNotIn("execution_witness_ref",r);self.assertEqual(3,runtime_event_observation(r)["value"])

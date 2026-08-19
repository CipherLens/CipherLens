import unittest
from pathlib import Path

from real_campaign_bridge.c1_retry import evaluate_c1_retry_gate


ROOT = Path(__file__).resolve().parents[2]


class C1RetryGateTest(unittest.TestCase):
    def test_current_canonical_bound_source_fails_closed_before_execution(self):
        gate = evaluate_c1_retry_gate(ROOT)
        self.assertEqual("C1_SINGLE_UNIT_DRY_RUN_BLOCKED", gate["status"])
        self.assertEqual(
            ["BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED", "ORACLE_EVENT_CAPTURE_NOT_EMBEDDED"],
            gate["blocking_reasons"],
        )
        self.assertFalse(gate["build_run_authorized"])
        self.assertFalse(gate["build_run_attempted"])


if __name__ == "__main__":
    unittest.main()

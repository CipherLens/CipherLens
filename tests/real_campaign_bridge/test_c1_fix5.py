import unittest
from pathlib import Path

from real_campaign_bridge.c1_fix5 import c1_fix5_audit


ROOT = Path(__file__).resolve().parents[2]


class C1Fix5AuditTest(unittest.TestCase):
    def test_protected_template_values_and_capture_without_hole_stay_blocked(self):
        audit = c1_fix5_audit(ROOT)
        self.assertEqual("C1_PRE_RUN_GATE_STILL_BLOCKED", audit["status"])
        self.assertEqual(
            ["BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED", "CAPTURE_INSERTION_POINT_MISSING"],
            audit["blocking_reasons"],
        )
        self.assertEqual(["hole:build-metadata"], audit["writable_holes"])
        self.assertEqual([], audit["capture_holes"])
        self.assertEqual(5, len(audit["unresolved_template_values"]))
        self.assertTrue(all(item["proposal_or_adaptation_forbidden"] for item in audit["unresolved_template_values"]))


if __name__ == "__main__":
    unittest.main()

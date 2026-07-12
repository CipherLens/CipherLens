from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from caller_audit.dynamic_parser import (
    evaluate_phase,
    parse_structured_output,
)
from caller_audit.scanner import (
    evaluate_static_checks,
    scan_call_sites,
)
from caller_audit.verdict import classify


BASELINE_LOG = """
case=canonical input_len=100 accepted=1 input_differs=0 canonical_roundtrip=1 public_key_equal=1 signature_verifies=1
case=tail_0500 input_len=102 accepted=1 input_differs=1 canonical_roundtrip=1 public_key_equal=1 signature_verifies=1
case=tail_3000 input_len=102 accepted=1 input_differs=1 canonical_roundtrip=1 public_key_equal=1 signature_verifies=1
case=tail_020100 input_len=103 accepted=1 input_differs=1 canonical_roundtrip=1 public_key_equal=1 signature_verifies=1
summary=mlspp_rsa_private baseline_ok=1 mutations_accepted=3 mutations_rejected=0
"""

FIX_LOG = """
case=canonical input_len=100 accepted=1 input_differs=0 canonical_roundtrip=1 public_key_equal=1 signature_verifies=1
case=tail_0500 input_len=102 accepted=0 input_differs=1 canonical_roundtrip=0 public_key_equal=0 signature_verifies=0
case=tail_3000 input_len=102 accepted=0 input_differs=1 canonical_roundtrip=0 public_key_equal=0 signature_verifies=0
case=tail_020100 input_len=103 accepted=0 input_differs=1 canonical_roundtrip=0 public_key_equal=0 signature_verifies=0
summary=mlspp_rsa_private baseline_ok=1 mutations_accepted=0 mutations_rejected=3
"""


class CallerAuditV01Test(unittest.TestCase):
    def test_per_case_parser(self):
        parsed = parse_structured_output(BASELINE_LOG)
        self.assertTrue(parsed["cases"]["canonical"]["accepted"])
        self.assertEqual(
            parsed["summaries"]["mlspp_rsa_private"]["mutations_accepted"],
            3,
        )

    def test_baseline_and_fix_control(self):
        baseline_spec = {
            "baseline_case": "canonical",
            "baseline_required": {
                "accepted": True,
                "canonical_roundtrip": True,
                "public_key_equal": True,
                "signature_verifies": True,
            },
            "mutation_cases": [
                "tail_0500", "tail_3000", "tail_020100"
            ],
            "expected_mutation_count": 3,
            "mutation_required": {
                "accepted": True,
                "input_differs": True,
                "canonical_roundtrip": True,
                "public_key_equal": True,
                "signature_verifies": True,
            },
        }
        fix_spec = {
            **baseline_spec,
            "mutation_required": {
                "accepted": False,
                "input_differs": True,
                "canonical_roundtrip": False,
                "public_key_equal": False,
                "signature_verifies": False,
            },
        }
        baseline = evaluate_phase(
            parse_structured_output(BASELINE_LOG), baseline_spec
        )
        fix = evaluate_phase(
            parse_structured_output(FIX_LOG), fix_spec
        )
        self.assertTrue(baseline["baseline_passed"])
        self.assertTrue(baseline["mutations_passed"])
        self.assertTrue(fix["baseline_passed"])
        self.assertTrue(fix["mutations_passed"])

    def test_scan_missing_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            source = repo / "src" / "rsa.cpp"
            source.parent.mkdir(parents=True)
            source.write_text(
                """
const auto* data_ptr = skm.data();
auto* pkey = d2i_PrivateKey(
    EVP_PKEY_RSA, nullptr, &data_ptr, skm.size());
if (pkey == nullptr) { throw openssl_error(); }
""",
                encoding="utf-8",
            )
            sites = scan_call_sites(
                repo,
                [r"\bd2i_PrivateKey\s*\("],
                include_globs=["**/*.cpp"],
                test_markers=["/test/"],
            )
            checks = evaluate_static_checks(
                sites,
                [
                    r"data_ptr\s*==\s*skm\.data\(\)\s*\+\s*skm\.size\(\)"
                ],
            )
            self.assertEqual(
                checks["production_without_full_consumption_check"], 1
            )

    def test_downgrade_requires_fix_control(self):
        verdict = classify(
            {"production_without_full_consumption_check": 1},
            {
                "baseline_passed": True,
                "mutation_candidate_confirmed": True,
                "fix_control_passed": True,
                "asan_error": False,
                "ubsan_error": False,
            },
            {
                "production_reachable": False,
                "attacker_controlled_input": False,
                "official_protocol_route_found": False,
                "security_impact_demonstrated": False,
            },
        )
        self.assertEqual(verdict["status"], "downgraded_unreachable")
        self.assertTrue(verdict["fix_control_passed"])


if __name__ == "__main__":
    unittest.main()

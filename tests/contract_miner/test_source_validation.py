from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

import yaml

from contract_miner.source_validation import canonical_source_validation_bytes, validate_source_contract
from contract_miner.trace import dump_trace, load_trace


ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).parent / "fixtures" / "golden"


def load_case(name):
    directory = GOLDEN / name
    return {
        "directory": directory,
        "contract": yaml.safe_load((directory / "expected.vc.yaml").read_text()),
        "divergence": yaml.safe_load((directory / "divergence.yaml").read_text()),
        "manifest": yaml.safe_load((directory / "evidence.yaml").read_text()),
        "buggy": directory / "buggy.trace.jsonl",
        "fixed": directory / "fixed.trace.jsonl",
    }


def run(case, **changes):
    values = {**case, **changes}
    return validate_source_contract(
        values["contract"], values["buggy"], values["fixed"],
        values["divergence"], values["manifest"], repo_root=ROOT,
    )


class SourceValidationTests(unittest.TestCase):
    def test_three_golden_pairs_pass_and_match_expected_artifacts(self):
        for directory in sorted(GOLDEN.iterdir()):
            case = load_case(directory.name)
            result = run(case)
            with self.subTest(directory=directory):
                self.assertEqual("PASS", result["status"])
                self.assertEqual((directory / "expected.validation.yaml").read_bytes(), canonical_source_validation_bytes(result))
                text = yaml.safe_dump(result)
                self.assertNotIn("SATISFIED", text)
                self.assertNotIn("VIOLATED", text)
                self.assertNotIn("UNKNOWN", text)

    def test_missing_required_observable_is_inconclusive(self):
        case = load_case("mbedtls_poc_0005")
        contract = deepcopy(case["contract"])
        contract["observable_evidence"]["observables"][0]["extraction"]["field"] = "missing_field"
        result = run(case, contract=contract)
        self.assertEqual("INCONCLUSIVE", result["status"])
        self.assertIn("REQUIRED_OBSERVABLE_MISSING", result["reason_codes"])

    def test_wrong_observable_type_is_inconclusive(self):
        case = load_case("mbedtls_poc_0004")
        contract = deepcopy(case["contract"])
        contract["observable_evidence"]["observables"][1]["value_type"] = "boolean"
        result = run(case, contract=contract)
        self.assertEqual("INCONCLUSIVE", result["status"])
        self.assertIn("WRONG_OBSERVABLE_TYPE", result["reason_codes"])

    def test_fixed_side_still_broken_is_fail(self):
        case = load_case("mbedtls_poc_0004")
        buggy_header, buggy_events = load_trace(case["buggy"])
        fixed_header, _ = load_trace(case["fixed"])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixed.trace.jsonl"
            dump_trace(fixed_header, buggy_events, path)
            result = run(case, fixed=path)
        self.assertEqual("FAIL", result["status"])
        self.assertIn("FIXED_ALSO_BREAKS_RELATION", result["reason_codes"])

    def test_buggy_violation_absent_is_fail(self):
        case = load_case("mbedtls_poc_0004")
        buggy_header, _ = load_trace(case["buggy"])
        _, fixed_events = load_trace(case["fixed"])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "buggy.trace.jsonl"
            dump_trace(buggy_header, fixed_events, path)
            result = run(case, buggy=path)
        self.assertEqual("FAIL", result["status"])
        self.assertIn("BUGGY_VIOLATION_NOT_OBSERVED", result["reason_codes"])

    def test_intervention_mismatch_is_invalid(self):
        case = load_case("mbedtls_poc_0020")
        divergence = deepcopy(case["divergence"])
        divergence["intervention_refs"] = ["OTHER_ACTION"]
        result = run(case, divergence=divergence)
        self.assertEqual("INVALID_INPUT", result["status"])
        self.assertIn("INTERVENTION_MISMATCH", result["reason_codes"])

    def test_revision_mismatch_is_invalid(self):
        case = load_case("mbedtls_poc_0020")
        header, events = load_trace(case["fixed"])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixed.trace.jsonl"
            dump_trace(replace(header, library_version="wrong-revision"), events, path)
            result = run(case, fixed=path)
        self.assertEqual("INVALID_INPUT", result["status"])
        self.assertIn("SOURCE_REVISION_MISMATCH", result["reason_codes"])

    def test_digest_mismatch_is_invalid(self):
        case = load_case("mbedtls_poc_0020")
        contract = deepcopy(case["contract"])
        contract["provenance"]["evidence"][0]["sha256"] = "0" * 64
        result = run(case, contract=contract)
        self.assertEqual("INVALID_INPUT", result["status"])
        self.assertIn("EVIDENCE_DIGEST_MISMATCH", result["reason_codes"])

    def test_swapped_buggy_fixed_is_invalid(self):
        case = load_case("mbedtls_poc_0020")
        result = run(case, buggy=case["fixed"], fixed=case["buggy"])
        self.assertEqual("INVALID_INPUT", result["status"])


if __name__ == "__main__":
    unittest.main()

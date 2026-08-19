"""M0 acceptance tests for the Vulnerability Contract v0.2 schema."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from contract_miner.schema import (
    VCValidationError,
    load_vc,
    validate_vc,
    validate_vc_or_raise,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class VulnerabilityContractSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.minimal = load_vc(FIXTURES / "valid_minimal" / "vc.yaml")
        cls.full = load_vc(FIXTURES / "valid_full" / "vc.yaml")

    def errors(self, data: object) -> list[str]:
        return validate_vc(data, repo_root=REPO_ROOT)

    def assert_error_contains(self, data: object, text: str) -> None:
        errors = self.errors(data)
        self.assertTrue(errors, "expected validation to fail")
        self.assertTrue(
            any(text in error for error in errors),
            f"expected {text!r} in validation errors: {errors}",
        )

    def test_valid_minimal_contract(self) -> None:
        self.assertEqual([], self.errors(deepcopy(self.minimal)))

    def test_valid_full_contract(self) -> None:
        self.assertEqual([], self.errors(deepcopy(self.full)))

    def test_v1_missing_required_field(self) -> None:
        data = deepcopy(self.minimal)
        del data["effect"]
        self.assert_error_contains(data, "effect: required field missing")

    def test_v1_unknown_nested_field(self) -> None:
        data = deepcopy(self.minimal)
        data["effect"]["surprise"] = True
        self.assert_error_contains(data, "effect.surprise: unknown field")

    def test_v2_closed_vocabularies(self) -> None:
        cases = (
            ("role", lambda d: d["roles"].__setitem__(0, "DECODE"), "roles[0]"),
            (
                "state kind",
                lambda d: d["states"][0].__setitem__("kind", "start"),
                "states[0].kind",
            ),
            (
                "expected",
                lambda d: d["transitions"][0].__setitem__("expected", "optional"),
                "transitions[0].expected",
            ),
            (
                "sink",
                lambda d: d["effect"]["sinks"].append("filesystem_write"),
                "effect.sinks[0]",
            ),
            (
                "mutation strategy",
                lambda d: d["mutation"].__setitem__("strategy", "byte_flip"),
                "mutation.strategy",
            ),
        )
        for label, mutate, expected_path in cases:
            with self.subTest(label=label):
                data = deepcopy(self.minimal)
                mutate(data)
                self.assert_error_contains(data, expected_path)

    def test_v2_oracle_signal_strings_remain_open(self) -> None:
        data = deepcopy(self.minimal)
        data["oracle"]["memory_safety"] = ["new_repo_backed_memory_signal"]
        data["oracle"]["bug_candidate"] = ["new_repo_backed_bug_signal"]
        data["oracle"]["fixed_or_safe"] = ["new_repo_backed_safe_signal"]
        self.assertEqual([], self.errors(data))

    def test_v3_referential_integrity_and_witness(self) -> None:
        cases = (
            (
                "from",
                lambda d: d["transitions"][0].__setitem__("from", "UNKNOWN"),
                "transitions[0].from: undeclared state",
            ),
            (
                "to",
                lambda d: d["transitions"][0].__setitem__("to", "UNKNOWN"),
                "transitions[0].to: undeclared state",
            ),
            (
                "role",
                lambda d: d["transitions"][0].__setitem__("on", "VERIFY"),
                "transitions[0].on: undeclared role",
            ),
            (
                "guard",
                lambda d: d["transitions"][1].__setitem__("guard_ref", "missing"),
                "transitions[1].guard_ref: undeclared guard",
            ),
            (
                "fidelity",
                lambda d: d["fidelity"]["target_states"].append("UNKNOWN"),
                "fidelity.target_states[3]: undeclared state",
            ),
            (
                "missing witness",
                lambda d: d["mutation"].__setitem__(
                    "witness_ref", "tests/contract_miner/fixtures/missing.seq"
                ),
                "existing regular file required",
            ),
            (
                "absolute witness",
                lambda d: d["mutation"].__setitem__(
                    "witness_ref", "/tmp/contract-miner-witness.min.seq"
                ),
                "must be a repo-relative path",
            ),
            (
                "escaping witness",
                lambda d: d["mutation"].__setitem__(
                    "witness_ref", "../outside-repository.seq"
                ),
                "path escapes repository root",
            ),
        )
        for label, mutate, expected_error in cases:
            with self.subTest(label=label):
                data = deepcopy(self.full)
                mutate(data)
                self.assert_error_contains(data, expected_error)

    def test_v4_transition_conditionals(self) -> None:
        cases = (
            (
                "forbidden with to",
                lambda d: d["transitions"][0].update(expected="forbidden"),
                "to: forbidden when expected='forbidden'",
            ),
            (
                "required without to",
                lambda d: d["transitions"][0].pop("to"),
                "to: required when expected='required'",
            ),
            (
                "guarded without to",
                lambda d: d["transitions"][1].pop("to"),
                "to: required when expected='allowed_with_guard'",
            ),
            (
                "guarded without guard",
                lambda d: d["transitions"][1].pop("guard_ref"),
                "guard_ref: required when expected='allowed_with_guard'",
            ),
            (
                "required with stray guard",
                lambda d: d["transitions"][0].__setitem__(
                    "guard_ref", "zero_length_value"
                ),
                "guard_ref: forbidden unless expected='allowed_with_guard'",
            ),
        )
        for label, mutate, expected_error in cases:
            with self.subTest(label=label):
                data = deepcopy(self.full)
                mutate(data)
                self.assert_error_contains(data, expected_error)
        self.assertEqual([], self.errors(deepcopy(self.full)))

    def test_v5_required_only_contract_passes(self) -> None:
        self.assertEqual([], self.errors(deepcopy(self.minimal)))
        self.assertFalse(
            any(
                transition["expected"] == "forbidden"
                for transition in self.minimal["transitions"]
            )
        )

    def test_v5_guard_only_contract_fails(self) -> None:
        data = deepcopy(self.minimal)
        data["guards"] = [
            {"id": "parse_guard", "description": "The parser guard holds."}
        ]
        data["transitions"][0]["expected"] = "allowed_with_guard"
        data["transitions"][0]["guard_ref"] = "parse_guard"
        self.assert_error_contains(data, "requires at least one")

    def test_v6_independent_assertion_and_review_gate(self) -> None:
        data = deepcopy(self.minimal)
        data["oracle"]["contract_violation"]["independent_of_generator"] = False
        self.assert_error_contains(data, "expected literal True")

        unreviewed = deepcopy(self.minimal)
        unreviewed["provenance"]["human_reviewed"] = False
        self.assertEqual([], self.errors(unreviewed))

    def test_v7_naming_and_uniqueness(self) -> None:
        cases = (
            (
                "contract id",
                lambda d: d.__setitem__("contract_id", "bad-id"),
                "contract_id: does not match",
            ),
            (
                "state name",
                lambda d: d["states"][0].__setitem__("name", "bad_state"),
                "states[0].name: does not match",
            ),
            (
                "roles",
                lambda d: d["roles"].append(d["roles"][0]),
                "roles: duplicate role",
            ),
            (
                "states",
                lambda d: d["states"].append(deepcopy(d["states"][0])),
                "states: duplicate state name",
            ),
            (
                "guards",
                lambda d: d["guards"].append(deepcopy(d["guards"][0])),
                "guards: duplicate guard id",
            ),
        )
        for label, mutate, expected_error in cases:
            with self.subTest(label=label):
                data = deepcopy(self.full)
                mutate(data)
                self.assert_error_contains(data, expected_error)

    def test_additional_field_constraints(self) -> None:
        cases = (
            (
                "schema version",
                lambda d: d.__setitem__("schema_version", "cipherlens.vc.v0_1"),
                "schema_version: expected literal",
            ),
            (
                "lowercase library",
                lambda d: d["source"].__setitem__("library", "MbedTLS"),
                "source.library: must be lowercase",
            ),
            (
                "roles non-empty",
                lambda d: d.__setitem__("roles", []),
                "roles: expected at least 1 item",
            ),
            (
                "states non-empty",
                lambda d: d.__setitem__("states", []),
                "states: expected at least 1 item",
            ),
        )
        for label, mutate, expected_error in cases:
            with self.subTest(label=label):
                data = deepcopy(self.minimal)
                mutate(data)
                self.assert_error_contains(data, expected_error)

    def test_v8_aggregates_multiple_errors(self) -> None:
        invalid = load_vc(FIXTURES / "invalid" / "multiple_errors" / "vc.yaml")
        errors = self.errors(invalid)
        self.assertGreaterEqual(len(errors), 4)
        for expected in (
            "contract_id",
            "effect.surprise",
            "roles[2]",
            "transitions[0].to",
            "fidelity.target_states[0]",
            "mutation.witness_ref",
        ):
            with self.subTest(expected=expected):
                self.assertTrue(any(expected in error for error in errors), errors)

        with self.assertRaises(VCValidationError) as context:
            validate_vc_or_raise(invalid, repo_root=REPO_ROOT)
        self.assertEqual(tuple(errors), context.exception.errors)


if __name__ == "__main__":
    unittest.main()

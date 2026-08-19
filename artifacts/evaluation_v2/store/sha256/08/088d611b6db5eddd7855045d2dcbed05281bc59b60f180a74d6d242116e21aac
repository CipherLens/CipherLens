from __future__ import annotations

import json
from pathlib import Path
import unittest

from binding_proposal.validate import validate_payload


FIXTURES = Path(__file__).with_name("fixtures")


class FixtureTests(unittest.TestCase):
    def test_valid_and_advisory_negative_content(self):
        for name in ("valid_codex_payload.json", "valid_glm_payload.json", "replay_payload.json", "partial_payload.json", "wrong_subject_proposal.json", "unsupported_role_proposal.json"):
            value = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            with self.subTest(name=name): self.assertEqual([], validate_payload(value))

    def test_injection_fixtures_are_rejected(self):
        for name in ("unknown_field.json", "trusted_field_injection.json", "verified_injection.json", "eligibility_verdict_injection.json", "secret_injection.json"):
            value = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            with self.subTest(name=name): self.assertTrue(validate_payload(value))

    def test_malformed_fixture_is_not_json(self):
        with self.assertRaises(json.JSONDecodeError):
            json.loads((FIXTURES / "malformed.json").read_text(encoding="utf-8"))


if __name__ == "__main__": unittest.main()

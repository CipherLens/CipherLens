from copy import deepcopy
from pathlib import Path
import unittest

import yaml

from contract_miner.divergence import canonical_divergence_bytes, validate_divergence


GOLDEN = Path(__file__).parent / "fixtures" / "golden"


class DivergenceTests(unittest.TestCase):
    def values(self):
        for path in sorted(GOLDEN.glob("*/divergence.yaml")):
            yield path, yaml.safe_load(path.read_text())

    def test_golden_divergences_validate_and_are_stable(self):
        for path, value in self.values():
            with self.subTest(path=path):
                self.assertEqual([], validate_divergence(value))
                self.assertEqual(canonical_divergence_bytes(value), canonical_divergence_bytes(yaml.safe_load(canonical_divergence_bytes(value))))

    def test_unknown_nested_and_claim_fields_are_rejected(self):
        _, value = next(self.values())
        invalid = deepcopy(value)
        invalid["deltas"][0]["vulnerability"] = True
        errors = validate_divergence(invalid)
        self.assertTrue(any("vulnerability: unknown field" in item for item in errors), errors)

    def test_target_expectation_is_not_allowed(self):
        _, value = next(self.values())
        invalid = deepcopy(value)
        invalid["target_expectation"] = "reject"
        self.assertTrue(any("target_expectation: unknown field" in item for item in validate_divergence(invalid)))


if __name__ == "__main__":
    unittest.main()

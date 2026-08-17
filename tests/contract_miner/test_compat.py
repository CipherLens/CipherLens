from pathlib import Path
import unittest

import yaml

from contract_miner.compat import upgrade_v02
from contract_miner.schema import validate_vc


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"


class CompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy = yaml.safe_load((FIXTURES / "valid_full" / "vc.yaml").read_text())
        cls.canonical = yaml.safe_load((FIXTURES / "golden" / "mbedtls_poc_0005" / "expected.vc.yaml").read_text())

    def test_v02_remains_read_only_valid(self):
        self.assertEqual([], validate_vc(self.legacy, repo_root=ROOT))

    def test_ambiguous_upgrade_requires_structured_metadata(self):
        result = upgrade_v02(self.legacy, repo_root=ROOT)
        self.assertEqual("NEEDS_STRUCTURED_METADATA", result.status)
        self.assertIsNone(result.contract)

    def test_forbidden_legacy_inference_is_unsupported(self):
        result = upgrade_v02(
            self.legacy,
            {"canonical_contract": self.canonical, "free_text_relation": True},
            repo_root=ROOT,
        )
        self.assertEqual("UNSUPPORTED_LEGACY_SEMANTICS", result.status)

    def test_complete_independent_canonical_contract_can_upgrade(self):
        result = upgrade_v02(
            self.legacy,
            {"canonical_contract": self.canonical},
            repo_root=ROOT,
        )
        self.assertEqual("UPGRADED", result.status)
        self.assertEqual(self.canonical, result.contract)


if __name__ == "__main__":
    unittest.main()

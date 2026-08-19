from pathlib import Path
import unittest

import yaml

from contract_miner.miner import canonical_mined_bytes, mine_contract
from contract_miner.schema import validate_vc


ROOT = Path(__file__).resolve().parents[2]
GOLDEN = Path(__file__).parent / "fixtures" / "golden"


class MinerTests(unittest.TestCase):
    def test_three_golden_contracts_match_and_are_byte_stable(self):
        for directory in sorted(GOLDEN.iterdir()):
            evidence = yaml.safe_load((directory / "evidence.yaml").read_text())
            divergence = yaml.safe_load((directory / "divergence.yaml").read_text())
            expected = (directory / "expected.vc.yaml").read_bytes()
            with self.subTest(directory=directory):
                first = canonical_mined_bytes(evidence, divergence, repo_root=ROOT)
                second = canonical_mined_bytes(evidence, divergence, repo_root=ROOT)
                self.assertEqual(expected, first)
                self.assertEqual(first, second)
                contract = mine_contract(evidence, divergence, repo_root=ROOT)
                self.assertEqual([], validate_vc(contract, repo_root=ROOT))

    def test_contract_does_not_embed_witness_observations(self):
        for directory in sorted(GOLDEN.iterdir()):
            contract = yaml.safe_load((directory / "expected.vc.yaml").read_text())
            text = yaml.safe_dump(contract)
            self.assertNotIn("18446744073709551504", text)
            self.assertNotIn("signal_sigsegv", text)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from contract_miner.schema import canonical_vc_bytes
from contract_miner.source_validation import canonical_source_validation_bytes
from transfer_signature.derive import derive_transfer_signature
from transfer_signature.model import DerivationError, SourceValidationArtifact

from tests.transfer_signature.common import CASES, ROOT, TS_GOLDEN, contract_case, derive_case, load_yaml


class DerivationTests(unittest.TestCase):
    def test_three_contracts_derive_exact_golden_ts(self):
        for case in CASES:
            signature, _, _ = derive_case(case)
            self.assertEqual(load_yaml(TS_GOLDEN / case / "expected.ts.yaml"), signature)

    def test_contract_digest_mismatch_is_rejected(self):
        contract, validation = contract_case(CASES[0])
        validation_digest = hashlib.sha256(canonical_source_validation_bytes(validation)).hexdigest()
        with self.assertRaisesRegex(DerivationError, "Contract digest mismatch"):
            derive_transfer_signature(
                contract,
                source_contract_ref=f"contract:{contract['contract_id']}",
                source_contract_digest="0" * 64,
                source_validations=[SourceValidationArtifact(validation, validation_digest)],
                repo_root=ROOT,
            )

    def test_validation_digest_mismatch_is_rejected(self):
        contract, validation = contract_case(CASES[0])
        contract_digest = hashlib.sha256(canonical_vc_bytes(contract)).hexdigest()
        with self.assertRaisesRegex(DerivationError, "source validation 0 digest mismatch"):
            derive_transfer_signature(
                contract,
                source_contract_ref=f"contract:{contract['contract_id']}",
                source_contract_digest=contract_digest,
                source_validations=[SourceValidationArtifact(validation, "0" * 64)],
                repo_root=ROOT,
            )

    def test_non_pass_validation_is_rejected(self):
        contract, validation = contract_case(CASES[0])
        value = deepcopy(validation)
        value["status"] = "FAIL"
        digest = hashlib.sha256(canonical_source_validation_bytes(value)).hexdigest()
        contract_digest = hashlib.sha256(canonical_vc_bytes(contract)).hexdigest()
        with self.assertRaisesRegex(DerivationError, "at least one PASS"):
            derive_transfer_signature(
                contract,
                source_contract_ref=f"contract:{contract['contract_id']}",
                source_contract_digest=contract_digest,
                source_validations=[SourceValidationArtifact(value, digest)],
                repo_root=ROOT,
            )

    def test_v02_or_unvalidated_contract_cannot_enter_derivation(self):
        contract, validation = contract_case(CASES[0])
        value = deepcopy(contract)
        value["schema_version"] = "cipherlens.vc.v0_2"
        with self.assertRaisesRegex(DerivationError, "VC schema validation failed"):
            derive_transfer_signature(
                value,
                source_contract_ref=f"contract:{contract['contract_id']}",
                source_contract_digest="0" * 64,
                source_validations=[SourceValidationArtifact(validation, "0" * 64)],
                repo_root=ROOT,
            )


if __name__ == "__main__":
    unittest.main()

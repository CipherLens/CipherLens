from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from contract_miner.schema import canonical_vc_bytes
from contract_miner.source_validation import canonical_source_validation_bytes
from transfer_signature.derive import derive_transfer_signature
from transfer_signature.model import SourceValidationArtifact


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_GOLDEN = ROOT / "tests" / "contract_miner" / "fixtures" / "golden"
TS_GOLDEN = ROOT / "tests" / "transfer_signature" / "fixtures" / "golden"
CASES = ("mbedtls_poc_0020", "mbedtls_poc_0004", "mbedtls_poc_0005")


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def contract_case(name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    directory = CONTRACT_GOLDEN / name
    return load_yaml(directory / "expected.vc.yaml"), load_yaml(
        directory / "expected.validation.yaml"
    )


def derive_case(name: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    contract, validation = contract_case(name)
    contract_digest = hashlib.sha256(canonical_vc_bytes(contract)).hexdigest()
    validation_digest = hashlib.sha256(
        canonical_source_validation_bytes(validation)
    ).hexdigest()
    signature = derive_transfer_signature(
        contract,
        source_contract_ref=f"contract:{contract['contract_id']}",
        source_contract_digest=contract_digest,
        source_validations=[SourceValidationArtifact(validation, validation_digest)],
        repo_root=ROOT,
    )
    return signature, contract, validation


def golden_profile(name: str, label: str) -> dict[str, Any]:
    return load_yaml(TS_GOLDEN / name / f"{label}.profile.yaml")

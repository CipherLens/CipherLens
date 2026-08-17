"""Regenerate deterministic TS/Profile/Evaluation golden snapshots."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any, Mapping

import yaml

from contract_miner.schema import canonical_vc_bytes
from contract_miner.source_validation import canonical_source_validation_bytes
from transfer_signature import (
    SourceValidationArtifact,
    derive_transfer_signature,
    evaluate_transfer_signature,
)
from transfer_signature.model import PROFILE_SCHEMA_VERSION


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_FIXTURES = ROOT / "tests" / "contract_miner" / "fixtures" / "golden"
OUTPUT_ROOT = ROOT / "tests" / "transfer_signature" / "fixtures" / "golden"
EVIDENCE_PATH = "tests/transfer_signature/fixtures/synthetic_target_evidence.md"


CASES = {
    "mbedtls_poc_0020": {
        "surface": "synthetic:rsa-parse-surface",
        "subjects": [
            ("SYNTHETIC_PARSE_SURFACE", "API_GROUP", ["encoded_input"]),
            ("SYNTHETIC_PARSER", "API", ["encoded_input"]),
            ("SYNTHETIC_INPUT", "OBJECT", ["encoded_input"]),
            ("SYNTHETIC_PARSE_CHANNEL", "OBSERVATION_CHANNEL", ["encoded_input"]),
        ],
        "role_subjects": {"encoded_input": "SYNTHETIC_INPUT"},
        "operation_subject": "SYNTHETIC_PARSER",
        "surface_subject": "SYNTHETIC_PARSE_SURFACE",
        "observable_subject": "SYNTHETIC_PARSE_CHANNEL",
        "participants": ["SYNTHETIC_PARSER"],
    },
    "mbedtls_poc_0004": {
        "surface": "synthetic:cipher-final-surface",
        "subjects": [
            ("SYNTHETIC_CIPHER_SURFACE", "API_GROUP", ["stateful_context", "encoded_input"]),
            ("SYNTHETIC_FINAL", "API", ["stateful_context"]),
            ("SYNTHETIC_CONTEXT", "OBJECT", ["stateful_context"]),
            ("SYNTHETIC_CIPHER_INPUT", "OBJECT", ["encoded_input"]),
            ("SYNTHETIC_OUTPUT_CHANNEL", "OBSERVATION_CHANNEL", ["stateful_context"]),
        ],
        "role_subjects": {
            "stateful_context": "SYNTHETIC_CONTEXT",
            "encoded_input": "SYNTHETIC_CIPHER_INPUT",
        },
        "operation_subject": "SYNTHETIC_FINAL",
        "surface_subject": "SYNTHETIC_CIPHER_SURFACE",
        "observable_subject": "SYNTHETIC_OUTPUT_CHANNEL",
        "participants": ["SYNTHETIC_FINAL"],
    },
    "mbedtls_poc_0005": {
        "surface": "synthetic:object-state-surface",
        "subjects": [
            ("SYNTHETIC_STATE_SURFACE", "API_GROUP", ["stateful_context", "encoded_input"]),
            ("SYNTHETIC_UPDATE", "API", ["stateful_context"]),
            ("SYNTHETIC_STATE_OBJECT", "OBJECT", ["stateful_context"]),
            ("SYNTHETIC_VALUE", "OBJECT", ["encoded_input"]),
            ("SYNTHETIC_STATE_CHANNEL", "OBSERVATION_CHANNEL", ["stateful_context"]),
        ],
        "role_subjects": {
            "stateful_context": "SYNTHETIC_STATE_OBJECT",
            "encoded_input": "SYNTHETIC_VALUE",
        },
        "operation_subject": "SYNTHETIC_UPDATE",
        "surface_subject": "SYNTHETIC_STATE_SURFACE",
        "observable_subject": "SYNTHETIC_STATE_CHANNEL",
        "participants": ["SYNTHETIC_UPDATE", "SYNTHETIC_UPDATE", "SYNTHETIC_UPDATE"],
    },
}


def main() -> None:
    evidence_digest = hashlib.sha256((ROOT / EVIDENCE_PATH).read_bytes()).hexdigest()
    for case_name, case in CASES.items():
        contract_dir = CONTRACT_FIXTURES / case_name
        contract = _load(contract_dir / "expected.vc.yaml")
        validation = _load(contract_dir / "expected.validation.yaml")
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
        eligible = _profile(signature, contract, case, "ELIGIBLE", evidence_digest)
        ineligible = deepcopy(eligible)
        ineligible["profile_id"] = f"{contract['contract_id']}_INELIGIBLE_PROFILE"
        for fact in ineligible["facts"]:
            if fact["fact_type"] in {
                "complete_input_enforcement",
                "failure_output_transactionality",
                "atomic_clear_semantics",
                "terminalization_after_operation",
            }:
                fact["assertion"] = "TRUE"
                break
        indeterminate = deepcopy(eligible)
        indeterminate["profile_id"] = f"{contract['contract_id']}_INDETERMINATE_PROFILE"
        for index, fact in enumerate(indeterminate["facts"]):
            if fact["fact_type"] in {"observable_channel", "observable_correlation"}:
                fact["epistemic_status"] = "INFERRED" if index % 2 == 0 else "PROPOSED"

        output = OUTPUT_ROOT / case_name
        output.mkdir(parents=True, exist_ok=True)
        _dump(output / "expected.ts.yaml", signature)
        for label, profile in (
            ("eligible", eligible),
            ("ineligible", ineligible),
            ("indeterminate", indeterminate),
        ):
            evaluation = evaluate_transfer_signature(
                signature, profile, contract, repo_root=ROOT
            )
            _dump(output / f"{label}.profile.yaml", profile)
            _dump(output / f"{label}.evaluation.yaml", evaluation)


def _profile(
    signature: Mapping[str, Any],
    contract: Mapping[str, Any],
    case: Mapping[str, Any],
    label: str,
    evidence_digest: str,
) -> dict[str, Any]:
    surface = case["surface"]
    subjects = [
        {
            "subject_ref": subject_ref,
            "subject_kind": subject_kind,
            "surface_ref": surface,
            "semantic_roles": roles,
        }
        for subject_ref, subject_kind, roles in case["subjects"]
    ]
    facts: list[dict[str, Any]] = []
    groups = (
        signature["required_capabilities"],
        signature["excluded_semantics"],
        signature["required_observability"],
    )
    for constraints in groups:
        for constraint in constraints:
            facts.append(_fact(constraint, contract, case))
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_id": f"{contract['contract_id']}_{label}_PROFILE",
        "target_scope": {
            "library": "synthetic-target",
            "version": "1.0",
            "surface_ref": surface,
        },
        "subjects": subjects,
        "facts": facts,
        "evidence": [
            {
                "evidence_id": "SYNTHETIC_FIXTURE",
                "kind": "test_fixture",
                "path": EVIDENCE_PATH,
                "sha256": evidence_digest,
            }
        ],
    }


def _fact(
    constraint: Mapping[str, Any],
    contract: Mapping[str, Any],
    case: Mapping[str, Any],
) -> dict[str, Any]:
    constraint_type = constraint["type"]
    parameters = deepcopy(constraint["parameters"])
    assertion = "TRUE"
    if constraint_type == "supports_operation_role":
        fact_type = "operation_role"
        subject_ref = case["operation_subject"]
    elif constraint_type == "supports_object_role":
        fact_type = "object_role"
        subject_ref = case["role_subjects"][parameters["role"]]
    elif constraint_type == "supports_precondition_shape":
        fact_type = "precondition_shape"
        subject_ref = case["surface_subject"]
    elif constraint_type == "permits_equivalent_intervention":
        fact_type = "equivalent_intervention"
        subject_ref = case["surface_subject"]
    elif constraint_type == "supports_execution_shape":
        fact_type = "execution_shape"
        subject_ref = case["surface_subject"]
        parameters["participant_refs"] = list(case["participants"])
    elif constraint_type == "mandatory_complete_input_enforcement":
        fact_type = "complete_input_enforcement"
        subject_ref = case["surface_subject"]
        assertion = "FALSE"
    elif constraint_type == "failure_output_transactionality":
        fact_type = "failure_output_transactionality"
        subject_ref = case["surface_subject"]
        assertion = "FALSE"
    elif constraint_type == "atomic_clear_precludes_inconsistent_intermediate_state":
        fact_type = "atomic_clear_semantics"
        subject_ref = case["surface_subject"]
        assertion = "FALSE"
    elif constraint_type == "mandatory_terminalization_precludes_followup":
        fact_type = "terminalization_after_operation"
        subject_ref = case["surface_subject"]
        assertion = "FALSE"
    elif constraint_type == "contract_observable_resolvable":
        fact_type = "observable_channel"
        subject_ref = case["observable_subject"]
        parameters = _observable_parameters(contract, parameters["observable_ref"])
    elif constraint_type == "observable_set_correlatable":
        fact_type = "observable_correlation"
        subject_ref = case["surface_subject"]
        parameters["participant_refs"] = [case["observable_subject"]]
    else:
        raise AssertionError(f"unhandled constraint type {constraint_type}")
    return {
        "fact_id": f"F_{constraint['constraint_id']}",
        "subject_ref": subject_ref,
        "coverage": "SURFACE",
        "fact_type": fact_type,
        "parameters": parameters,
        "assertion": assertion,
        "epistemic_status": "VERIFIED",
        "evidence_refs": ["SYNTHETIC_FIXTURE"],
    }


def _observable_parameters(
    contract: Mapping[str, Any], observable_ref: str
) -> dict[str, Any]:
    observable = next(
        item
        for item in contract["observable_evidence"]["observables"]
        if item["observable_id"] == observable_ref
    )
    step_ref = observable["source"].get("step_ref")
    operation_role = "PROCESS_END"
    if step_ref is not None:
        operation_role = next(
            step["role"]
            for step in contract["execution"]["steps"]
            if step["step_id"] == step_ref
        )
    return {
        "observable_ref": observable_ref,
        "semantic_role": observable["semantic_role"],
        "value_type": observable["value_type"],
        "phase": observable["source"]["phase"],
        "operation_role": operation_role,
    }


def _load(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _dump(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        yaml.safe_dump(
            dict(value), allow_unicode=True, default_flow_style=False, sort_keys=True
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

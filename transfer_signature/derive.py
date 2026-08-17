"""Derive target-agnostic Transfer Signatures from validated VC v0.3."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from contract_miner.schema import canonical_vc_bytes, validate_vc
from contract_miner.source_validation import (
    canonical_source_validation_bytes,
    validate_source_validation_record,
)

from transfer_signature.canonical import validate_signature_or_raise
from transfer_signature.family_rules import FAMILY_RULES, family_rule
from transfer_signature.model import DerivationError, SourceValidationArtifact, TS_SCHEMA_VERSION


_SAFE_ID = re.compile(r"[^A-Z0-9_]+")


def derive_transfer_signature(
    contract: Mapping[str, Any],
    *,
    source_contract_ref: str,
    source_contract_digest: str,
    source_validations: Sequence[SourceValidationArtifact],
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Apply the validated-Contract gate and deterministic family derivation."""

    root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
    _generation_gate(
        contract,
        source_contract_ref,
        source_contract_digest,
        source_validations,
        root,
    )
    contract_id = contract["contract_id"]
    family = contract["contract_family"]
    rule = family_rule(family)
    objects = contract["context"]["objects"]
    object_by_id = {item["object_id"]: item for item in objects}
    constraints: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    for index, item in enumerate(objects):
        _add_constraint(
            constraints,
            "required_capabilities",
            f"RC_OBJECT_{_id(item['object_id'])}",
            "supports_object_role",
            {"role": item["semantic_role"], "value_type": item["value_type"]},
            "direct_projection",
            "ts.direct.object_role.v0_1",
            [f"contract:/context/objects/{index}"],
        )

    for index, item in enumerate(contract["context"]["preconditions"]):
        operand_roles = [object_by_id[ref]["semantic_role"] for ref in item["operand_refs"]]
        _add_constraint(
            constraints,
            "required_capabilities",
            f"RC_PRECONDITION_{_id(item['precondition_id'])}",
            "supports_precondition_shape",
            {"predicate_id": item["predicate_id"], "operand_roles": operand_roles},
            "direct_projection",
            "ts.direct.precondition_shape.v0_1",
            [f"contract:/context/preconditions/{index}"],
        )

    for index, item in enumerate(contract["intervention"]["actions"]):
        target_role = object_by_id[item["target_ref"]]["semantic_role"]
        sources = [f"contract:/intervention/actions/{index}"]
        sources.extend(f"evidence:{ref}" for ref in item["evidence_refs"])
        _add_constraint(
            constraints,
            "required_capabilities",
            f"RC_INTERVENTION_{_id(item['action_id'])}",
            "permits_equivalent_intervention",
            {"kind": item["kind"], "target_role": target_role},
            "direct_projection",
            "ts.direct.intervention.v0_1",
            sources,
        )

    operation_sources: dict[tuple[str, str], list[str]] = {}
    steps = contract["execution"]["steps"]
    for index, step in enumerate(steps):
        subject_role = object_by_id[step["target_ref"]]["semantic_role"]
        operation_sources.setdefault((step["role"], subject_role), []).append(
            f"contract:/execution/steps/{index}"
        )
    for (role, subject_role), sources in sorted(operation_sources.items()):
        _add_constraint(
            constraints,
            "required_capabilities",
            f"RC_OPERATION_{_id(role)}_{_id(subject_role)}",
            "supports_operation_role",
            {"role": role, "subject_role": subject_role},
            "direct_projection",
            "ts.direct.operation_role.v0_1",
            sources,
        )

    target_refs = [step["target_ref"] for step in steps]
    continuity = "single_subject" if len(set(target_refs)) == 1 else "multi_subject"
    _add_constraint(
        constraints,
        "required_capabilities",
        "RC_EXECUTION_SHAPE",
        "supports_execution_shape",
        {
            "roles": [step["role"] for step in steps],
            "subject_roles": [
                object_by_id[step["target_ref"]]["semantic_role"] for step in steps
            ],
            "continuity": continuity,
        },
        "direct_projection",
        "ts.direct.execution_shape.v0_1",
        ["contract:/execution/steps"],
    )

    evidence_refs = [
        f"evidence:{item['evidence_id']}" for item in contract["provenance"]["evidence"]
    ]
    for index, (constraint_type, parameters) in enumerate(rule.excluded_semantics, 1):
        _add_constraint(
            constraints,
            "excluded_semantics",
            f"ES_{index:02d}_{_id(constraint_type)}",
            constraint_type,
            dict(parameters),
            "family_rule",
            rule.rule_id,
            [
                "contract:/expected_relation",
                f"family_rule:{rule.rule_id}",
                *evidence_refs,
            ],
        )

    observable_ids = _required_observable_ids(contract)
    observable_index = {
        item["observable_id"]: index
        for index, item in enumerate(contract["observable_evidence"]["observables"])
    }
    for observable_id in observable_ids:
        index = observable_index[observable_id]
        _add_constraint(
            constraints,
            "required_observability",
            f"RO_OBSERVABLE_{_id(observable_id)}",
            "contract_observable_resolvable",
            {"observable_ref": observable_id},
            "direct_projection",
            "ts.direct.observable_ref.v0_1",
            [
                f"contract:/observable_evidence/observables/{index}",
                "contract:/expected_relation",
            ],
        )
    if len(observable_ids) > 1:
        _add_constraint(
            constraints,
            "required_observability",
            "RO_OBSERVABLE_CORRELATION",
            "observable_set_correlatable",
            {
                "observable_refs": observable_ids,
                "correlation_scope": rule.correlation_scope,
            },
            "family_rule",
            rule.rule_id,
            [
                "contract:/observable_evidence/observables",
                f"family_rule:{rule.rule_id}",
            ],
        )

    grouped: dict[str, list[dict[str, Any]]] = {
        "required_capabilities": [],
        "excluded_semantics": [],
        "required_observability": [],
    }
    derivations: list[dict[str, Any]] = []
    for constraint_class, constraint, derivation in constraints:
        grouped[constraint_class].append(constraint)
        derivations.append(derivation)
    for values in grouped.values():
        values.sort(key=lambda item: item["constraint_id"])
    derivations.sort(key=lambda item: item["derivation_id"])

    passing = sorted(
        (
            artifact
            for artifact in source_validations
            if artifact.record.get("status") == "PASS"
        ),
        key=lambda artifact: str(artifact.record.get("validation_id")),
    )
    signature = {
        "schema_version": TS_SCHEMA_VERSION,
        "signature_id": f"{contract_id}_TS_V0_1",
        "source_contract_ref": source_contract_ref,
        "source_contract_digest": source_contract_digest,
        "source_validation_refs": [
            {
                "validation_id": artifact.record["validation_id"],
                "validation_digest": artifact.digest,
            }
            for artifact in passing
        ],
        "contract_family": family,
        **grouped,
        "provenance": {
            "producer": {
                "name": "transfer_signature",
                "version": "v0.1",
                "mode": "deterministic_family_rule",
            },
            "evidence": sorted(
                (dict(item) for item in contract["provenance"]["evidence"]),
                key=lambda item: item["evidence_id"],
            ),
            "derivations": derivations,
        },
    }
    validate_signature_or_raise(signature, repo_root=root)
    return signature


def _generation_gate(
    contract: Mapping[str, Any],
    source_contract_ref: str,
    declared_contract_digest: str,
    source_validations: Sequence[SourceValidationArtifact],
    repo_root: Path,
) -> None:
    errors = validate_vc(contract, repo_root=repo_root)
    if errors:
        raise DerivationError("VC schema validation failed: " + "; ".join(errors))
    if contract.get("schema_version") != "cipherlens.vc.v0_3":
        raise DerivationError("only validated VC v0.3 can derive a Transfer Signature")
    expected_ref = f"contract:{contract['contract_id']}"
    if source_contract_ref != expected_ref:
        raise DerivationError(
            f"source_contract_ref mismatch: expected {expected_ref!r}"
        )
    actual_contract_digest = hashlib.sha256(canonical_vc_bytes(contract)).hexdigest()
    if declared_contract_digest != actual_contract_digest:
        raise DerivationError("source Contract digest mismatch")
    if not source_validations:
        raise DerivationError("at least one source validation artifact is required")
    pass_count = 0
    for index, artifact in enumerate(source_validations):
        validation_errors = validate_source_validation_record(artifact.record)
        if validation_errors:
            raise DerivationError(
                f"source validation {index} invalid: " + "; ".join(validation_errors)
            )
        actual_validation_digest = hashlib.sha256(
            canonical_source_validation_bytes(artifact.record)
        ).hexdigest()
        if artifact.digest != actual_validation_digest:
            raise DerivationError(f"source validation {index} digest mismatch")
        if artifact.record.get("contract_id") != contract.get("contract_id"):
            raise DerivationError(f"source validation {index} Contract ID mismatch")
        if artifact.record.get("provenance", {}).get("contract_sha256") != actual_contract_digest:
            raise DerivationError(f"source validation {index} Contract digest mismatch")
        if artifact.record.get("status") == "PASS":
            pass_count += 1
    if pass_count == 0:
        raise DerivationError("at least one PASS source validation is required")
    if contract.get("contract_family") not in FAMILY_RULES:
        raise DerivationError(
            f"no registered TS family rule for {contract.get('contract_family')!r}"
        )


def _add_constraint(
    collection: list[tuple[str, dict[str, Any], dict[str, Any]]],
    constraint_class: str,
    constraint_id: str,
    constraint_type: str,
    parameters: Mapping[str, Any],
    method: str,
    rule_id: str,
    source_refs: Iterable[str],
) -> None:
    derivation_id = f"D_{constraint_id}"
    constraint = {
        "constraint_id": constraint_id,
        "type": constraint_type,
        "parameters": dict(parameters),
        "derivation_refs": [derivation_id],
    }
    derivation = {
        "derivation_id": derivation_id,
        "constraint_ref": constraint_id,
        "method": method,
        "rule_id": rule_id,
        "source_refs": list(dict.fromkeys(source_refs)),
    }
    collection.append((constraint_class, constraint, derivation))


def _required_observable_ids(contract: Mapping[str, Any]) -> list[str]:
    referenced: set[str] = set()
    for relation in contract["expected_relation"]["relations"]:
        for key, value in relation["operands"].items():
            if key.endswith("_ref") and isinstance(value, str):
                referenced.add(value)
    for observable in contract["observable_evidence"]["observables"]:
        if observable["requirement"] == "required":
            referenced.add(observable["observable_id"])
    declared_order = [
        item["observable_id"] for item in contract["observable_evidence"]["observables"]
    ]
    return [observable_id for observable_id in declared_order if observable_id in referenced]


def _id(value: str) -> str:
    return _SAFE_ID.sub("_", value.upper()).strip("_")

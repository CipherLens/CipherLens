"""Constraint-specific fact matching and deterministic TS eligibility."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping

from contract_miner.schema import canonical_vc_bytes, validate_vc_or_raise

from transfer_signature.canonical import (
    validate_evaluation_or_raise,
    validate_signature_or_raise,
)
from transfer_signature.model import (
    Assertion,
    ConstraintClass,
    ConstraintEvaluation,
    ConstraintResult,
    EVALUATION_SCHEMA_VERSION,
    Eligibility,
    EpistemicStatus,
    FactCoverage,
    TransferSignatureError,
)
from transfer_signature.profile import validate_profile_or_raise
from transfer_signature.registry import CONSTRAINT_REGISTRY


FactMatcher = Callable[
    [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
    bool,
]


def _match_operation_role(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    expected = constraint["parameters"]
    actual = fact["parameters"]
    subject = _subject(profile, fact["subject_ref"])
    return (
        actual == expected
        and expected["subject_role"] in subject["semantic_roles"]
    )


def _match_object_role(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    expected = constraint["parameters"]
    subject = _subject(profile, fact["subject_ref"])
    return fact["parameters"] == expected and expected["role"] in subject["semantic_roles"]


def _match_precondition_shape(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    expected = constraint["parameters"]
    subject = _subject(profile, fact["subject_ref"])
    return (
        fact["parameters"] == expected
        and set(expected["operand_roles"]).issubset(subject["semantic_roles"])
    )


def _match_intervention(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    expected = constraint["parameters"]
    subject = _subject(profile, fact["subject_ref"])
    return (
        fact["parameters"] == expected
        and expected["target_role"] in subject["semantic_roles"]
    )


def _match_execution_shape(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    expected = constraint["parameters"]
    actual = fact["parameters"]
    semantic_actual = {key: actual[key] for key in ("roles", "subject_roles", "continuity")}
    participants = actual["participant_refs"]
    if semantic_actual != expected or len(participants) != len(expected["roles"]):
        return False
    if expected["continuity"] == "single_subject" and len(set(participants)) != 1:
        return False
    if expected["continuity"] == "multi_subject" and len(set(participants)) < 2:
        return False
    for participant, role in zip(participants, expected["subject_roles"]):
        if role not in _subject(profile, participant)["semantic_roles"]:
            return False
    return True


def _match_complete_input_enforcement(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    return fact["parameters"] == constraint["parameters"]


def _match_failure_output_transactionality(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    return fact["parameters"] == constraint["parameters"]


def _match_atomic_clear(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    return fact["parameters"] == constraint["parameters"]


def _match_terminalization(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    return fact["parameters"] == constraint["parameters"]


def _match_observable_channel(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    observable_ref = constraint["parameters"]["observable_ref"]
    observable = _observable(contract, observable_ref)
    step_role = _observable_operation_role(contract, observable)
    expected = {
        "observable_ref": observable_ref,
        "semantic_role": observable["semantic_role"],
        "value_type": observable["value_type"],
        "phase": observable["source"]["phase"],
        "operation_role": step_role,
    }
    return fact["parameters"] == expected


def _match_observable_correlation(constraint: Mapping[str, Any], fact: Mapping[str, Any], profile: Mapping[str, Any], contract: Mapping[str, Any]) -> bool:
    expected = constraint["parameters"]
    actual = fact["parameters"]
    if actual["observable_refs"] != expected["observable_refs"]:
        return False
    if actual["correlation_scope"] != expected["correlation_scope"]:
        return False
    participants = actual["participant_refs"]
    if not participants:
        return False
    if expected["correlation_scope"] == "same_subject" and len(set(participants)) != 1:
        return False
    return all(_subject(profile, ref) for ref in participants)


FACT_MATCHER_REGISTRY: dict[str, FactMatcher] = {
    "supports_operation_role": _match_operation_role,
    "supports_object_role": _match_object_role,
    "supports_precondition_shape": _match_precondition_shape,
    "permits_equivalent_intervention": _match_intervention,
    "supports_execution_shape": _match_execution_shape,
    "mandatory_complete_input_enforcement": _match_complete_input_enforcement,
    "failure_output_transactionality": _match_failure_output_transactionality,
    "atomic_clear_precludes_inconsistent_intermediate_state": _match_atomic_clear,
    "mandatory_terminalization_precludes_followup": _match_terminalization,
    "contract_observable_resolvable": _match_observable_channel,
    "observable_set_correlatable": _match_observable_correlation,
}


def evaluate_transfer_signature(
    signature: Mapping[str, Any],
    profile: Mapping[str, Any],
    contract: Mapping[str, Any],
    *,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Evaluate target eligibility without producing a Contract Verdict."""

    root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
    validate_signature_or_raise(signature, repo_root=root)
    validate_profile_or_raise(profile, repo_root=root)
    validate_vc_or_raise(contract, repo_root=root)
    actual_digest = hashlib.sha256(canonical_vc_bytes(contract)).hexdigest()
    if signature["source_contract_digest"] != actual_digest:
        raise TransferSignatureError("evaluation Contract digest does not match TS")
    if signature["source_contract_ref"] != f"contract:{contract['contract_id']}":
        raise TransferSignatureError("evaluation Contract reference does not match TS")

    evaluations: list[ConstraintEvaluation] = []
    groups = (
        ("required_capabilities", ConstraintClass.REQUIRED_CAPABILITY),
        ("excluded_semantics", ConstraintClass.EXCLUDED_SEMANTIC),
        ("required_observability", ConstraintClass.REQUIRED_OBSERVABILITY),
    )
    for key, constraint_class in groups:
        for constraint in signature[key]:
            evaluations.append(
                _evaluate_constraint(
                    constraint, constraint_class, profile, contract
                )
            )

    eligibility, reason_codes = _aggregate(evaluations)
    result = {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "signature_id": signature["signature_id"],
        "profile_id": profile["profile_id"],
        "constraint_results": [item.to_dict() for item in evaluations],
        "eligibility": eligibility.value,
        "reason_codes": reason_codes,
    }
    validate_evaluation_or_raise(result)
    return result


def _evaluate_constraint(
    constraint: Mapping[str, Any],
    constraint_class: ConstraintClass,
    profile: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> ConstraintEvaluation:
    spec = CONSTRAINT_REGISTRY[constraint["type"]]
    matcher = FACT_MATCHER_REGISTRY[constraint["type"]]
    compatible = [
        fact
        for fact in profile["facts"]
        if fact["fact_type"] == spec.fact_type
        and _scope_compatible(fact, profile)
        and matcher(constraint, fact, profile, contract)
    ]
    verified_true = [
        fact
        for fact in compatible
        if fact["epistemic_status"] == EpistemicStatus.VERIFIED.value
        and fact["assertion"] == Assertion.TRUE.value
    ]
    verified_surface_false = [
        fact
        for fact in compatible
        if fact["epistemic_status"] == EpistemicStatus.VERIFIED.value
        and fact["assertion"] == Assertion.FALSE.value
        and fact["coverage"] == FactCoverage.SURFACE.value
    ]
    if verified_true:
        return ConstraintEvaluation(
            constraint_id=constraint["constraint_id"],
            constraint_class=constraint_class,
            result=ConstraintResult.MATCH,
            matched_fact_refs=tuple(sorted(fact["fact_id"] for fact in verified_true)),
            reason_code=(
                "VERIFIED_EXCLUSION_PRESENT"
                if constraint_class is ConstraintClass.EXCLUDED_SEMANTIC
                else "VERIFIED_CHANNEL_AVAILABLE"
                if constraint_class is ConstraintClass.REQUIRED_OBSERVABILITY
                else "VERIFIED_COMPATIBLE_TRUE"
            ),
        )
    if verified_surface_false:
        return ConstraintEvaluation(
            constraint_id=constraint["constraint_id"],
            constraint_class=constraint_class,
            result=ConstraintResult.MISMATCH,
            matched_fact_refs=tuple(
                sorted(fact["fact_id"] for fact in verified_surface_false)
            ),
            reason_code=(
                "VERIFIED_EXCLUSION_ABSENT"
                if constraint_class is ConstraintClass.EXCLUDED_SEMANTIC
                else "VERIFIED_CHANNEL_UNAVAILABLE"
                if constraint_class is ConstraintClass.REQUIRED_OBSERVABILITY
                else "VERIFIED_COMPATIBLE_FALSE"
            ),
        )
    if compatible:
        return ConstraintEvaluation(
            constraint_id=constraint["constraint_id"],
            constraint_class=constraint_class,
            result=ConstraintResult.UNKNOWN,
            matched_fact_refs=tuple(sorted(fact["fact_id"] for fact in compatible)),
            reason_code="NONDETERMINATE_COMPATIBLE_FACT",
            missing_fact_requirements=("VERIFIED_FACT", "SURFACE_NEGATIVE_FACT"),
        )
    return ConstraintEvaluation(
        constraint_id=constraint["constraint_id"],
        constraint_class=constraint_class,
        result=ConstraintResult.UNKNOWN,
        matched_fact_refs=(),
        reason_code="NO_COMPATIBLE_FACT",
        missing_fact_requirements=("COMPATIBLE_FACT", "COMPATIBLE_SUBJECT"),
    )


def _aggregate(
    evaluations: list[ConstraintEvaluation],
) -> tuple[Eligibility, list[str]]:
    cap_mismatch = any(
        item.constraint_class is ConstraintClass.REQUIRED_CAPABILITY
        and item.result is ConstraintResult.MISMATCH
        for item in evaluations
    )
    obs_mismatch = any(
        item.constraint_class is ConstraintClass.REQUIRED_OBSERVABILITY
        and item.result is ConstraintResult.MISMATCH
        for item in evaluations
    )
    excluded_match = any(
        item.constraint_class is ConstraintClass.EXCLUDED_SEMANTIC
        and item.result is ConstraintResult.MATCH
        for item in evaluations
    )
    if cap_mismatch or obs_mismatch or excluded_match:
        reasons: list[str] = []
        if cap_mismatch:
            reasons.append("REQUIRED_CAPABILITY_MISMATCH")
        if obs_mismatch:
            reasons.append("REQUIRED_OBSERVABILITY_MISMATCH")
        if excluded_match:
            reasons.append("EXCLUDED_SEMANTIC_MATCH")
        return Eligibility.INELIGIBLE, reasons
    required = [
        item
        for item in evaluations
        if item.constraint_class
        in {ConstraintClass.REQUIRED_CAPABILITY, ConstraintClass.REQUIRED_OBSERVABILITY}
    ]
    excluded = [
        item
        for item in evaluations
        if item.constraint_class is ConstraintClass.EXCLUDED_SEMANTIC
    ]
    if all(item.result is ConstraintResult.MATCH for item in required) and all(
        item.result is ConstraintResult.MISMATCH for item in excluded
    ):
        return Eligibility.ELIGIBLE, ["ALL_ELIGIBILITY_CONDITIONS_MET"]
    return Eligibility.INDETERMINATE, ["UNRESOLVED_CONSTRAINTS"]


def _scope_compatible(fact: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    subject = _subject(profile, fact["subject_ref"])
    return subject["surface_ref"] == profile["target_scope"]["surface_ref"]


def _subject(profile: Mapping[str, Any], subject_ref: str) -> Mapping[str, Any]:
    for subject in profile["subjects"]:
        if subject["subject_ref"] == subject_ref:
            return subject
    raise TransferSignatureError(f"undeclared profile subject {subject_ref!r}")


def _observable(contract: Mapping[str, Any], observable_ref: str) -> Mapping[str, Any]:
    for observable in contract["observable_evidence"]["observables"]:
        if observable["observable_id"] == observable_ref:
            return observable
    raise TransferSignatureError(f"TS references undeclared Contract observable {observable_ref!r}")


def _observable_operation_role(
    contract: Mapping[str, Any], observable: Mapping[str, Any]
) -> str:
    step_ref = observable["source"].get("step_ref")
    if step_ref is None:
        return "PROCESS_END"
    for step in contract["execution"]["steps"]:
        if step["step_id"] == step_ref:
            return step["role"]
    raise TransferSignatureError(f"observable has undeclared step_ref {step_ref!r}")

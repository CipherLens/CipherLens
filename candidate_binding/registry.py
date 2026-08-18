"""Ten deterministic CandidateBinding validation checks."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Mapping

from candidate_binding.canonical import candidate_binding_digest
from candidate_binding.model import CheckResult, ValidationContext, ValidationStatus, ValidatorType, VALIDATION_SCHEMA_VERSION, VALIDATOR_REGISTRY_VERSION
from candidate_binding.validate import validate_candidate_binding
from contract_miner.schema import canonical_vc_bytes
from transfer_signature.canonical import canonical_evaluation_bytes, signature_digest
from transfer_signature.profile import profile_digest
from trigger_template_interface.canonical import manifest_digest


def validate_with_registry(binding: Mapping[str, Any], context: ValidationContext) -> dict[str, Any]:
    checks = [VALIDATOR_REGISTRY[k](binding, context) for k in ValidatorType]
    if any(x["result"] == CheckResult.FAIL.value for x in checks):
        status = ValidationStatus.INVALID
    elif any(x["result"] == CheckResult.INCOMPLETE.value for x in checks):
        status = ValidationStatus.INCOMPLETE
    else:
        status = ValidationStatus.VALID
    digest = candidate_binding_digest(binding)
    validation_id = "validation:" + hashlib.sha256((digest + "\0" + VALIDATOR_REGISTRY_VERSION).encode()).hexdigest()
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "validation_id": validation_id,
        "candidate_binding_ref": binding["binding_id"],
        "candidate_binding_digest": digest,
        "validator_registry_version": VALIDATOR_REGISTRY_VERSION,
        "status": status.value,
        "check_results": checks,
        "reason_codes": sorted({x["reason_code"] for x in checks if x["result"] != CheckResult.PASS.value}),
    }


def _check(kind: ValidatorType, result: CheckResult, reason: str, *, refs: list[str] | None = None, facts: list[str] | None = None, evidence: list[str] | None = None, missing: list[str] | None = None) -> dict[str, Any]:
    return {"check_id": f"CHECK_{kind.value}", "validator_type": kind.value, "result": result.value,
            "binding_refs": sorted(set(refs or [])), "verified_fact_refs": sorted(set(facts or [])),
            "evidence_refs": sorted(set(evidence or [])), "reason_code": reason,
            "missing_requirements": sorted(set(missing or []))}


def _reference(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    contract_digest = hashlib.sha256(canonical_vc_bytes(ctx.contract)).hexdigest()
    evaluation_digest = hashlib.sha256(canonical_evaluation_bytes(ctx.eligibility_evaluation)).hexdigest()
    expected = {
        "source_contract_ref": f"contract:{ctx.contract['contract_id']}", "source_contract_digest": contract_digest,
        "transfer_signature_ref": f"transfer-signature:{ctx.transfer_signature['signature_id']}", "transfer_signature_digest": signature_digest(ctx.transfer_signature),
        "trigger_template_ref": ctx.template_manifest["trigger_template_ref"], "trigger_template_digest": ctx.template_manifest["trigger_template_digest"],
        "target_profile_ref": f"target-profile:{ctx.target_profile['profile_id']}", "target_profile_digest": profile_digest(ctx.target_profile),
        "eligibility_evaluation_ref": f"eligibility-evaluation:{ctx.transfer_signature['signature_id']}:{ctx.target_profile['profile_id']}", "eligibility_evaluation_digest": evaluation_digest,
    }
    mismatches = [key for key, value in expected.items() if binding.get(key) != value]
    consistency = []
    if ctx.transfer_signature.get("source_contract_ref") != expected["source_contract_ref"] or ctx.transfer_signature.get("source_contract_digest") != contract_digest:
        consistency.append("CONTRACT_TS_MISMATCH")
    if ctx.eligibility_evaluation.get("signature_id") != ctx.transfer_signature.get("signature_id") or ctx.eligibility_evaluation.get("profile_id") != ctx.target_profile.get("profile_id"):
        consistency.append("TS_EVALUATION_PROFILE_MISMATCH")
    if mismatches or consistency:
        return _check(ValidatorType.REFERENCE_INTEGRITY, CheckResult.FAIL, "REFERENCE_MISMATCH", refs=[binding.get("binding_id", "")], missing=mismatches + consistency)
    return _check(ValidatorType.REFERENCE_INTEGRITY, CheckResult.PASS, "REFERENCES_VERIFIED", refs=[ctx.template_manifest["manifest_id"]], evidence=[manifest_digest(ctx.template_manifest)])


def _target_scope(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    profile_scope = ctx.target_profile.get("target_scope")
    if binding.get("target_scope") != profile_scope:
        return _check(ValidatorType.TARGET_SCOPE, CheckResult.FAIL, "TARGET_SCOPE_MISMATCH")
    return _check(ValidatorType.TARGET_SCOPE, CheckResult.PASS, "TARGET_SCOPE_VERIFIED")


def _eligibility(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    eligibility = ctx.eligibility_evaluation.get("eligibility")
    if eligibility != "ELIGIBLE":
        return _check(ValidatorType.ELIGIBILITY_GATE, CheckResult.FAIL, f"ELIGIBILITY_{eligibility}")
    return _check(ValidatorType.ELIGIBILITY_GATE, CheckResult.PASS, "ELIGIBILITY_ELIGIBLE")


def _facts(ctx: ValidationContext) -> dict[str, Mapping[str, Any]]:
    return {fact["fact_id"]: fact for fact in ctx.target_profile.get("facts", [])}


def _fact_state(refs: list[str], ctx: ValidationContext) -> tuple[CheckResult, list[str], list[str], list[str]]:
    facts = _facts(ctx)
    missing = [ref for ref in refs if ref not in facts]
    unverified = [ref for ref in refs if ref in facts and facts[ref].get("epistemic_status") != "VERIFIED"]
    verified = [ref for ref in refs if ref in facts and facts[ref].get("epistemic_status") == "VERIFIED"]
    evidence = [e for ref in verified for e in facts[ref].get("evidence_refs", [])]
    if missing or unverified or not verified:
        return CheckResult.INCOMPLETE, verified, evidence, missing + unverified + ([] if refs else ["VERIFIED_FACT"])
    return CheckResult.PASS, verified, evidence, []


def _all_refs(items: list[Mapping[str, Any]], key: str = "verified_fact_refs") -> list[str]:
    return [ref for item in items for ref in item.get(key, [])]


def _subject(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    profile_subjects = {x["subject_ref"]: x for x in ctx.target_profile.get("subjects", [])}
    contract_objects = {x["object_id"]: x for x in ctx.contract.get("context", {}).get("objects", [])}
    failures: list[str] = []
    for item in binding.get("subject_bindings", []):
        subject = profile_subjects.get(item["target_subject_ref"])
        obj = contract_objects.get(item["contract_object_ref"])
        if subject is None: failures.append(f"UNKNOWN_SUBJECT:{item['subject_binding_id']}")
        elif subject.get("subject_kind") != item["subject_kind"]: failures.append(f"WRONG_SUBJECT_KIND:{item['subject_binding_id']}")
        elif item["semantic_role"] not in subject.get("semantic_roles", []): failures.append(f"WRONG_SUBJECT_ROLE:{item['subject_binding_id']}")
        elif subject.get("surface_ref") != binding.get("target_scope", {}).get("surface_ref"): failures.append(f"SUBJECT_OUTSIDE_SURFACE:{item['subject_binding_id']}")
        if obj is None or obj.get("semantic_role") != item["semantic_role"]: failures.append(f"CONTRACT_OBJECT_MISMATCH:{item['subject_binding_id']}")
        if subject is not None and subject.get("subject_kind") != "OBSERVATION_CHANNEL":
            compatible_fact = any(
                fact.get("fact_type") == "object_role"
                and fact.get("subject_ref") == item["target_subject_ref"]
                and fact.get("epistemic_status") == "VERIFIED"
                and fact.get("parameters", {}).get("role") == item["semantic_role"]
                and item["target_type_ref"] == f"type:{fact.get('parameters', {}).get('value_type')}"
                for ref in item["verified_fact_refs"]
                for fact in [_facts(ctx).get(ref, {})]
            )
            if not compatible_fact: failures.append(f"TARGET_TYPE_UNVERIFIED:{item['subject_binding_id']}")
    if failures:
        return _check(ValidatorType.SUBJECT_BINDING, CheckResult.FAIL, "SUBJECT_BINDING_MISMATCH", refs=failures)
    refs = _all_refs(binding.get("subject_bindings", []))
    state, facts, evidence, missing = _fact_state(refs, ctx)
    return _check(ValidatorType.SUBJECT_BINDING, state, "SUBJECT_BINDINGS_VERIFIED" if state is CheckResult.PASS else "SUBJECT_EVIDENCE_INCOMPLETE", facts=facts, evidence=evidence, missing=missing)


def _operation(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    items = binding.get("operation_bindings", [])
    contract_steps = {x["step_id"]: x for x in ctx.contract.get("execution", {}).get("steps", [])}
    subjects = {x["subject_binding_id"]: x for x in binding.get("subject_bindings", [])}
    profile_subjects = {x["subject_ref"]: x for x in ctx.target_profile.get("subjects", [])}
    inputs = {x["input_binding_id"] for x in binding.get("input_bindings", [])}
    slots = {x["slot_ref"]: x for x in ctx.template_manifest.get("slots", [])}
    failures: list[str] = []
    primary = [x for x in items if x["binding_kind"] == "PRIMARY_CONTRACT_STEP"]
    if {x["contract_step_ref"] for x in primary} != set(contract_steps): failures.append("REQUIRED_CONTRACT_STEP_COVERAGE")
    indexes = [x["sequence_index"] for x in items]
    if len(indexes) != len(set(indexes)) or indexes != sorted(indexes): failures.append("SEQUENCE_ORDER")
    for item in items:
        step = contract_steps.get(item["contract_step_ref"])
        slot = slots.get(item["template_call_slot_ref"])
        receiver = subjects.get(item["receiver_subject_binding_ref"])
        symbol = profile_subjects.get(item["target_symbol_ref"])
        if step is None or step.get("role") != item["operation_role"]: failures.append(f"WRONG_OPERATION_ROLE:{item['operation_binding_id']}")
        if slot is None or slot.get("slot_kind") != "OPERATION": failures.append(f"UNRESOLVED_OPERATION_SLOT:{item['operation_binding_id']}")
        if receiver is None: failures.append(f"WRONG_RECEIVER:{item['operation_binding_id']}")
        elif step is not None and receiver.get("contract_object_ref") != step.get("target_ref"): failures.append(f"RECEIVER_CONTRACT_TARGET_MISMATCH:{item['operation_binding_id']}")
        if symbol is None or symbol.get("subject_kind") not in {"API", "WRAPPER", "INTERFACE"}: failures.append(f"UNKNOWN_TARGET_SYMBOL:{item['operation_binding_id']}")
        if not set(item["argument_binding_refs"]).issubset(inputs): failures.append(f"DANGLING_ARGUMENT:{item['operation_binding_id']}")
        participant_universe = set(subjects) | inputs
        if not set(item["participant_binding_refs"]).issubset(participant_universe): failures.append(f"DANGLING_PARTICIPANT:{item['operation_binding_id']}")
    if failures:
        return _check(ValidatorType.OPERATION_BINDING, CheckResult.FAIL, "OPERATION_BINDING_MISMATCH", refs=failures)
    refs = _all_refs(items); state, facts, evidence, missing = _fact_state(refs, ctx)
    return _check(ValidatorType.OPERATION_BINDING, state, "OPERATION_BINDINGS_VERIFIED" if state is CheckResult.PASS else "OPERATION_EVIDENCE_INCOMPLETE", facts=facts, evidence=evidence, missing=missing)


def _input(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    items = binding.get("input_bindings", []); operations = {x["operation_binding_id"]: x for x in binding.get("operation_bindings", [])}; ops = set(operations); slots = {x["slot_ref"]: x for x in ctx.template_manifest.get("slots", [])}
    facts = _facts(ctx)
    failures: list[str] = []
    for x in items:
        if x["target_operation_binding_ref"] not in ops or slots.get(x["template_input_slot_ref"], {}).get("slot_kind") not in {"INPUT", "INTERVENTION"}:
            failures.append(f"BAD_INPUT_REF:{x['input_binding_id']}")
        if not x["target_parameter_ref"].startswith("parameter:"):
            failures.append(f"UNKNOWN_PARAMETER:{x['input_binding_id']}")
        operation = operations.get(x["target_operation_binding_ref"])
        if operation is not None and x["input_binding_id"] not in operation["argument_binding_refs"]:
            failures.append(f"PARAMETER_NOT_BOUND_TO_OPERATION:{x['input_binding_id']}")
        if "direction=IN" not in x["type_constraints"]:
            failures.append(f"PARAMETER_DIRECTION_UNVERIFIED:{x['input_binding_id']}")
        if x["representation_kind"] not in {"DIRECT_VALUE", "ARTIFACT_REF", "ENCODED_BYTES"}:
            failures.append(f"WRONG_REPRESENTATION:{x['input_binding_id']}")
        if x["representation_kind"] == "ARTIFACT_REF" and not x.get("artifact_ref"):
            failures.append(f"MISSING_INPUT_ARTIFACT:{x['input_binding_id']}")
        compatible = [facts.get(ref) for ref in x["verified_fact_refs"]]
        object_facts = [fact for fact in compatible if fact and fact.get("fact_type") == "object_role"]
        if object_facts and not any(fact["parameters"].get("role") == x["input_role"] and fact["parameters"].get("value_type") == x["value_type"] for fact in object_facts):
            failures.append(f"INPUT_TYPE_ROLE_MISMATCH:{x['input_binding_id']}")
    if failures: return _check(ValidatorType.INPUT_BINDING, CheckResult.FAIL, "INPUT_BINDING_MISMATCH", refs=failures)
    refs = _all_refs(items); state, facts, evidence, missing = _fact_state(refs, ctx)
    return _check(ValidatorType.INPUT_BINDING, state, "INPUT_BINDINGS_VERIFIED" if state is CheckResult.PASS else "INPUT_EVIDENCE_INCOMPLETE", facts=facts, evidence=evidence, missing=missing)


def _intervention(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    items = binding.get("intervention_bindings", []); actions = {x["action_id"]: x for x in ctx.contract.get("intervention", {}).get("actions", [])}; slots = {x["slot_ref"]: x for x in ctx.template_manifest.get("slots", [])}; ops = {x["operation_binding_id"] for x in binding.get("operation_bindings", [])}; subjects = {x["subject_binding_id"] for x in binding.get("subject_bindings", [])}; parameters = {x["target_parameter_ref"] for x in binding.get("input_bindings", [])}
    failures: list[str] = []
    if {x["contract_intervention_ref"] for x in items} != set(actions): failures.append("CONTRACT_INTERVENTION_COVERAGE")
    for x in items:
        action = actions.get(x["contract_intervention_ref"])
        if action is None or action.get("kind") != x["intervention_kind"]: failures.append(f"WRONG_INTERVENTION_KIND:{x['intervention_binding_id']}")
        if slots.get(x["template_intervention_ref"], {}).get("slot_kind") not in {"INTERVENTION", "INPUT", "STATE_ANCHOR"}: failures.append(f"UNRESOLVED_INTERVENTION_SLOT:{x['intervention_binding_id']}")
        if x["target_operation_binding_ref"] not in ops or x["target_subject_binding_ref"] not in subjects: failures.append(f"WRONG_INTERVENTION_TARGET:{x['intervention_binding_id']}")
        if x.get("target_parameter_ref") is not None and x["target_parameter_ref"] not in parameters:
            failures.append(f"UNKNOWN_INTERVENTION_PARAMETER:{x['intervention_binding_id']}")
        expected_phase = {"append_input_tail": "BEFORE_OPERATION", "set_invalid_parameter": "AT_OPERATION", "state_reuse_sequence": "FOLLOWUP_SEQUENCE"}.get(x["intervention_kind"])
        if expected_phase is not None and x["application_phase"] != expected_phase:
            failures.append(f"WRONG_INTERVENTION_PHASE:{x['intervention_binding_id']}")
    if failures: return _check(ValidatorType.INTERVENTION_BINDING, CheckResult.FAIL, "INTERVENTION_BINDING_MISMATCH", refs=failures)
    refs = _all_refs(items, "equivalence_fact_refs"); state, facts, evidence, missing = _fact_state(refs, ctx)
    return _check(ValidatorType.INTERVENTION_BINDING, state, "INTERVENTIONS_VERIFIED" if state is CheckResult.PASS else "INTERVENTION_EVIDENCE_INCOMPLETE", facts=facts, evidence=evidence, missing=missing)


def _continuity(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    items = binding.get("continuity_bindings", []); subjects = {x["subject_binding_id"]: x for x in binding.get("subject_bindings", [])}; ops = {x["operation_binding_id"] for x in binding.get("operation_bindings", [])}; obs = {x["observation_binding_id"] for x in binding.get("observation_bindings", [])}; interventions = {x["intervention_binding_id"] for x in binding.get("intervention_bindings", [])}; failures: list[str] = []
    for x in items:
        selected = [subjects.get(ref) for ref in x["subject_binding_refs"]]
        identities = {y["identity_group_ref"] for y in selected if y}
        if any(y is None for y in selected) or len(identities) > 1: failures.append(f"IDENTITY_CHAIN:{x['continuity_binding_id']}")
        if not set(x["operation_binding_refs"]).issubset(ops) or not set(x["observation_binding_refs"]).issubset(obs) or not set(x["intervention_binding_refs"]).issubset(interventions): failures.append(f"DANGLING_CONTINUITY_REF:{x['continuity_binding_id']}")
    if failures: return _check(ValidatorType.CONTINUITY, CheckResult.FAIL, "CONTINUITY_VIOLATION", refs=failures)
    refs = _all_refs(items); state, facts, evidence, missing = _fact_state(refs, ctx)
    return _check(ValidatorType.CONTINUITY, state, "CONTINUITY_VERIFIED" if state is CheckResult.PASS else "CONTINUITY_EVIDENCE_INCOMPLETE", facts=facts, evidence=evidence, missing=missing)


_ACQ_BY_ROLE = {"operation_outcome": {"RETURN_VALUE", "OUT_PARAMETER", "BOUND_VALUE"}, "consumed_length": {"BOUND_VALUE", "OUT_PARAMETER", "POINTER_DELTA"}, "input_length": {"BOUND_VALUE", "OUT_PARAMETER"}, "output_length": {"OUT_PARAMETER", "BOUND_VALUE", "OBJECT_ACCESSOR"}, "object_state": {"OBJECT_ACCESSOR", "STATE_PROBE", "BUFFER_SNAPSHOT"}, "fatal_event": {"PROCESS_EVENT"}}
_PHASE_MAP = {"before_step": "BEFORE_STEP", "after_step": "AFTER_STEP", "between_steps": "BETWEEN_STEPS", "process_end": "PROCESS_END"}


def _observability(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    items = binding.get("observation_bindings", []); observables = {x["observable_id"]: x for x in ctx.contract.get("observable_evidence", {}).get("observables", [])}; profile_facts = _facts(ctx); subjects = {x["subject_binding_id"] for x in binding.get("subject_bindings", [])}; ops = {x["operation_binding_id"] for x in binding.get("operation_bindings", [])}; corr = {x["correlation_binding_id"] for x in binding.get("correlation_bindings", [])}; failures: list[str] = []
    if {x["contract_observable_ref"] for x in items} != set(observables): failures.append("CONTRACT_OBSERVABLE_COVERAGE")
    for x in items:
        observable = observables.get(x["contract_observable_ref"])
        if observable is None: continue
        if x["observable_role"] != observable["semantic_role"] or x["value_type"] != observable["value_type"]: failures.append(f"WRONG_OBSERVABLE_ROLE:{x['observation_binding_id']}")
        if x["acquisition_kind"] not in _ACQ_BY_ROLE.get(x["observable_role"], set()): failures.append(f"WRONG_ACQUISITION:{x['observation_binding_id']}")
        if x["phase"] != _PHASE_MAP.get(observable["source"]["phase"]): failures.append(f"WRONG_OBSERVATION_PHASE:{x['observation_binding_id']}")
        if x["target_subject_binding_ref"] not in subjects or x["target_operation_binding_ref"] not in ops: failures.append(f"WRONG_OBSERVATION_TARGET:{x['observation_binding_id']}")
        if not set(x["correlation_group_refs"]).issubset(corr): failures.append(f"BROKEN_CORRELATION:{x['observation_binding_id']}")
        channel_refs = [ref for ref in x["verified_fact_refs"] if profile_facts.get(ref, {}).get("fact_type") == "observable_channel" and profile_facts[ref].get("parameters", {}).get("observable_ref") == x["contract_observable_ref"] and profile_facts[ref].get("subject_ref") == x["semantic_source_ref"]]
        if not channel_refs: failures.append(f"MISSING_OBSERVABLE_CHANNEL_FACT:{x['observation_binding_id']}")
    observation_ids = {x["observation_binding_id"] for x in items}
    subject_ids = {x["subject_binding_id"] for x in binding.get("subject_bindings", [])}
    operation_ids = {x["operation_binding_id"] for x in binding.get("operation_bindings", [])}
    intervention_ids = {x["intervention_binding_id"] for x in binding.get("intervention_bindings", [])}
    for item in binding.get("correlation_bindings", []):
        if not set(item["observation_binding_refs"]).issubset(observation_ids) or not set(item["subject_binding_refs"]).issubset(subject_ids) or not set(item["operation_binding_refs"]).issubset(operation_ids) or not set(item["intervention_binding_refs"]).issubset(intervention_ids):
            failures.append(f"BROKEN_CORRELATION_OBJECT:{item['correlation_binding_id']}")
    if failures: return _check(ValidatorType.OBSERVABILITY, CheckResult.FAIL, "OBSERVABILITY_MISMATCH", refs=failures)
    refs = _all_refs(items) + _all_refs(binding.get("correlation_bindings", [])); state, facts, evidence, missing = _fact_state(refs, ctx)
    return _check(ValidatorType.OBSERVABILITY, state, "OBSERVABILITY_VERIFIED" if state is CheckResult.PASS else "OBSERVABILITY_EVIDENCE_INCOMPLETE", facts=facts, evidence=evidence, missing=missing)


def _completeness(binding: Mapping[str, Any], ctx: ValidationContext) -> dict[str, Any]:
    schema_errors = validate_candidate_binding(binding)
    slot_ids = {x["slot_ref"] for x in ctx.template_manifest.get("slots", [])}
    used_slots = {x["template_call_slot_ref"] for x in binding.get("operation_bindings", [])} | {x["template_input_slot_ref"] for x in binding.get("input_bindings", [])} | {x["template_intervention_ref"] for x in binding.get("intervention_bindings", [])} | {x["template_observation_ref"] for x in binding.get("observation_bindings", [])} | {ref for x in binding.get("subject_bindings", []) for ref in x["template_object_slot_refs"]}
    required = {x["slot_ref"] for x in ctx.template_manifest.get("slots", []) if x.get("required")}
    failures = list(schema_errors)
    if not used_slots.issubset(slot_ids): failures.append("UNRESOLVED_STABLE_SLOT")
    missing_slots = required - used_slots
    if missing_slots: failures.extend(f"MISSING_REQUIRED_TEMPLATE_SLOT:{x}" for x in sorted(missing_slots))
    usage: dict[str, int] = {slot: 0 for slot in slot_ids}
    for slot in used_slots:
        usage[slot] = usage.get(slot, 0) + 1
    slot_occurrences = [x["template_call_slot_ref"] for x in binding.get("operation_bindings", [])] + [x["template_input_slot_ref"] for x in binding.get("input_bindings", [])] + [x["template_intervention_ref"] for x in binding.get("intervention_bindings", [])] + [x["template_observation_ref"] for x in binding.get("observation_bindings", [])] + [ref for x in binding.get("subject_bindings", []) for ref in x["template_object_slot_refs"]]
    occurrence_counts = {slot: slot_occurrences.count(slot) for slot in slot_ids}
    for slot in ctx.template_manifest.get("slots", []):
        count = occurrence_counts[slot["slot_ref"]]
        if slot["multiplicity"] in {"ONE", "ZERO_OR_ONE"} and count > 1:
            failures.append(f"SLOT_MULTIPLICITY_EXCEEDED:{slot['slot_ref']}")
        if slot["multiplicity"] in {"ONE", "ONE_OR_MORE"} and slot.get("required") and count < 1:
            failures.append(f"SLOT_MULTIPLICITY_UNDERFLOW:{slot['slot_ref']}")
    if failures: return _check(ValidatorType.COMPLETENESS, CheckResult.FAIL, "BINDING_INCOMPLETE_OR_DANGLING", missing=failures)
    refs = binding.get("construction", {}).get("verified_fact_refs", []); state, facts, evidence, missing = _fact_state(refs, ctx)
    return _check(ValidatorType.COMPLETENESS, state, "BINDING_COMPLETE" if state is CheckResult.PASS else "COMPLETENESS_EVIDENCE_INCOMPLETE", facts=facts, evidence=evidence, missing=missing)


VALIDATOR_REGISTRY: dict[ValidatorType, Callable[[Mapping[str, Any], ValidationContext], dict[str, Any]]] = {
    ValidatorType.REFERENCE_INTEGRITY: _reference, ValidatorType.TARGET_SCOPE: _target_scope,
    ValidatorType.ELIGIBILITY_GATE: _eligibility, ValidatorType.SUBJECT_BINDING: _subject,
    ValidatorType.OPERATION_BINDING: _operation, ValidatorType.INPUT_BINDING: _input,
    ValidatorType.INTERVENTION_BINDING: _intervention, ValidatorType.CONTINUITY: _continuity,
    ValidatorType.OBSERVABILITY: _observability, ValidatorType.COMPLETENESS: _completeness,
}

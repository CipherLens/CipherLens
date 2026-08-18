from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from candidate_binding.construct import construct_candidate_binding
from candidate_binding.model import ValidationContext
from candidate_binding.registry import validate_with_registry
from tests.transfer_signature.common import ROOT, derive_case, golden_profile
from transfer_signature.evaluate import evaluate_transfer_signature
from trigger_template_interface.manifest import adapt_normalized_template


CASE_TEMPLATES = {
    "mbedtls_poc_0020": "normalized_templates/rsa/rsa_der_trailing_garbage",
    "mbedtls_poc_0004": "normalized_templates/cipher/cipher_pkcs_padding_outlen_underflow",
    "mbedtls_poc_0005": "normalized_templates/asn1/asn1_store_named_data_zero_len_stale_state",
}


def case_context(name: str) -> ValidationContext:
    signature, contract, _ = derive_case(name)
    profile = golden_profile(name, "eligible")
    evaluation = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
    manifest = adapt_normalized_template(ROOT / CASE_TEMPLATES[name], repo_root=ROOT)
    return ValidationContext(contract, signature, manifest, profile, evaluation)


def valid_case(name: str) -> tuple[dict[str, Any], ValidationContext, dict[str, Any]]:
    ctx = case_context(name)
    binding = construct_candidate_binding(
        contract=ctx.contract,
        transfer_signature=ctx.transfer_signature,
        template_manifest=ctx.template_manifest,
        target_profile=ctx.target_profile,
        eligibility_evaluation=ctx.eligibility_evaluation,
        mappings=_mappings(name, ctx),
    )
    validation = validate_with_registry(binding, ctx)
    return binding, ctx, validation


def rebuild(binding: Mapping[str, Any]) -> dict[str, Any]:
    from candidate_binding.canonical import expected_binding_id

    result = deepcopy(dict(binding))
    result["binding_id"] = expected_binding_id(result)
    return result


def _mappings(name: str, ctx: ValidationContext) -> dict[str, Any]:
    contract = ctx.contract
    profile = ctx.target_profile
    facts = profile["facts"]
    evidence_refs = sorted({ref for fact in facts for ref in fact["evidence_refs"]})
    object_facts = [fact for fact in facts if fact["fact_type"] == "object_role" and fact["assertion"] == "TRUE"]
    operation_facts = [fact for fact in facts if fact["fact_type"] == "operation_role" and fact["assertion"] == "TRUE"]
    channel_facts = [fact for fact in facts if fact["fact_type"] == "observable_channel" and fact["assertion"] == "TRUE"]
    intervention_facts = [fact for fact in facts if fact["fact_type"] == "equivalent_intervention" and fact["assertion"] == "TRUE"]
    continuity_facts = [fact for fact in facts if fact["fact_type"] == "execution_shape" and fact["assertion"] == "TRUE"]
    correlation_facts = [fact for fact in facts if fact["fact_type"] == "observable_correlation" and fact["assertion"] == "TRUE"]
    profile_subjects = {x["subject_ref"]: x for x in profile["subjects"]}
    evidence_for = lambda fact: list(fact["evidence_refs"])

    subject_bindings: list[dict[str, Any]] = []
    subject_by_object: dict[str, str] = {}
    for index, obj in enumerate(contract["context"]["objects"]):
        fact = next(x for x in object_facts if x["parameters"]["role"] == obj["semantic_role"] and x["parameters"]["value_type"] == obj["value_type"])
        subject = profile_subjects[fact["subject_ref"]]
        binding_id = f"SUBJECT_{index}_{obj['object_id']}"
        subject_by_object[obj["object_id"]] = binding_id
        subject_bindings.append({
            "subject_binding_id": binding_id, "contract_object_ref": obj["object_id"],
            "template_object_slot_refs": [], "target_subject_ref": fact["subject_ref"],
            "subject_kind": subject["subject_kind"], "semantic_role": obj["semantic_role"],
            "target_type_ref": f"type:{obj['value_type']}", "identity_group_ref": f"identity:{obj['object_id'].lower()}",
            "ownership": "CALLER_OWNED", "lifetime": "candidate-run",
            "verified_fact_refs": [fact["fact_id"]], "evidence_refs": evidence_for(fact),
        })
    channel_subject_by_ref: dict[str, str] = {}
    for index, fact in enumerate(channel_facts):
        channel_ref = fact["subject_ref"]
        if channel_ref in channel_subject_by_ref:
            continue
        subject = profile_subjects[channel_ref]
        role = subject["semantic_roles"][0]
        obj = next((x for x in contract["context"]["objects"] if x["semantic_role"] == role), contract["context"]["objects"][0])
        binding_id = f"SUBJECT_CHANNEL_{index}"
        channel_subject_by_ref[channel_ref] = binding_id
        subject_bindings.append({
            "subject_binding_id": binding_id, "contract_object_ref": obj["object_id"],
            "template_object_slot_refs": [], "target_subject_ref": channel_ref,
            "subject_kind": subject["subject_kind"], "semantic_role": obj["semantic_role"],
            "target_type_ref": "type:observation-channel", "identity_group_ref": f"identity:{obj['object_id'].lower()}",
            "ownership": "BORROWED", "lifetime": "candidate-run",
            "verified_fact_refs": [fact["fact_id"]], "evidence_refs": evidence_for(fact),
        })

    operation_slots = [x for x in ctx.template_manifest["slots"] if x["slot_kind"] == "OPERATION"]
    steps = contract["execution"]["steps"]
    operation_bindings: list[dict[str, Any]] = []
    primary_by_step: dict[str, str] = {}
    for index, slot in enumerate(operation_slots):
        step = steps[index] if index < len(steps) else steps[-1]
        fact = next(x for x in operation_facts if x["parameters"]["role"] == step["role"])
        op_id = f"OPERATION_{index}_{step['step_id']}"
        if step["step_id"] not in primary_by_step:
            primary_by_step[step["step_id"]] = op_id
            kind = "PRIMARY_CONTRACT_STEP"
        else:
            kind = "SUPPORTING_SETUP"
        receiver = subject_by_object[step["target_ref"]]
        operation_bindings.append({
            "operation_binding_id": op_id, "binding_kind": kind, "contract_step_ref": step["step_id"],
            "template_call_slot_ref": slot["slot_ref"], "operation_role": step["role"],
            "target_operation_kind": "API_CALL", "target_symbol_ref": fact["subject_ref"],
            "receiver_subject_binding_ref": receiver, "argument_binding_refs": [],
            "participant_binding_refs": [receiver], "sequence_index": index,
            "verified_fact_refs": [fact["fact_id"]], "evidence_refs": evidence_for(fact),
        })

    input_slots = [x for x in ctx.template_manifest["slots"] if x["slot_kind"] == "INPUT"]
    object_fact = object_facts[0]
    first_step = steps[0]
    source_inputs = list(first_step.get("input_refs", [])) or [contract["context"]["objects"][0]["object_id"]]
    input_bindings = [{
        "input_binding_id": f"INPUT_{index}", "source_input_ref": source_inputs[index % len(source_inputs)],
        "template_input_slot_ref": slot["slot_ref"], "target_operation_binding_ref": primary_by_step[first_step["step_id"]],
        "target_parameter_ref": f"parameter:{index}", "input_role": object_fact["parameters"]["role"],
        "value_type": object_fact["parameters"]["value_type"], "representation_kind": "DIRECT_VALUE",
        "encoding": "NATIVE", "construction_strategy_ref": "strategy:fixture-explicit",
        "artifact_ref": None, "type_constraints": ["direction=IN", f"value_type={object_fact['parameters']['value_type']}"],
        "size_range": {"minimum": 0, "maximum": None}, "ownership": "CALLER_OWNED",
        "verified_fact_refs": [object_fact["fact_id"]], "evidence_refs": evidence_for(object_fact),
    } for index, slot in enumerate(input_slots)]
    inputs_by_operation: dict[str, list[str]] = {}
    for item in input_bindings:
        inputs_by_operation.setdefault(item["target_operation_binding_ref"], []).append(item["input_binding_id"])
    for operation in operation_bindings:
        operation["argument_binding_refs"] = sorted(inputs_by_operation.get(operation["operation_binding_id"], []))

    intervention_slots = [x for x in ctx.template_manifest["slots"] if x["slot_kind"] in {"INTERVENTION", "STATE_ANCHOR"}]
    if not intervention_slots:
        intervention_slots = input_slots[:1]
    actions = contract["intervention"]["actions"]
    intervention_bindings: list[dict[str, Any]] = []
    for index, slot in enumerate(intervention_slots):
        action = actions[index] if index < len(actions) else actions[-1]
        fact = next(x for x in intervention_facts if x["parameters"]["kind"] == action["kind"])
        target_subject = subject_by_object[action["target_ref"]]
        operation_id = primary_by_step[steps[min(index, len(steps) - 1)]["step_id"]]
        phase = {"mbedtls_poc_0020": "BEFORE_OPERATION", "mbedtls_poc_0004": "AT_OPERATION", "mbedtls_poc_0005": "FOLLOWUP_SEQUENCE"}[name]
        intervention_bindings.append({
            "intervention_binding_id": f"INTERVENTION_{index}", "contract_intervention_ref": action["action_id"],
            "template_intervention_ref": slot["slot_ref"], "target_subject_binding_ref": target_subject,
            "target_operation_binding_ref": operation_id,
            "target_parameter_ref": input_bindings[0]["target_parameter_ref"] if input_bindings else None,
            "target_state_ref": None, "intervention_kind": action["kind"], "application_phase": phase,
            "equivalence_fact_refs": [fact["fact_id"]], "evidence_refs": evidence_for(fact),
        })

    correlation_fact = correlation_facts[0]
    correlation_id = "CORRELATION_PRIMARY"
    correlation_kind = {"same_run": "SAME_RUN", "same_step": "SAME_STEP", "same_subject": "SAME_SUBJECT"}[correlation_fact["parameters"]["correlation_scope"]]
    observation_slots = [x for x in ctx.template_manifest["slots"] if x["slot_kind"] == "OBSERVATION"]
    observables = contract["observable_evidence"]["observables"]
    observation_count = max(len(observation_slots), len(observables))
    observation_bindings: list[dict[str, Any]] = []
    for index in range(observation_count):
        observable = observables[index % len(observables)]
        slot = observation_slots[index % len(observation_slots)]
        fact = next(x for x in channel_facts if x["parameters"]["observable_ref"] == observable["observable_id"])
        operation_id = primary_by_step.get(observable["source"].get("step_ref"), operation_bindings[-1]["operation_binding_id"])
        acquisition = {"operation_outcome": "RETURN_VALUE", "consumed_length": "POINTER_DELTA", "input_length": "BOUND_VALUE", "output_length": "OUT_PARAMETER", "object_state": "STATE_PROBE", "fatal_event": "PROCESS_EVENT"}[observable["semantic_role"]]
        phase = {"before_step": "BEFORE_STEP", "after_step": "AFTER_STEP", "between_steps": "BETWEEN_STEPS", "process_end": "PROCESS_END"}[observable["source"]["phase"]]
        observation_bindings.append({
            "observation_binding_id": f"OBSERVATION_{index}_{observable['observable_id']}",
            "contract_observable_ref": observable["observable_id"], "template_observation_ref": slot["slot_ref"],
            "target_subject_binding_ref": channel_subject_by_ref[fact["subject_ref"]],
            "target_operation_binding_ref": operation_id, "observable_role": observable["semantic_role"],
            "value_type": observable["value_type"], "acquisition_kind": acquisition, "phase": phase,
            "semantic_source_ref": fact["subject_ref"], "correlation_group_refs": [correlation_id],
            "participant_binding_refs": [channel_subject_by_ref[fact["subject_ref"]]],
            "verified_fact_refs": [fact["fact_id"]], "evidence_refs": evidence_for(fact),
        })
    correlation_bindings = [{
        "correlation_binding_id": correlation_id, "correlation_kind": correlation_kind,
        "subject_binding_refs": sorted(channel_subject_by_ref.values()),
        "operation_binding_refs": [x["operation_binding_id"] for x in operation_bindings],
        "intervention_binding_refs": [x["intervention_binding_id"] for x in intervention_bindings],
        "observation_binding_refs": [x["observation_binding_id"] for x in observation_bindings],
        "participant_binding_refs": sorted(channel_subject_by_ref.values()),
        "verified_fact_refs": [correlation_fact["fact_id"]], "evidence_refs": evidence_for(correlation_fact),
    }]
    continuity_fact = continuity_facts[0]
    receiver_ids = sorted({x["receiver_subject_binding_ref"] for x in operation_bindings})
    continuity_bindings = [{
        "continuity_binding_id": "CONTINUITY_PRIMARY",
        "continuity_kind": {"mbedtls_poc_0020": "SAME_IDENTITY_ACROSS_OPERATIONS", "mbedtls_poc_0004": "BEFORE_AFTER_SAME_IDENTITY", "mbedtls_poc_0005": "REUSE_AFTER_INTERVENTION"}[name],
        "subject_binding_refs": receiver_ids, "operation_binding_refs": [x["operation_binding_id"] for x in operation_bindings],
        "intervention_binding_refs": [x["intervention_binding_id"] for x in intervention_bindings],
        "observation_binding_refs": [x["observation_binding_id"] for x in observation_bindings],
        "verified_fact_refs": [continuity_fact["fact_id"]], "evidence_refs": evidence_for(continuity_fact),
    }]
    return {
        "subject_bindings": subject_bindings, "operation_bindings": operation_bindings,
        "input_bindings": input_bindings, "intervention_bindings": intervention_bindings,
        "continuity_bindings": continuity_bindings, "observation_bindings": observation_bindings,
        "correlation_bindings": correlation_bindings,
        "verified_fact_refs": [x["fact_id"] for x in facts], "evidence_refs": evidence_refs,
    }

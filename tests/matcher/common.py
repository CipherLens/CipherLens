from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from typing import Any, Mapping

import yaml

from binding_proposal.config import ProviderConfig
from binding_proposal.model import PAYLOAD_SCHEMA_VERSION, ProviderKind
from binding_proposal.providers.replay import ReplayProposalProvider
from binding_proposal.router import ProviderRouter
from matcher.knowledge import EvidenceItem, KnowledgeSeed, SyntheticKnowledgeBackend
from matcher.model import EvidenceClass, MatcherBudgets, TargetScope
from matcher.orchestrate import MatcherRequest
from matcher.proposal import ProposalOrchestrator
from tests.transfer_signature.common import derive_case
from trigger_template_interface.manifest import adapt_normalized_template


ROOT = Path(__file__).resolve().parents[2]
CASES = ("mbedtls_poc_0020", "mbedtls_poc_0004", "mbedtls_poc_0005")
CASE_TEMPLATES = {
    "mbedtls_poc_0020": "normalized_templates/rsa/rsa_der_trailing_garbage",
    "mbedtls_poc_0004": "normalized_templates/cipher/cipher_pkcs_padding_outlen_underflow",
    "mbedtls_poc_0005": "normalized_templates/asn1/asn1_store_named_data_zero_len_stale_state",
}


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def golden_profile(name: str, label: str = "eligible") -> dict[str, Any]:
    return load_yaml(
        ROOT / "tests" / "transfer_signature" / "fixtures" / "golden" / name / f"{label}.profile.yaml"
    )


def valid_binding(name: str) -> dict[str, Any]:
    return load_yaml(
        ROOT / "tests" / "candidate_binding" / "fixtures" / "golden" / name / "valid.binding.yaml"
    )


def binding_mappings(binding: Mapping[str, Any]) -> dict[str, Any]:
    names = (
        "subject_bindings", "operation_bindings", "input_bindings",
        "intervention_bindings", "continuity_bindings",
        "observation_bindings", "correlation_bindings",
    )
    return {
        **{name: deepcopy(binding[name]) for name in names},
        "verified_fact_refs": deepcopy(binding["construction"]["verified_fact_refs"]),
        "evidence_refs": deepcopy(binding["construction"]["evidence_refs"]),
    }


def payload_from_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": PAYLOAD_SCHEMA_VERSION,
        "role_proposals": [],
        "subject_proposals": [],
        "operation_proposals": [],
        "input_proposals": [],
        "intervention_proposals": [],
        "state_continuity_proposals": [],
        "observation_proposals": [],
        "advisory_rationale": "Replay-only role proposal; deterministic evidence remains required.",
    }
    destination = {
        "object_role": "subject_proposals",
        "operation_role": "operation_proposals",
        "equivalent_intervention": "intervention_proposals",
        "execution_shape": "state_continuity_proposals",
        "observable_channel": "observation_proposals",
        "observable_correlation": "observation_proposals",
        "precondition_shape": "role_proposals",
        "complete_input_enforcement": "role_proposals",
        "failure_output_transactionality": "role_proposals",
        "atomic_clear_semantics": "role_proposals",
        "terminalization_after_operation": "role_proposals",
    }
    evidence_ref = str(profile["evidence"][0]["evidence_id"])
    for fact in profile["facts"]:
        fact_type = str(fact["fact_type"])
        source_ref = str(fact["fact_id"])
        related_refs: list[str] = []
        if fact_type == "observable_channel":
            source_ref = str(fact["parameters"]["observable_ref"])
            related_refs = [
                str(fact["fact_id"]),
                "operation:" + str(fact["parameters"]["operation_role"]),
            ]
        payload[destination[fact_type]].append(
            {
                "proposal_ref": "proposal-item:" + str(fact["fact_id"]).lower(),
                "source_ref": source_ref,
                "target_ref": str(fact["subject_ref"]),
                "semantic_role": fact_type,
                "related_refs": related_refs,
                "evidence_hints": [evidence_ref],
            }
        )
    return payload


def case_request(
    name: str,
    *,
    profile_label: str = "eligible",
    payload: Mapping[str, Any] | str | None = None,
    budgets: MatcherBudgets | None = None,
    seed_updates: Mapping[str, Any] | None = None,
    extra_evidence: tuple[EvidenceItem, ...] = (),
    evidence_class: EvidenceClass = EvidenceClass.FIXTURE,
    profile_override: Mapping[str, Any] | None = None,
    binding_label: str = "valid",
) -> tuple[MatcherRequest, ReplayProposalProvider, SyntheticKnowledgeBackend]:
    signature, contract, _ = derive_case(name)
    profile = deepcopy(dict(profile_override or golden_profile(name, profile_label)))
    manifest = adapt_normalized_template(ROOT / CASE_TEMPLATES[name], repo_root=ROOT)
    scope = TargetScope(**profile["target_scope"])
    profile_evidence = profile["evidence"][0]
    evidence = EvidenceItem(
        evidence_ref=str(profile_evidence["evidence_id"]),
        source_type=evidence_class,
        target_scope=scope,
        subject_refs=tuple(sorted(x["subject_ref"] for x in profile["subjects"])),
        symbol_refs=tuple(
            sorted(
                x["subject_ref"]
                for x in profile["subjects"]
                if x["subject_kind"] in {"API", "API_GROUP", "CALL_SURFACE", "OBJECT_MODEL"}
            )
        ),
        artifact_ref=str(profile_evidence["path"]),
        artifact_digest=str(profile_evidence["sha256"]),
        initial_epistemic_status="HYPOTHESIS",
        fact_payloads=tuple(deepcopy(profile["facts"])),
        retrieval_provenance={"backend": "synthetic", "fixture": name},
    )
    composition = {
        "family": contract["contract_family"],
        "assignments": [{"fixture_family": name}],
        "adaptation_complexity": 1,
        "legacy_affinity": 5,
        "_binding_mappings": binding_mappings(
            load_yaml(
                ROOT / "tests" / "candidate_binding" / "fixtures" / "golden" /
                name / f"{binding_label}.binding.yaml"
            )
        ),
    }
    composition.update(deepcopy(dict(seed_updates or {})))
    seed = KnowledgeSeed(
        entity_ref=f"seed:{name}",
        entity_kind="STATEFUL_OPERATION_FAMILY" if name == "mbedtls_poc_0005" else "API_GROUP",
        target_scope=scope,
        subject_refs=tuple(sorted(x["subject_ref"] for x in profile["subjects"])),
        symbol_refs=evidence.symbol_refs,
        evidence_refs=(evidence.evidence_ref,),
        surface_composition=composition,
        surface_relations=tuple(
            {"kind": "SAME_SURFACE", "subject_ref": x["subject_ref"]}
            for x in profile["subjects"]
        ),
        score=0.99,
        metadata={
            "compatibility_group": scope.surface_ref,
            "assembly_reasons": ["FIXTURE_EXPLICIT_RELATION"],
        },
    )
    subjects = {str(x["subject_ref"]): deepcopy(x) for x in profile["subjects"]}
    backend = SyntheticKnowledgeBackend(
        seeds=(seed,), evidence=(evidence, *extra_evidence), subjects=subjects
    )
    replay = ReplayProposalProvider(payload or payload_from_profile(profile))
    config = ProviderConfig(provider=ProviderKind.TEST_REPLAY)
    proposal_orchestrator = ProposalOrchestrator(
        provider=replay,
        router=ProviderRouter(replay, config=config),
    )
    request = MatcherRequest(
        contract=contract,
        transfer_signature=signature,
        template_manifest=manifest,
        target_scope=scope,
        knowledge=backend,
        proposal_orchestrator=proposal_orchestrator,
        repo_root=ROOT,
        budgets=budgets or MatcherBudgets(),
        family_metadata={"fixture_family": name},
        contract_artifact_ref=f"tests/contract_miner/fixtures/golden/{name}/expected.vc.yaml",
        transfer_signature_artifact_ref=f"tests/transfer_signature/fixtures/golden/{name}/expected.ts.yaml",
        template_artifact_ref=f"tests/candidate_binding/fixtures/golden/{name}/template_interface.manifest.yaml",
    )
    return request, replay, backend


def synthetic_digest() -> str:
    return hashlib.sha256(
        (ROOT / "tests/transfer_signature/fixtures/synthetic_target_evidence.md").read_bytes()
    ).hexdigest()

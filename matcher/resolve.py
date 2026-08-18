"""Deterministic proposal-claim resolution and immutable profile rounds."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from binding_proposal.validate import PROPOSAL_LISTS, validate_binding_proposal_or_raise
from matcher.knowledge import EvidenceItem, TargetKnowledgeBase, artifact_exists_and_matches
from matcher.model import (
    EvidenceClass,
    FactResolutionRecord,
    MatcherCandidate,
    TRUSTED_EVIDENCE_CLASSES,
    VerifierType,
    semantic_digest,
)
from transfer_signature.profile import profile_digest, validate_profile_or_raise
from transfer_signature.registry import FACT_PARAMETER_KEYS


VERIFIER_VERSION = "cipherlens.matcher_verifier_registry.v0.1"


class ProfileConflictError(ValueError):
    pass


@dataclass(frozen=True)
class VerificationResult:
    assertion: str
    epistemic_status: str
    reason_code: str
    missing_requirements: tuple[str, ...] = ()


Verifier = Callable[[Mapping[str, Any], EvidenceItem, MatcherCandidate, str | Path], VerificationResult]


class VerifierRegistry:
    """Closed, typed registry. Verifier types are not Profile fact types."""

    def __init__(self) -> None:
        self._registry: dict[VerifierType, Verifier] = {
            kind: _verify_exact_evidence for kind in VerifierType
        }

    def verify(
        self,
        verifier_type: VerifierType,
        fact: Mapping[str, Any],
        evidence: EvidenceItem,
        candidate: MatcherCandidate,
        repo_root: str | Path,
    ) -> VerificationResult:
        return self._registry[verifier_type](fact, evidence, candidate, repo_root)


@dataclass(frozen=True)
class ProfileRound:
    round_index: int
    profile: Mapping[str, Any]
    profile_digest: str
    derived_from_profile_ref: str | None
    resolution_records: tuple[FactResolutionRecord, ...]

    @property
    def profile_ref(self) -> str:
        return f"target-profile:{self.profile['profile_id']}"


class DeterministicResolver:
    def __init__(
        self,
        knowledge: TargetKnowledgeBase,
        *,
        repo_root: str | Path,
        registry: VerifierRegistry | None = None,
    ) -> None:
        self.knowledge = knowledge
        self.repo_root = Path(repo_root)
        self.registry = registry or VerifierRegistry()

    def resolve(
        self,
        *,
        candidate: MatcherCandidate,
        proposal: Mapping[str, Any],
        round_index: int,
        previous: ProfileRound | None = None,
        additional_evidence_refs: Sequence[str] = (),
    ) -> ProfileRound:
        validate_binding_proposal_or_raise(proposal)
        evidence_refs = set(candidate.evidence_refs)
        evidence_refs.update(additional_evidence_refs)
        evidence_refs.update(
            hint
            for list_name in PROPOSAL_LISTS
            for item in proposal.get(list_name, [])
            for hint in item.get("evidence_hints", [])
        )
        evidence_items = {
            ref: item
            for ref in sorted(evidence_refs)
            if (item := self.knowledge.get_evidence(ref)) is not None
        }

        records: list[FactResolutionRecord] = []
        seen_claims: set[tuple[str, str]] = set()
        for list_name in PROPOSAL_LISTS:
            for item in proposal.get(list_name, []):
                claim_source = str(item.get("source_ref", ""))
                target_ref = str(item.get("target_ref", ""))
                hints = sorted(
                    set(item.get("evidence_hints", []))
                    | set(additional_evidence_refs)
                )
                if not hints:
                    records.append(
                        _missing_record(candidate, proposal, item, list_name)
                    )
                    continue
                matched = False
                for evidence_ref in sorted(hints):
                    evidence = evidence_items.get(evidence_ref)
                    if evidence is None:
                        continue
                    for fact in evidence.fact_payloads:
                        claim_fact_refs = {claim_source, *map(str, item.get("related_refs", []))}
                        if str(fact.get("fact_id", "")) not in claim_fact_refs:
                            continue
                        if str(fact.get("subject_ref", "")) != target_ref:
                            continue
                        claim_key = (claim_source, evidence_ref)
                        if claim_key in seen_claims:
                            continue
                        seen_claims.add(claim_key)
                        matched = True
                        records.append(
                            self._resolve_fact(candidate, proposal, item, fact, evidence)
                        )
                if not matched:
                    records.append(
                        _missing_record(candidate, proposal, item, list_name)
                    )

        facts_by_id: dict[str, Mapping[str, Any]] = {}
        if previous is not None:
            facts_by_id.update(
                {str(fact["fact_id"]): deepcopy(dict(fact)) for fact in previous.profile["facts"]}
            )
            for item in previous.profile["evidence"]:
                evidence_ref = str(item["evidence_id"])
                if evidence_ref not in evidence_items:
                    existing = self.knowledge.get_evidence(evidence_ref)
                    if existing is not None:
                        evidence_items[evidence_ref] = existing
        for record in records:
            if record.fact is not None and record.resulting_fact_ref is not None:
                facts_by_id[record.resulting_fact_ref] = deepcopy(dict(record.fact))

        facts = sorted(facts_by_id.values(), key=lambda item: str(item["fact_id"]))
        if not facts:
            raise ValueError("PROFILE_FACTS_UNAVAILABLE")
        used_evidence = sorted(
            {
                ref
                for fact in facts
                for ref in fact.get("evidence_refs", [])
            }
        )
        missing_evidence = [ref for ref in used_evidence if ref not in evidence_items]
        if missing_evidence:
            raise ValueError(f"PROFILE_EVIDENCE_UNAVAILABLE:{missing_evidence!r}")
        subjects = []
        for subject_ref in sorted(
            {str(fact["subject_ref"]) for fact in facts}
            | {
                str(participant)
                for fact in facts
                for participant in fact.get("parameters", {}).get("participant_refs", [])
            }
        ):
            subject = self.knowledge.get_subject(subject_ref)
            if subject is None:
                raise ValueError(f"PROFILE_SUBJECT_UNAVAILABLE:{subject_ref}")
            subjects.append(deepcopy(dict(subject)))

        _reject_verified_conflicts(facts)
        semantic = {
            "target_scope": candidate.target_scope.to_dict(),
            "subjects": subjects,
            "facts": facts,
            "evidence": [
                evidence_items[ref].to_profile_evidence() for ref in used_evidence
            ],
        }
        profile_id = "MATCHER_PROFILE_" + semantic_digest(semantic)[:32].upper()
        profile = {
            "schema_version": "cipherlens.target_semantic_profile.v0.1",
            "profile_id": profile_id,
            **semantic,
        }
        validate_profile_or_raise(profile, repo_root=self.repo_root)
        digest = profile_digest(profile, repo_root=self.repo_root)
        return ProfileRound(
            round_index=round_index,
            profile=profile,
            profile_digest=digest,
            derived_from_profile_ref=(previous.profile_ref if previous else None),
            resolution_records=tuple(records),
        )

    def _resolve_fact(
        self,
        candidate: MatcherCandidate,
        proposal: Mapping[str, Any],
        proposal_item: Mapping[str, Any],
        raw_fact: Mapping[str, Any],
        evidence: EvidenceItem,
    ) -> FactResolutionRecord:
        fact_type = str(raw_fact.get("fact_type", ""))
        if fact_type not in FACT_PARAMETER_KEYS:
            return _rejected_record(
                candidate, proposal, proposal_item, raw_fact, evidence,
                "UNKNOWN_CANONICAL_FACT_TYPE",
            )
        verifier_type = _verifier_for_fact(fact_type, evidence.source_type)
        result = self.registry.verify(
            verifier_type, raw_fact, evidence, candidate, self.repo_root
        )
        fact = {
            "fact_id": str(raw_fact["fact_id"]),
            "subject_ref": str(raw_fact["subject_ref"]),
            "coverage": str(raw_fact["coverage"]),
            "fact_type": fact_type,
            "parameters": deepcopy(dict(raw_fact["parameters"])),
            "assertion": result.assertion,
            "epistemic_status": result.epistemic_status,
            "evidence_refs": [evidence.evidence_ref],
        }
        semantic = {
            "candidate_ref": candidate.candidate_id,
            "proposal_ref": proposal["proposal_id"],
            "claim_ref": proposal_item["proposal_ref"],
            "fact": fact,
            "verifier_type": verifier_type.value,
            "evidence_ref": evidence.evidence_ref,
            "reason_code": result.reason_code,
        }
        return FactResolutionRecord(
            record_id="fact-resolution:" + semantic_digest(semantic),
            candidate_ref=candidate.candidate_id,
            proposal_ref=str(proposal["proposal_id"]),
            claim_ref=str(proposal_item["proposal_ref"]),
            requested_fact_type=fact_type,
            target_subject_ref=str(raw_fact["subject_ref"]),
            verifier_type=verifier_type,
            verifier_version=VERIFIER_VERSION,
            input_evidence_refs=(evidence.evidence_ref,),
            input_evidence_digests=(evidence.artifact_digest,),
            assertion=result.assertion,
            resulting_epistemic_status=result.epistemic_status,
            resulting_fact_ref=str(raw_fact["fact_id"]),
            reason_code=result.reason_code,
            missing_requirements=result.missing_requirements,
            fact=fact,
        )


def _verify_exact_evidence(
    fact: Mapping[str, Any],
    evidence: EvidenceItem,
    candidate: MatcherCandidate,
    repo_root: str | Path,
) -> VerificationResult:
    assertion = str(fact.get("assertion", "UNKNOWN"))
    if evidence.target_scope.library != candidate.target_scope.library or evidence.target_scope.version != candidate.target_scope.version:
        return VerificationResult(
            assertion, "PROPOSED", "EVIDENCE_TARGET_VERSION_MISMATCH",
            ("EXACT_TARGET_VERSION",),
        )
    if evidence.target_scope.surface_ref != candidate.target_scope.surface_ref:
        return VerificationResult(
            assertion, "PROPOSED", "EVIDENCE_SURFACE_MISMATCH",
            ("COMPATIBLE_SURFACE",),
        )
    subject_ref = str(fact.get("subject_ref", ""))
    if subject_ref not in candidate.subject_refs or subject_ref not in evidence.subject_refs:
        return VerificationResult(
            assertion, "PROPOSED", "EVIDENCE_SUBJECT_MISMATCH",
            ("COMPATIBLE_SUBJECT",),
        )
    if not artifact_exists_and_matches(evidence, repo_root):
        return VerificationResult(
            assertion, "PROPOSED", "EVIDENCE_DIGEST_OR_PATH_INVALID",
            ("CONTENT_DIGEST", "REPO_ARTIFACT"),
        )
    if evidence.source_type not in TRUSTED_EVIDENCE_CLASSES:
        return VerificationResult(
            assertion, "INFERRED", "UNTRUSTED_EVIDENCE_CANNOT_VERIFY",
            ("DETERMINISTIC_EVIDENCE",),
        )
    return VerificationResult(assertion, "VERIFIED", "DETERMINISTIC_EVIDENCE_CONFIRMED")


def _verifier_for_fact(fact_type: str, source_type: EvidenceClass) -> VerifierType:
    if source_type is EvidenceClass.HEADER:
        return VerifierType.HEADER_CONFIRMATION
    if source_type is EvidenceClass.SOURCE:
        return VerifierType.SOURCE_CONFIRMATION
    return {
        "operation_role": VerifierType.SYMBOL_EXISTENCE,
        "object_role": VerifierType.SIGNATURE_TYPE,
        "precondition_shape": VerifierType.DOCUMENTED_CONTRACT,
        "equivalent_intervention": VerifierType.PARAMETER_ROLE,
        "execution_shape": VerifierType.STATE_CONTINUITY_CHECK,
        "observable_channel": VerifierType.OBSERVABLE_CHANNEL_CHECK,
        "observable_correlation": VerifierType.STATE_CONTINUITY_CHECK,
    }.get(fact_type, VerifierType.DOCUMENTED_CONTRACT)


def _reject_verified_conflicts(facts: Sequence[Mapping[str, Any]]) -> None:
    assertions: dict[tuple[str, str, str, str], set[str]] = {}
    import json

    for fact in facts:
        if fact.get("epistemic_status") != "VERIFIED":
            continue
        key = (
            str(fact.get("fact_type")),
            str(fact.get("subject_ref")),
            str(fact.get("coverage")),
            json.dumps(fact.get("parameters", {}), sort_keys=True, separators=(",", ":")),
        )
        assertions.setdefault(key, set()).add(str(fact.get("assertion")))
    if any({"TRUE", "FALSE"}.issubset(values) for values in assertions.values()):
        raise ProfileConflictError("PROFILE_VERIFIED_FACT_CONFLICT")


def _missing_record(
    candidate: MatcherCandidate,
    proposal: Mapping[str, Any],
    item: Mapping[str, Any],
    list_name: str,
) -> FactResolutionRecord:
    semantic = {
        "candidate_ref": candidate.candidate_id,
        "proposal_ref": proposal.get("proposal_id"),
        "claim_ref": item.get("proposal_ref"),
        "list_name": list_name,
        "reason": "DETERMINISTIC_EVIDENCE_MISSING",
    }
    return FactResolutionRecord(
        record_id="fact-resolution:" + semantic_digest(semantic),
        candidate_ref=candidate.candidate_id,
        proposal_ref=str(proposal.get("proposal_id")),
        claim_ref=str(item.get("proposal_ref")),
        requested_fact_type=str(item.get("semantic_role") or "unresolved"),
        target_subject_ref=str(item.get("target_ref") or "unresolved"),
        verifier_type=VerifierType.DOCUMENTED_CONTRACT,
        verifier_version=VERIFIER_VERSION,
        input_evidence_refs=(),
        input_evidence_digests=(),
        assertion="UNKNOWN",
        resulting_epistemic_status="PROPOSED",
        resulting_fact_ref=None,
        reason_code="DETERMINISTIC_EVIDENCE_MISSING",
        missing_requirements=("DETERMINISTIC_EVIDENCE",),
    )


def _rejected_record(
    candidate: MatcherCandidate,
    proposal: Mapping[str, Any],
    item: Mapping[str, Any],
    fact: Mapping[str, Any],
    evidence: EvidenceItem,
    reason: str,
) -> FactResolutionRecord:
    semantic = {
        "candidate_ref": candidate.candidate_id,
        "proposal_ref": proposal.get("proposal_id"),
        "claim_ref": item.get("proposal_ref"),
        "fact_type": fact.get("fact_type"),
        "reason": reason,
    }
    return FactResolutionRecord(
        record_id="fact-resolution:" + semantic_digest(semantic),
        candidate_ref=candidate.candidate_id,
        proposal_ref=str(proposal.get("proposal_id")),
        claim_ref=str(item.get("proposal_ref")),
        requested_fact_type=str(fact.get("fact_type")),
        target_subject_ref=str(fact.get("subject_ref")),
        verifier_type=VerifierType.DOCUMENTED_CONTRACT,
        verifier_version=VERIFIER_VERSION,
        input_evidence_refs=(evidence.evidence_ref,),
        input_evidence_digests=(evidence.artifact_digest,),
        assertion=str(fact.get("assertion", "UNKNOWN")),
        resulting_epistemic_status="PROPOSED",
        resulting_fact_ref=None,
        reason_code=reason,
        missing_requirements=("KNOWN_CANONICAL_FACT_TYPE",),
    )

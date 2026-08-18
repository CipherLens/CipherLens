"""Provider-neutral proposal orchestration for Matcher candidates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping, Sequence

from binding_proposal.canonical import binding_proposal_digest
from binding_proposal.model import InvocationStatus, ProviderInvocationResult
from binding_proposal.provider import LLMRoleProposalProvider
from binding_proposal.router import ProviderRouter
from matcher.knowledge import EvidenceItem
from matcher.model import MatcherCandidate, semantic_digest


@dataclass(frozen=True)
class ProposalAttempt:
    attempt_id: str
    candidate_ref: str
    invocation_ref: str
    invocation_status: str
    reason_code: str
    proposal: Mapping[str, Any] | None
    proposal_digest: str | None

    def to_trace_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "candidate_ref": self.candidate_ref,
            "invocation_ref": self.invocation_ref,
            "invocation_status": self.invocation_status,
            "reason_code": self.reason_code,
            "proposal_ref": self.proposal.get("proposal_id") if self.proposal else None,
            "proposal_digest": self.proposal_digest,
        }


class ProposalOrchestrator:
    def __init__(
        self,
        *,
        provider: LLMRoleProposalProvider,
        router: ProviderRouter,
        schema_path: str = "binding_proposal/payload.schema.yaml",
    ) -> None:
        self.provider = provider
        self.router = router
        self.schema_path = schema_path

    def propose(
        self,
        *,
        candidate: MatcherCandidate,
        contract_summary: Mapping[str, Any],
        transfer_signature_summary: Mapping[str, Any],
        template_summary: Mapping[str, Any],
        evidence: Sequence[EvidenceItem],
        attempt_number: int,
        source_references: Sequence[Mapping[str, Any]],
    ) -> ProposalAttempt:
        invocation_ref = (
            f"matcher-proposal:{candidate.candidate_id.rsplit(':', 1)[-1]}:{attempt_number}"
        )
        prompt = json.dumps(
            {
                "task": "propose semantic role assignments only",
                "trust_boundary": "output remains PROPOSED; do not decide security truth",
                "contract": contract_summary,
                "transfer_signature": transfer_signature_summary,
                "trigger_template": template_summary,
                "candidate": candidate.semantic_summary(),
                "evidence": [
                    {
                        "evidence_ref": item.evidence_ref,
                        "source_type": item.source_type.value,
                        "artifact_ref": item.artifact_ref,
                        "initial_epistemic_status": item.initial_epistemic_status,
                    }
                    for item in sorted(evidence, key=lambda item: item.evidence_ref)
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        request = self.provider.prepare_request(
            prompt, schema_path=self.schema_path, invocation_ref=invocation_ref
        )
        result = self.router.invoke(request)
        attempt_semantic = {
            "candidate_ref": candidate.candidate_id,
            "invocation_ref": invocation_ref,
            "status": result.status.value,
            "reason_code": result.reason_code,
        }
        if result.status is not InvocationStatus.SUCCESS or result.payload is None:
            return ProposalAttempt(
                attempt_id="proposal-attempt:" + semantic_digest(attempt_semantic),
                candidate_ref=candidate.candidate_id,
                invocation_ref=invocation_ref,
                invocation_status=result.status.value,
                reason_code=result.reason_code,
                proposal=None,
                proposal_digest=None,
            )

        provenance = self.provider.build_provenance(request, result)
        target_references = [
            {"artifact_ref": item.artifact_ref, "artifact_digest": item.artifact_digest}
            for item in sorted(evidence, key=lambda item: item.evidence_ref)
        ] or [{"artifact_ref": "matcher/synthetic-target", "artifact_digest": "0" * 64}]
        proposal_evidence = [
            {
                "evidence_ref": item.evidence_ref,
                "kind": item.source_type.value,
                "artifact_ref": item.artifact_ref,
                "artifact_digest": item.artifact_digest,
            }
            for item in sorted(evidence, key=lambda item: item.evidence_ref)
        ]
        request_artifact = json.dumps(
            {
                "invocation_ref": request.invocation_ref,
                "prompt": request.prompt,
                "schema_path": request.schema_path,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        invocation_source = {
            "artifact_ref": f"matcher/provider-requests/{invocation_ref}.json",
            "artifact_digest": hashlib.sha256(request_artifact).hexdigest(),
        }
        proposal = self.provider.build_binding_proposal(
            result.payload,
            source_references=[*source_references, invocation_source],
            target_references=target_references,
            provider_provenance=provenance,
            evidence=proposal_evidence,
        )
        digest = binding_proposal_digest(proposal)
        attempt_semantic.update(
            {"proposal_ref": proposal["proposal_id"], "proposal_digest": digest}
        )
        return ProposalAttempt(
            attempt_id="proposal-attempt:" + semantic_digest(attempt_semantic),
            candidate_ref=candidate.candidate_id,
            invocation_ref=invocation_ref,
            invocation_status=result.status.value,
            reason_code=result.reason_code,
            proposal=proposal,
            proposal_digest=digest,
        )

from __future__ import annotations

from copy import deepcopy

from binding_proposal.model import PAYLOAD_SCHEMA_VERSION


def payload() -> dict:
    empty = {
        "schema_version": PAYLOAD_SCHEMA_VERSION,
        "role_proposals": [], "subject_proposals": [], "operation_proposals": [],
        "input_proposals": [], "intervention_proposals": [],
        "state_continuity_proposals": [], "observation_proposals": [],
        "advisory_rationale": "Advisory proposal; deterministic verification is still required.",
    }
    empty["operation_proposals"] = [{
        "proposal_ref": "proposal-item:operation:1", "source_ref": "contract-step:PARSE_KEY",
        "target_ref": "symbol:synthetic_parse", "semantic_role": "PARSE",
        "related_refs": ["subject:synthetic-parser"], "evidence_hints": ["api-card:synthetic"],
    }]
    return empty


def reference(path: str) -> dict:
    return {"artifact_ref": path, "artifact_digest": "a" * 64}

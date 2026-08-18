"""Canonical construction of payloads and trusted BindingProposal envelopes."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Mapping

from binding_proposal.model import PROPOSAL_SCHEMA_VERSION
from binding_proposal.validate import PROPOSAL_LISTS, validate_binding_proposal_or_raise, validate_payload_or_raise


def normalize_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    for name in PROPOSAL_LISTS:
        for item in normalized.get(name, []):
            for key in ("related_refs", "evidence_hints"):
                item[key] = sorted(dict.fromkeys(item.get(key, [])))
        normalized[name] = sorted(normalized.get(name, []), key=lambda item: item.get("proposal_ref", ""))
    return normalized


def canonical_payload_bytes(value: Mapping[str, Any]) -> bytes:
    normalized = normalize_payload(value)
    validate_payload_or_raise(normalized)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def build_binding_proposal(
    payload: Mapping[str, Any], *, source_references: list[Mapping[str, Any]],
    target_references: list[Mapping[str, Any]], provider_provenance: Mapping[str, Any],
    evidence: list[Mapping[str, Any]], raw_output_artifact_ref: str | None = None,
    raw_output_digest: str | None = None,
) -> dict[str, Any]:
    """Inject the trusted envelope; model payload cannot provide these fields."""

    normalized_payload = normalize_payload(payload)
    validate_payload_or_raise(normalized_payload)
    semantic = {
        "source_references": sorted((dict(x) for x in source_references), key=lambda x: (x["artifact_ref"], x["artifact_digest"])),
        "target_references": sorted((dict(x) for x in target_references), key=lambda x: (x["artifact_ref"], x["artifact_digest"])),
        **{name: normalized_payload[name] for name in PROPOSAL_LISTS},
        **({"advisory_rationale": normalized_payload["advisory_rationale"]} if "advisory_rationale" in normalized_payload else {}),
    }
    proposal_id = "proposal:" + hashlib.sha256(
        json.dumps(semantic, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    result: dict[str, Any] = {
        "schema_version": PROPOSAL_SCHEMA_VERSION,
        "proposal_id": proposal_id,
        "source_references": semantic["source_references"],
        "target_references": semantic["target_references"],
        "provider_provenance": deepcopy(dict(provider_provenance)),
        "epistemic_status": "PROPOSED",
        "evidence": sorted((dict(x) for x in evidence), key=lambda x: x["evidence_ref"]),
        **{name: semantic[name] for name in PROPOSAL_LISTS},
    }
    if "advisory_rationale" in semantic:
        result["advisory_rationale"] = semantic["advisory_rationale"]
    if raw_output_artifact_ref is not None:
        result["raw_output_artifact_ref"] = raw_output_artifact_ref
    if raw_output_digest is not None:
        result["raw_output_digest"] = raw_output_digest
    validate_binding_proposal_or_raise(result)
    return result


def normalize_binding_proposal(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    for name in PROPOSAL_LISTS:
        for item in normalized.get(name, []):
            item["related_refs"] = sorted(dict.fromkeys(item.get("related_refs", [])))
            item["evidence_hints"] = sorted(dict.fromkeys(item.get("evidence_hints", [])))
        normalized[name] = sorted(normalized.get(name, []), key=lambda item: item.get("proposal_ref", ""))
    for name in ("source_references", "target_references"):
        normalized[name] = sorted(normalized.get(name, []), key=lambda x: (x.get("artifact_ref", ""), x.get("artifact_digest", "")))
    normalized["evidence"] = sorted(normalized.get("evidence", []), key=lambda x: x.get("evidence_ref", ""))
    return normalized


def canonical_binding_proposal_bytes(value: Mapping[str, Any]) -> bytes:
    normalized = normalize_binding_proposal(value)
    validate_binding_proposal_or_raise(normalized)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def binding_proposal_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_binding_proposal_bytes(value)).hexdigest()

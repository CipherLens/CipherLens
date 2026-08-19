"""C0 replay provenance manifests, deliberately outside frozen execution schemas."""

from __future__ import annotations

from typing import Any, Mapping

from target_knowledge.canonical import identified, semantic_safety_errors


_REQUIRED = (
    "candidate_binding", "candidate_binding_validation", "merge", "bound_source",
    "source_map", "execution_handoff", "build_spec", "run_spec", "run_record",
    "execution_witness", "structured_execution_trace", "contract_projection",
    "relation_evaluation",
)


def _edge(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not isinstance(value.get("ref"), str) or not isinstance(value.get("digest"), str):
        raise ValueError(f"{label} requires a ref + digest")
    digest = value["digest"]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"{label} digest must be SHA-256")
    return {"ref": value["ref"], "digest": digest}


def make_c0_replay_lineage(
    *, unit_id: str, source_identity: Mapping[str, Any], build_profile: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]], relation_result: str,
) -> dict[str, Any]:
    """Record fixture-only lineage without creating a Verdict or a claim result."""

    missing = [name for name in _REQUIRED if name not in artifacts]
    if missing:
        raise ValueError("C0 replay lineage missing: " + ", ".join(missing))
    if relation_result not in {"HOLDS", "BROKEN", "NOT_EVALUABLE"}:
        raise ValueError("C0 replay lineage requires deterministic relation evaluation")
    document = {
        "schema_version": "cipherlens.real_campaign_c0_replay_lineage.v0.1",
        "classification": "C0_REPLAY_FIXTURE_NOT_REAL_CAMPAIGN",
        "unit_id": unit_id,
        "source_identity": _edge(source_identity, "source identity"),
        "build_profile": _edge(build_profile, "build profile"),
        "artifacts": {name: _edge(artifacts[name], name) for name in _REQUIRED},
        "relation_result": relation_result,
        "report_real_number_allowed": False,
        "forbidden_outputs": ["ExecutionVerdict", "ViolationEvidencePackage", "CURRENT_V2_CAMPAIGN_RESULT", "SECURITY_FINDING"],
        "authority": "PIPELINE_VALIDATION_REPLAY_ONLY",
    }
    errors = semantic_safety_errors(document)
    if errors:
        raise ValueError("; ".join(errors))
    return identified(document, "c0-replay-lineage", "lineage_id")

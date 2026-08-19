"""C1-fix5 audit: refuse source materialization without declared writable holes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from target_knowledge.canonical import canonical_json_bytes, identified

from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
_FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage")
_FIX4 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1")
_RETRY = Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.1")
_OUT = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix5-v0.1")
_VALUES = ("DER_KIND", "PARSE_API_KIND", "TRAILING_GARBAGE_BYTES", "TRAILING_GARBAGE_LEN", "EXPECT_RET")


def _edge(root: Path, ref: str) -> dict[str, str]:
    return {"ref": ref, "digest": hashlib.sha256((root / ref).read_bytes()).hexdigest()}


def c1_fix5_audit(repo_root: str | Path) -> dict[str, Any]:
    """Return immutable facts; this routine never renders or executes C code."""
    root = Path(repo_root).resolve()
    merge_ref, map_ref, source_ref, handoff_ref = (str(_FIX2 / name) for name in ("merge.json", "source_map.json", "bound_source.c", "execution_handoff.json"))
    merge = json.loads((root / merge_ref).read_text())
    source_map = json.loads((root / map_ref).read_text())
    declared_holes = {x["hole_id"]: x for x in merge["adaptation_holes"]}
    capture_holes = {x.get("adaptation_hole_ref") for x in merge["observation_capture_bindings"] if x.get("adaptation_hole_ref")}
    writable = {x for region in source_map["regions"] if not region["protected"] for x in region["adaptation_hole_refs"]}
    unresolved = [{
        "hole_ref": f"undeclared-template-value:{name}", "template_slot_ref": f"template-value:{name}",
        "required_value_kind": "enum" if name in {"DER_KIND", "PARSE_API_KIND"} else ("hex_bytes" if name == "TRAILING_GARBAGE_BYTES" else ("size_t" if name == "TRAILING_GARBAGE_LEN" else "int")),
        "expected_source": "declared deterministic Template–CandidateBinding value hole",
        "current_reason_unresolved": "value occurs in protected base template and has no declared adaptation hole",
        "deterministic_resolver_exists": False, "proposal_or_adaptation_forbidden": True,
        "safe_repair_action": "create a successor canonical template/merge with an explicitly declared deterministic value hole",
    } for name in _VALUES]
    return identified({
        "schema_version": "cipherlens.c1_fix5_materialization_audit.v0.1", "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE, "execution_status": "NOT_EXECUTED", "report_real_number_allowed": False,
        "parent_artifacts": {"c1_retry_index": _edge(root, str(_RETRY / "artifact_index.json")), "c1_fix4_index": _edge(root, str(_FIX4 / "artifact_index.json"))},
        "lineage": {"merge": _edge(root, merge_ref), "source_map": _edge(root, map_ref), "bound_source": _edge(root, source_ref), "execution_handoff": _edge(root, handoff_ref)},
        "declared_adaptation_holes": sorted(declared_holes), "writable_holes": sorted(writable), "capture_holes": sorted(capture_holes),
        "unresolved_template_values": unresolved,
        "capture_insertion_status": "CAPTURE_INSERTION_POINT_MISSING",
        "capture_reason": "all Merge observation captures have adaptation_hole_ref=null; SourceMap has no writable capture region",
        "status": "C1_PRE_RUN_GATE_STILL_BLOCKED", "blocking_reasons": ["BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED", "CAPTURE_INSERTION_POINT_MISSING"],
        "authority": "C1_FIX5_AUDIT_ONLY_NO_SOURCE_PATCH_OR_EXECUTION",
    }, "c1-fix5-audit", "audit_id")


def write_c1_fix5_blocked_artifacts(repo_root: str | Path, audit: Mapping[str, Any]) -> dict[str, Path]:
    if audit.get("status") != "C1_PRE_RUN_GATE_STILL_BLOCKED": raise ValueError("C1-fix5 only writes a blocked repair")
    root = Path(repo_root).resolve(); out = root / _OUT
    if out.exists(): raise FileExistsError("C1-fix5 root is create-only")
    out.mkdir(parents=True)
    common = {"unit_id": APPROVED_UNIT_ID, "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE, "execution_status": "NOT_EXECUTED", "report_real_number_allowed": False}
    def edge(name: str, document: Mapping[str, Any]) -> dict[str, str]: return {"ref": str(_OUT / name), "digest": hashlib.sha256(canonical_json_bytes(document)).hexdigest()}
    audit_edge = edge("materialization_audit.json", audit)
    resolution = identified({"schema_version": "cipherlens.c1_fix5_template_value_resolution.v0.1", **common, "status": "UNRESOLVED", "parent_audit": audit_edge, "resolved_holes": [], "unresolved": audit["unresolved_template_values"], "authority": "DECLARED_HOLES_ONLY"}, "c1-fix5-resolution", "resolution_id")
    capture = identified({"schema_version": "cipherlens.c1_fix5_capture_hook_spec.v0.1", **common, "status": "CAPTURE_INSERTION_POINT_MISSING", "parent_audit": audit_edge, "required_semantic_roles": ["operation_outcome", "consumed_length", "input_length"], "required_correlation_group": "CORRELATION_PRIMARY", "marker_version": "ORACLE_EVENT_V0_1", "hook_generated": False, "authority": "DECLARED_CAPTURE_HOLE_ONLY"}, "c1-fix5-capture", "spec_id")
    source = identified({"schema_version": "cipherlens.c1_fix5_bound_source_materialization.v0.1", **common, "status": "NOT_GENERATED", "parent_audit": audit_edge, "reason_code": "BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED", "protected_source_mutated": False}, "c1-fix5-source", "materialization_id")
    source_map = identified({"schema_version": "cipherlens.c1_fix5_source_map_update.v0.1", **common, "status": "NOT_GENERATED", "parent_audit": audit_edge, "reason_code": "CAPTURE_INSERTION_POINT_MISSING", "protected_region_mutated": False}, "c1-fix5-map", "update_id")
    handoff = identified({"schema_version": "cipherlens.c1_fix5_execution_handoff_readiness.v0.1", **common, "status": "NOT_READY", "parent_audit": audit_edge, "reason_codes": list(audit["blocking_reasons"]), "build_spec_materializable": False, "run_spec_materializable": False}, "c1-fix5-handoff", "readiness_id")
    gate = identified({"schema_version": "cipherlens.c1_fix5_pre_run_gate.v0.1", **common, "status": "C1_PRE_RUN_GATE_STILL_BLOCKED", "parent_audit": audit_edge, "blocking_reasons": list(audit["blocking_reasons"]), "build_run_authorized": False, "witness_generated": False, "structured_trace_generated": False, "execution_verdict_generated": False, "violation_evidence_package_generated": False}, "c1-fix5-gate", "decision_id")
    docs = {"materialization_audit.json": audit, "template_value_resolution.json": resolution, "capture_hook_spec.json": capture, "bound_source_materialization.json": source, "source_map_update.json": source_map, "execution_handoff_readiness.json": handoff, "c1_pre_run_gate_decision.json": gate}
    entries = [{"artifact_type": name[:-5], **edge(name, doc)} for name, doc in sorted(docs.items())]
    index = identified({"schema_version": "cipherlens.c1_fix5_artifact_index.v0.1", **common, "status": "C1_PRE_RUN_GATE_STILL_BLOCKED", "parent_artifacts": audit["parent_artifacts"], "artifacts": entries, "authority": "C1_FIX5_CREATE_ONLY_ARTIFACT_INDEX"}, "c1-fix5-index", "index_id")
    docs["artifact_index.json"] = index
    for name, doc in docs.items(): (out / name).write_bytes(canonical_json_bytes(doc))
    return {name: out / name for name in docs}

"""Source-only Contract validation over same-library Buggy/Fixed witnesses."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

import yaml

from contract_miner.divergence import validate_divergence
from contract_miner.relations import evaluate_relation, extract_observations
from contract_miner.schema import canonical_vc_bytes, validate_vc
from contract_miner.trace import TraceValidationError, load_trace


SOURCE_VALIDATION_VERSION = "cipherlens.source_validation.v0_1"
SOURCE_RESULTS = frozenset({"PASS", "FAIL", "INCONCLUSIVE", "INVALID_INPUT"})


class SourceValidationSchemaError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("invalid source validation record:\n" + "\n".join(f"- {item}" for item in errors))


def validate_source_contract(
    contract: Mapping[str, Any],
    buggy_trace_path: str | Path,
    fixed_trace_path: str | Path,
    divergence: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate historical separation; never emit target Contract Verdicts."""

    root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
    input_errors = validate_vc(contract, repo_root=root)
    input_errors.extend(validate_divergence(divergence))
    input_errors.extend(_validate_manifest(evidence_manifest, contract, root))
    buggy_header = fixed_header = None
    buggy_events: list[Any] = []
    fixed_events: list[Any] = []
    try:
        buggy_header, buggy_events = load_trace(buggy_trace_path)
    except (OSError, TraceValidationError) as exc:
        input_errors.append(f"buggy_trace: {exc}")
    try:
        fixed_header, fixed_events = load_trace(fixed_trace_path)
    except (OSError, TraceValidationError) as exc:
        input_errors.append(f"fixed_trace: {exc}")

    alignment_errors: list[str] = []
    if buggy_header and fixed_header:
        alignment_errors.extend(_trace_alignment(contract, buggy_header, fixed_header))
    alignment_errors.extend(_intervention_alignment(contract, divergence, evidence_manifest))
    alignment_errors.extend(_divergence_alignment(contract, divergence, evidence_manifest))
    input_errors.extend(alignment_errors)

    source = contract.get("source", {}) if isinstance(contract, dict) else {}
    base = {
        "schema_version": SOURCE_VALIDATION_VERSION,
        "validation_id": f"{contract.get('contract_id', 'INVALID')}_SOURCE_VALIDATION",
        "contract_id": contract.get("contract_id", "INVALID"),
        "source_pair": {
            "library": source.get("library", ""),
            "buggy_revision": source.get("buggy_revision", ""),
            "fixed_revision": source.get("fixed_revision", ""),
            "pair_kind": "same_library_fix",
        },
        "provenance": {
            "contract_sha256": hashlib.sha256(canonical_vc_bytes(contract)).hexdigest() if isinstance(contract, dict) else "",
            "buggy_trace": _provenance_path(buggy_trace_path, root),
            "fixed_trace": _provenance_path(fixed_trace_path, root),
            "divergence_id": divergence.get("divergence_id", "") if isinstance(divergence, dict) else "",
        },
    }
    if input_errors:
        return {
            **base,
            "status": "INVALID_INPUT",
            "reason_codes": _reason_codes(input_errors, default="INVALID_SCHEMA"),
            "buggy": {"relation_results": [], "errors": sorted(input_errors)},
            "fixed": {"relation_results": [], "errors": sorted(input_errors)},
        }

    buggy_observations, buggy_errors = extract_observations(contract, buggy_events)
    fixed_observations, fixed_errors = extract_observations(contract, fixed_events)
    relations = contract["expected_relation"]["relations"]
    buggy_results = [evaluate_relation(item, buggy_observations) for item in relations]
    fixed_results = [evaluate_relation(item, fixed_observations) for item in relations]
    primary_ids = {item["relation_id"] for item in relations if item["criticality"] == "primary"}
    buggy_primary = [item for item in buggy_results if item.relation_id in primary_ids]
    fixed_primary = [item for item in fixed_results if item.relation_id in primary_ids]

    reasons: list[str] = []
    if buggy_errors or fixed_errors or any(item.result == "NOT_EVALUABLE" for item in buggy_primary + fixed_primary):
        status = "INCONCLUSIVE"
        reasons.append("RELATION_NOT_EVALUABLE")
        if any(item.missing_observables for item in buggy_primary + fixed_primary):
            reasons.append("REQUIRED_OBSERVABLE_MISSING")
        if buggy_errors or fixed_errors:
            reasons.append("WRONG_OBSERVABLE_TYPE")
    elif any(item.result == "BROKEN" for item in fixed_primary):
        status = "FAIL"
        reasons.append("FIXED_ALSO_BREAKS_RELATION")
    elif not any(item.result == "BROKEN" for item in buggy_primary):
        status = "FAIL"
        reasons.append("BUGGY_VIOLATION_NOT_OBSERVED")
    else:
        status = "PASS"
        reasons.append("SOURCE_WITNESSES_DISTINGUISHED")
    return {
        **base,
        "status": status,
        "reason_codes": sorted(reasons),
        "buggy": {"relation_results": [item.to_dict() for item in buggy_results], "errors": sorted(buggy_errors)},
        "fixed": {"relation_results": [item.to_dict() for item in fixed_results], "errors": sorted(fixed_errors)},
    }


def canonical_source_validation_bytes(value: Mapping[str, Any]) -> bytes:
    validate_source_validation_record_or_raise(value)
    return yaml.safe_dump(dict(value), allow_unicode=True, default_flow_style=False, sort_keys=True).encode("utf-8")


def validate_source_validation_record(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    required = {"schema_version", "validation_id", "contract_id", "status", "reason_codes", "source_pair", "buggy", "fixed", "provenance"}
    for key in sorted(required - set(value)):
        errors.append(f"{key}: required field missing")
    for key in sorted(set(value) - required):
        errors.append(f"{key}: unknown field")
    if value.get("schema_version") != SOURCE_VALIDATION_VERSION:
        errors.append("schema_version: invalid")
    if value.get("status") not in SOURCE_RESULTS:
        errors.append("status: unknown value")
    if not isinstance(value.get("reason_codes"), list) or not all(isinstance(item, str) for item in value.get("reason_codes", [])):
        errors.append("reason_codes: expected list[string]")
    pair = value.get("source_pair")
    if not isinstance(pair, dict) or set(pair) != {"library", "buggy_revision", "fixed_revision", "pair_kind"}:
        errors.append("source_pair: invalid fields")
    elif pair.get("pair_kind") != "same_library_fix":
        errors.append("source_pair.pair_kind: only same_library_fix is supported")
    for side in ("buggy", "fixed"):
        body = value.get(side)
        if not isinstance(body, dict) or set(body) != {"relation_results", "errors"}:
            errors.append(f"{side}: invalid fields")
            continue
        if not isinstance(body.get("errors"), list):
            errors.append(f"{side}.errors: expected list")
        results = body.get("relation_results")
        if not isinstance(results, list):
            errors.append(f"{side}.relation_results: expected list")
            continue
        for index, item in enumerate(results):
            path = f"{side}.relation_results[{index}]"
            expected = {"relation_id", "result", "evidence_bindings", "reason_code", "missing_observables"}
            if not isinstance(item, dict) or set(item) != expected:
                errors.append(f"{path}: invalid fields")
            elif item.get("result") not in {"HOLDS", "BROKEN", "NOT_EVALUABLE"}:
                errors.append(f"{path}.result: unknown value")
    serialized = yaml.safe_dump(value)
    for forbidden in ("SATISFIED", "VIOLATED", "UNKNOWN"):
        if forbidden in serialized:
            errors.append(f"record: target Verdict {forbidden} is forbidden")
    return sorted(dict.fromkeys(errors))


def validate_source_validation_record_or_raise(value: Any) -> None:
    errors = validate_source_validation_record(value)
    if errors:
        raise SourceValidationSchemaError(errors)


def _trace_alignment(contract: Mapping[str, Any], buggy: Any, fixed: Any) -> list[str]:
    source = contract["source"]
    errors: list[str] = []
    expected = (
        (buggy.build, "buggy", "buggy build"),
        (fixed.build, "fixed", "fixed build"),
        (buggy.library, source["library"], "buggy library"),
        (fixed.library, source["library"], "fixed library"),
        (buggy.library_version, source["buggy_revision"], "buggy revision"),
        (fixed.library_version, source["fixed_revision"], "fixed revision"),
        (buggy.pattern_id, source["pattern_id"], "buggy pattern"),
        (fixed.pattern_id, source["pattern_id"], "fixed pattern"),
        (buggy.pair_kind, "same_library_fix", "buggy pair kind"),
        (fixed.pair_kind, "same_library_fix", "fixed pair kind"),
    )
    for actual, wanted, label in expected:
        if actual != wanted:
            errors.append(f"{label} mismatch")
    return errors


def _intervention_alignment(contract: Mapping[str, Any], divergence: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[str]:
    contract_ids = [item.get("action_id") for item in contract.get("intervention", {}).get("actions", [])]
    divergence_ids = divergence.get("intervention_refs", []) if isinstance(divergence, dict) else []
    manifest_ids = [item.get("action_id") for item in manifest.get("intervention", {}).get("actions", [])] if isinstance(manifest, dict) else []
    return [] if contract_ids == divergence_ids == manifest_ids else ["intervention semantics mismatch"]


def _divergence_alignment(contract: Mapping[str, Any], divergence: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    source = contract.get("source", {})
    pair = divergence.get("source_pair", {}) if isinstance(divergence, dict) else {}
    for key in ("library", "buggy_revision", "fixed_revision"):
        if source.get(key) != pair.get(key):
            errors.append(f"divergence {key} mismatch")
    step_ids = {item.get("step_id") for item in contract.get("execution", {}).get("steps", [])}
    evidence_ids = {item.get("evidence_id") for item in manifest.get("evidence", [])} if isinstance(manifest, dict) else set()
    divergence_evidence = set(divergence.get("evidence_refs", [])) if isinstance(divergence, dict) else set()
    if divergence_evidence != evidence_ids:
        errors.append("divergence evidence_refs mismatch")
    for index, delta in enumerate(divergence.get("deltas", []) if isinstance(divergence, dict) else []):
        if delta.get("step_ref") not in step_ids:
            errors.append(f"divergence delta {index} step_ref mismatch")
        if not set(delta.get("source_refs", [])).issubset(evidence_ids):
            errors.append(f"divergence delta {index} source_refs mismatch")
    provenance_refs = set(divergence.get("provenance", {}).get("source_refs", [])) if isinstance(divergence, dict) else set()
    if not provenance_refs.issubset(evidence_ids):
        errors.append("divergence provenance source_refs mismatch")
    return errors


def _validate_manifest(manifest: Mapping[str, Any], contract: Mapping[str, Any], repo_root: Path) -> list[str]:
    errors: list[str] = []
    required = {"schema_version", "contract_id", "contract_family", "family_rule", "source", "context", "intervention", "execution", "rule_parameters", "evidence", "human_review"}
    if not isinstance(manifest, dict):
        return ["evidence manifest: expected object"]
    if set(manifest) != required:
        errors.append("evidence manifest: invalid top-level keys")
        return errors
    if manifest.get("schema_version") != "cipherlens.mining_input.v0_1":
        errors.append("evidence manifest: invalid schema version")
    for key in ("contract_id", "contract_family", "source", "context", "intervention", "execution", "human_review"):
        if manifest.get(key) != contract.get(key if key != "evidence" else "provenance"):
            if key not in {"human_review"}:
                errors.append(f"evidence manifest: {key} mismatch")
    if manifest.get("human_review") != contract.get("provenance", {}).get("human_review"):
        errors.append("evidence manifest: human_review mismatch")
    if manifest.get("evidence") != contract.get("provenance", {}).get("evidence"):
        errors.append("evidence manifest: evidence mismatch")
    return errors


def _reason_codes(errors: list[str], default: str) -> list[str]:
    codes: set[str] = set()
    for error in errors:
        lower = error.lower()
        if "digest mismatch" in lower:
            codes.add("EVIDENCE_DIGEST_MISMATCH")
        elif "revision" in lower:
            codes.add("SOURCE_REVISION_MISMATCH")
        elif "intervention" in lower:
            codes.add("INTERVENTION_MISMATCH")
        elif "trace" in lower:
            codes.add("INVALID_TRACE")
        else:
            codes.add(default)
    return sorted(codes)


def _provenance_path(path: str | Path, repo_root: Path) -> str:
    """Use stable repo-relative trace paths without leaking host layout."""

    source = Path(path)
    try:
        return source.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return f"external:{source.name}"

"""Closed validators and the versioned initial metric-definition registry."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Mapping

from evaluation_evidence.canonical import ID_FIELDS, canonical_json_bytes, identify, semantic_id, semantic_safety_errors, validate_relative_location
from evaluation_evidence.lineage import GIT_REVISION_RE, SHA256_RE, validate_link
from evaluation_evidence.model import (
    ClaimGateResult, ClaimTaxonomy, EvidenceOrigin, EvaluationEvidenceError,
    FindingStatus, InventoryState, METRIC_REGISTRY_VERSION, REGISTRY_VERSION,
    RecomputeStatus, SCHEMA_VERSIONS, ValidationMaturity,
)


def _exact(value: Any, required: set[str], optional: set[str], path: str, errors: list[str]) -> bool:
    if not isinstance(value, Mapping):
        errors.append(f"{path}: expected object")
        return False
    missing = required - set(value)
    extra = set(value) - required - optional
    errors.extend(f"{path}.{key}: required field missing" for key in sorted(missing))
    errors.extend(f"{path}.{key}: unknown field" for key in sorted(extra))
    return not missing and not extra


def _string(value: Any, path: str, errors: list[str], *, allow_empty: bool = False) -> None:
    if not isinstance(value, str) or (not allow_empty and not value):
        errors.append(f"{path}: expected {'string' if allow_empty else 'non-empty string'}")


def _integer(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{path}: expected non-negative integer")


def _enum(value: Any, enum_type: type, path: str, errors: list[str]) -> None:
    if value not in {item.value for item in enum_type}:
        errors.append(f"{path}: unknown value")


def _strings(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        errors.append(f"{path}: expected array of non-empty strings")


def _link(value: Any, path: str, errors: list[str]) -> None:
    errors.extend(validate_link(value, path))


def _links(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{path}: expected array")
        return
    for index, item in enumerate(value):
        _link(item, f"{path}[{index}]", errors)


def _producer(value: Any, path: str, errors: list[str]) -> None:
    if _exact(value, {"producer_id", "producer_version"}, set(), path, errors):
        _string(value["producer_id"], f"{path}.producer_id", errors)
        _string(value["producer_version"], f"{path}.producer_version", errors)


def _git(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not GIT_REVISION_RE.fullmatch(value):
        errors.append(f"{path}: expected full lowercase Git revision")


def _target_scope(value: Any, path: str, errors: list[str]) -> None:
    if _exact(value, {"library", "version", "build_profile"}, set(), path, errors):
        for key in ("library", "version", "build_profile"):
            _string(value[key], f"{path}.{key}", errors)


def _rule(value: Any, path: str, errors: list[str]) -> None:
    if not _exact(value, {"kind", "predicates"}, set(), path, errors):
        return
    if value.get("kind") not in {"ALL", "FILTER", "NONE"}:
        errors.append(f"{path}.kind: unknown value")
    predicates = value.get("predicates")
    if not isinstance(predicates, list):
        errors.append(f"{path}.predicates: expected array")
        return
    if value.get("kind") != "FILTER" and predicates:
        errors.append(f"{path}.predicates: only FILTER may contain predicates")
    if value.get("kind") == "FILTER" and not predicates:
        errors.append(f"{path}.predicates: FILTER requires predicates")
    for index, predicate in enumerate(predicates):
        p = f"{path}.predicates[{index}]"
        if _exact(predicate, {"field", "comparator", "value"}, set(), p, errors):
            _string(predicate["field"], f"{p}.field", errors)
            if predicate["comparator"] not in {"EQ", "NE", "IN", "EXISTS"}:
                errors.append(f"{p}.comparator: unknown value")
            if predicate["comparator"] == "IN" and not isinstance(predicate["value"], list):
                errors.append(f"{p}.value: IN requires array")
            allowed_scalar = (str, int, bool, type(None))
            candidate = predicate["value"]
            if isinstance(candidate, Mapping) or not (
                isinstance(candidate, allowed_scalar)
                or (isinstance(candidate, list) and all(isinstance(item, allowed_scalar) for item in candidate))
            ):
                errors.append(f"{p}.value: expected closed scalar or scalar array")


def _validate_artifact_record(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "artifact_record_id", "artifact_ref", "artifact_digest",
        "artifact_type", "artifact_schema_version", "media_type", "producer",
        "git_revision", "origin", "inventory_state", "validation_maturity",
        "execution_scope", "synthetic_or_real", "public_disclosure_state",
        "parent_refs", "source_location", "validation_evidence_refs", "notes",
    }
    if not _exact(value, required, set(), "$", errors):
        return
    for key in ("artifact_ref", "artifact_type", "artifact_schema_version", "media_type", "execution_scope", "public_disclosure_state"):
        _string(value[key], key, errors, allow_empty=key == "artifact_schema_version")
    digest = value["artifact_digest"]
    if digest is None:
        if value["inventory_state"] not in {"NOT_FOUND", "PRESENT_UNVERIFIED", "REFERENCE_ONLY"}:
            errors.append("artifact_digest: required for present verified artifact")
    elif not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        errors.append("artifact_digest: expected lowercase sha256 or null")
    _producer(value["producer"], "producer", errors)
    _git(value["git_revision"], "git_revision", errors)
    _enum(value["origin"], EvidenceOrigin, "origin", errors)
    _enum(value["inventory_state"], InventoryState, "inventory_state", errors)
    if value["synthetic_or_real"] not in {"SYNTHETIC", "REAL"}:
        errors.append("synthetic_or_real: unknown value")
    if not isinstance(value["validation_maturity"], list):
        errors.append("validation_maturity: expected array")
    else:
        for index, item in enumerate(value["validation_maturity"]):
            _enum(item, ValidationMaturity, f"validation_maturity[{index}]", errors)
        if len(value["validation_maturity"]) != len(set(value["validation_maturity"])):
            errors.append("validation_maturity: duplicate state")
    _links(value["parent_refs"], "parent_refs", errors)
    _links(value["validation_evidence_refs"], "validation_evidence_refs", errors)
    _strings(value["notes"], "notes", errors)
    if not isinstance(value["source_location"], str) or not validate_relative_location(value["source_location"]):
        errors.append("source_location: expected repository-relative location")


def _validate_test_run(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "test_run_id", "git_revision", "command", "test_scope",
        "working_profile", "test_definition_refs", "passed", "failed", "skipped",
        "xfailed", "errors", "stdout_artifact", "stderr_artifact", "summary_artifact",
        "environment_profile", "producer",
    }
    if not _exact(value, required, set(), "$", errors):
        return
    _git(value["git_revision"], "git_revision", errors)
    _strings(value["command"], "command", errors)
    _string(value["test_scope"], "test_scope", errors)
    _link(value["working_profile"], "working_profile", errors)
    _links(value["test_definition_refs"], "test_definition_refs", errors)
    for key in ("passed", "failed", "skipped", "xfailed", "errors"):
        _integer(value[key], key, errors)
    for key in ("stdout_artifact", "stderr_artifact", "summary_artifact", "environment_profile"):
        _link(value[key], key, errors)
    _producer(value["producer"], "producer", errors)


def _validate_experiment_unit(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "experiment_unit_id", "research_question_refs", "unit_type",
        "target_scope", "input_refs", "attempt_refs", "output_refs", "inclusion_status",
        "completion_status", "origin", "notes",
    }
    if not _exact(value, required, set(), "$", errors):
        return
    _strings(value["research_question_refs"], "research_question_refs", errors)
    _string(value["unit_type"], "unit_type", errors)
    _target_scope(value["target_scope"], "target_scope", errors)
    for key in ("input_refs", "attempt_refs", "output_refs"):
        _links(value[key], key, errors)
    if value["inclusion_status"] not in {"INCLUDED", "EXCLUDED"}:
        errors.append("inclusion_status: unknown value")
    if value["completion_status"] not in {"COMPLETE", "PARTIAL", "NOT_RUN", "FAILED"}:
        errors.append("completion_status: unknown value")
    _enum(value["origin"], EvidenceOrigin, "origin", errors)
    _strings(value["notes"], "notes", errors)


def _validate_metric_definition(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "metric_definition_id", "metric_name", "definition_version",
        "research_question_refs", "population_unit", "selection_rule", "numerator_rule",
        "denominator_rule", "aggregation_rule", "required_artifact_types", "allowed_origins",
        "allowed_claim_levels", "presentation_rule", "forbidden_interpretations",
    }
    if not _exact(value, required, set(), "$", errors):
        return
    for key in ("metric_name", "definition_version", "population_unit"):
        _string(value[key], key, errors)
    _strings(value["research_question_refs"], "research_question_refs", errors)
    for key in ("selection_rule", "numerator_rule", "denominator_rule"):
        _rule(value[key], key, errors)
    if value["aggregation_rule"] not in {"COUNT", "RATIO"}:
        errors.append("aggregation_rule: unknown value")
    _strings(value["required_artifact_types"], "required_artifact_types", errors)
    if not isinstance(value["allowed_origins"], list):
        errors.append("allowed_origins: expected array")
    else:
        for index, item in enumerate(value["allowed_origins"]):
            _enum(item, EvidenceOrigin, f"allowed_origins[{index}]", errors)
    if not isinstance(value["allowed_claim_levels"], list):
        errors.append("allowed_claim_levels: expected array")
    else:
        for index, item in enumerate(value["allowed_claim_levels"]):
            _enum(item, ClaimTaxonomy, f"allowed_claim_levels[{index}]", errors)
    if _exact(value["presentation_rule"], {"format", "scale", "decimals"}, set(), "presentation_rule", errors):
        if value["presentation_rule"]["format"] not in {"INTEGER", "EXACT_RATIO", "PERCENTAGE"}:
            errors.append("presentation_rule.format: unknown value")
        _integer(value["presentation_rule"]["scale"], "presentation_rule.scale", errors)
        _integer(value["presentation_rule"]["decimals"], "presentation_rule.decimals", errors)
    _strings(value["forbidden_interpretations"], "forbidden_interpretations", errors)


def _validate_metric_record(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "metric_record_id", "metric_definition", "population_manifest", "experiment_unit_refs",
        "numerator_refs", "denominator_refs", "numerator_value", "denominator_value",
        "derived_value", "origin", "population_complete", "all_source_digests_valid",
        "recompute_status", "recompute_trace", "caveats", "producer", "git_revision", "registry_version",
    }
    if not _exact(value, required, {"ledger"}, "$", errors):
        return
    _link(value["metric_definition"], "metric_definition", errors)
    _link(value["population_manifest"], "population_manifest", errors)
    if "ledger" in value:
        _link(value["ledger"], "ledger", errors)
    for key in ("experiment_unit_refs", "numerator_refs", "denominator_refs"):
        _links(value[key], key, errors)
    _integer(value["numerator_value"], "numerator_value", errors)
    _integer(value["denominator_value"], "denominator_value", errors)
    derived = value["derived_value"]
    if _exact(derived, {"kind", "numerator", "denominator"}, set(), "derived_value", errors):
        if derived["kind"] not in {"COUNT", "RATIO"}:
            errors.append("derived_value.kind: unknown value")
        _integer(derived["numerator"], "derived_value.numerator", errors)
        _integer(derived["denominator"], "derived_value.denominator", errors)
        if derived["numerator"] != value["numerator_value"] or derived["denominator"] != value["denominator_value"]:
            errors.append("derived_value: must exactly preserve numerator_value/denominator_value")
    if isinstance(value["numerator_refs"], list) and len(value["numerator_refs"]) != value["numerator_value"]:
        errors.append("numerator_value: must equal numerator_refs length")
    if isinstance(value["denominator_refs"], list) and len(value["denominator_refs"]) != value["denominator_value"]:
        errors.append("denominator_value: must equal denominator_refs length")
    _enum(value["origin"], EvidenceOrigin, "origin", errors)
    for key in ("population_complete", "all_source_digests_valid"):
        if not isinstance(value[key], bool):
            errors.append(f"{key}: expected boolean")
    _enum(value["recompute_status"], RecomputeStatus, "recompute_status", errors)
    if not isinstance(value["recompute_trace"], list):
        errors.append("recompute_trace: expected array")
    else:
        for index, item in enumerate(value["recompute_trace"]):
            path = f"recompute_trace[{index}]"
            if _exact(item, {"step", "input_count", "output_count", "rule_digest"}, set(), path, errors):
                _string(item["step"], f"{path}.step", errors)
                _integer(item["input_count"], f"{path}.input_count", errors)
                _integer(item["output_count"], f"{path}.output_count", errors)
                if not isinstance(item["rule_digest"], str) or not SHA256_RE.fullmatch(item["rule_digest"]):
                    errors.append(f"{path}.rule_digest: expected lowercase sha256")
    _strings(value["caveats"], "caveats", errors)
    _producer(value["producer"], "producer", errors)
    _git(value["git_revision"], "git_revision", errors)
    if value["registry_version"] != REGISTRY_VERSION:
        errors.append("registry_version: unsupported")


def _validate_metric_population_manifest(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {"schema_version", "population_manifest_id", "population_unit", "origin", "complete", "items"}
    if not _exact(value, required, set(), "$", errors):
        return
    _string(value["population_unit"], "population_unit", errors)
    _enum(value["origin"], EvidenceOrigin, "origin", errors)
    if not isinstance(value["complete"], bool):
        errors.append("complete: expected boolean")
    if not isinstance(value["items"], list):
        errors.append("items: expected array")
        return
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value["items"]):
        path = f"items[{index}]"
        if not _exact(item, {"artifact", "artifact_type", "origin", "attributes"}, set(), path, errors):
            continue
        _link(item["artifact"], f"{path}.artifact", errors)
        _string(item["artifact_type"], f"{path}.artifact_type", errors)
        _enum(item["origin"], EvidenceOrigin, f"{path}.origin", errors)
        if item["origin"] != value["origin"]:
            errors.append(f"{path}.origin: must match manifest origin")
        if _exact(item["attributes"], {"status"}, set(), f"{path}.attributes", errors):
            status = item["attributes"]["status"]
            if status is not None and (not isinstance(status, str) or not status):
                errors.append(f"{path}.attributes.status: expected non-empty string or null")
        if isinstance(item.get("artifact"), Mapping):
            identity = (str(item["artifact"].get("ref")), str(item["artifact"].get("digest")))
            if identity in seen:
                errors.append(f"{path}.artifact: duplicate population item")
            seen.add(identity)


def _validate_claim(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "claim_id", "claim_taxonomy", "statement", "scope",
        "evidence_refs", "metric_refs", "finding_refs", "requested_report_sections",
        "requested_ppt_usage", "public_disclosure_state", "producer", "git_revision",
    }
    if not _exact(value, required, set(), "$", errors):
        return
    _enum(value["claim_taxonomy"], ClaimTaxonomy, "claim_taxonomy", errors)
    _string(value["statement"], "statement", errors)
    if _exact(value["scope"], {"current_v2", "real_campaign", "global_security", "confirmed_vulnerability", "upstream_acknowledged"}, set(), "scope", errors):
        for key, item in value["scope"].items():
            if not isinstance(item, bool):
                errors.append(f"scope.{key}: expected boolean")
    for key in ("evidence_refs", "metric_refs", "finding_refs"):
        _links(value[key], key, errors)
    _strings(value["requested_report_sections"], "requested_report_sections", errors)
    _strings(value["requested_ppt_usage"], "requested_ppt_usage", errors)
    _string(value["public_disclosure_state"], "public_disclosure_state", errors)
    _producer(value["producer"], "producer", errors)
    _git(value["git_revision"], "git_revision", errors)


def _validate_gate_report(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "claim_gate_report_id", "claim", "gate_result", "reason_codes",
        "blocking_refs", "required_actions", "allowed_wording", "forbidden_wording",
        "allowed_report_sections", "ppt_usage", "producer", "registry_version",
    }
    if not _exact(value, required, set(), "$", errors):
        return
    _link(value["claim"], "claim", errors)
    _enum(value["gate_result"], ClaimGateResult, "gate_result", errors)
    for key in ("reason_codes", "required_actions", "allowed_wording", "forbidden_wording", "allowed_report_sections", "ppt_usage"):
        _strings(value[key], key, errors)
    _links(value["blocking_refs"], "blocking_refs", errors)
    _producer(value["producer"], "producer", errors)
    if value["registry_version"] != REGISTRY_VERSION:
        errors.append("registry_version: unsupported")


def _validate_finding(value: Any, path: str, errors: list[str]) -> None:
    required = {
        "finding_id", "finding_status", "target_scope", "affected_component", "family",
        "contract", "candidate_binding", "execution_verdict", "violation_package",
        "reproduction_refs", "impact_refs", "upstream_refs", "fix_refs", "advisory_refs",
        "origin", "public_disclosure_state", "allowed_claim_boundary",
    }
    if not _exact(value, required, set(), path, errors):
        return
    _string(value["finding_id"], f"{path}.finding_id", errors)
    _enum(value["finding_status"], FindingStatus, f"{path}.finding_status", errors)
    _target_scope(value["target_scope"], f"{path}.target_scope", errors)
    _string(value["affected_component"], f"{path}.affected_component", errors)
    _string(value["family"], f"{path}.family", errors)
    for key in ("contract", "candidate_binding", "execution_verdict", "violation_package"):
        if value[key] is not None:
            _link(value[key], f"{path}.{key}", errors)
    for key in ("reproduction_refs", "impact_refs", "upstream_refs", "fix_refs", "advisory_refs"):
        _links(value[key], f"{path}.{key}", errors)
    _enum(value["origin"], EvidenceOrigin, f"{path}.origin", errors)
    _string(value["public_disclosure_state"], f"{path}.public_disclosure_state", errors)
    _string(value["allowed_claim_boundary"], f"{path}.allowed_claim_boundary", errors)
    if isinstance(value.get("finding_id"), str):
        try:
            body = deepcopy(dict(value)); body.pop("finding_id", None)
            expected_id = "finding:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()
            if value["finding_id"] != expected_id:
                errors.append(f"{path}.finding_id: canonical identity mismatch")
        except (TypeError, ValueError) as exc:
            errors.append(f"{path}.finding_id: {exc}")


def _validate_finding_ledger(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {"schema_version", "ledger_id", "producer", "git_revision", "registry_version", "findings"}
    if not _exact(value, required, set(), "$", errors):
        return
    _producer(value["producer"], "producer", errors)
    _git(value["git_revision"], "git_revision", errors)
    if value["registry_version"] != REGISTRY_VERSION:
        errors.append("registry_version: unsupported")
    if not isinstance(value["findings"], list):
        errors.append("findings: expected array")
    else:
        for index, item in enumerate(value["findings"]):
            _validate_finding(item, f"findings[{index}]", errors)
        ids = [item.get("finding_id") for item in value["findings"] if isinstance(item, Mapping)]
        if len(ids) != len(set(ids)):
            errors.append("findings: duplicate finding_id")


def _validate_ledger(value: Mapping[str, Any], errors: list[str]) -> None:
    required = {
        "schema_version", "ledger_id", "producer", "git_revision", "registry_version",
        "artifact_records", "test_run_records", "experiment_units", "metric_records",
        "finding_records", "claim_records",
    }
    if not _exact(value, required, set(), "$", errors):
        return
    _producer(value["producer"], "producer", errors)
    _git(value["git_revision"], "git_revision", errors)
    if value["registry_version"] != REGISTRY_VERSION:
        errors.append("registry_version: unsupported")
    groups = {
        "artifact_records": SCHEMA_VERSIONS["artifact_record"],
        "test_run_records": SCHEMA_VERSIONS["test_run_record"],
        "experiment_units": SCHEMA_VERSIONS["experiment_unit"],
        "metric_records": SCHEMA_VERSIONS["metric_record"],
        "claim_records": SCHEMA_VERSIONS["claim_record"],
    }
    for name, schema in groups.items():
        items = value[name]
        if not isinstance(items, list):
            errors.append(f"{name}: expected array")
            continue
        for index, item in enumerate(items):
            if not isinstance(item, Mapping) or item.get("schema_version") != schema:
                errors.append(f"{name}[{index}]: unexpected schema")
            else:
                child_errors = validate_document(item)
                errors.extend(f"{name}[{index}].{item}" for item in child_errors)
    _links(value["finding_records"], "finding_records", errors)


VALIDATORS = {
    SCHEMA_VERSIONS["ledger"]: _validate_ledger,
    SCHEMA_VERSIONS["artifact_record"]: _validate_artifact_record,
    SCHEMA_VERSIONS["test_run_record"]: _validate_test_run,
    SCHEMA_VERSIONS["experiment_unit"]: _validate_experiment_unit,
    SCHEMA_VERSIONS["metric_definition"]: _validate_metric_definition,
    SCHEMA_VERSIONS["metric_population_manifest"]: _validate_metric_population_manifest,
    SCHEMA_VERSIONS["metric_record"]: _validate_metric_record,
    SCHEMA_VERSIONS["claim_record"]: _validate_claim,
    SCHEMA_VERSIONS["claim_gate_report"]: _validate_gate_report,
    SCHEMA_VERSIONS["finding_ledger"]: _validate_finding_ledger,
}


def validate_document(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return ["$: expected object"]
    schema = str(value.get("schema_version") or "")
    validator = VALIDATORS.get(schema)
    if validator is None:
        return ["schema_version: unsupported"]
    errors = semantic_safety_errors(value)
    validator(value, errors)
    id_field = ID_FIELDS[schema]
    if isinstance(value.get(id_field), str):
        try:
            if value[id_field] != semantic_id(value):
                errors.append(f"{id_field}: canonical identity mismatch")
        except (TypeError, ValueError) as exc:
            errors.append(f"{id_field}: {exc}")
    return sorted(dict.fromkeys(errors))


def validate_document_or_raise(value: Any) -> None:
    errors = validate_document(value)
    if errors:
        schema = value.get("schema_version", "evidence") if isinstance(value, Mapping) else "evidence"
        raise EvaluationEvidenceError(str(schema), errors)


def validate_finding_record_or_raise(value: Any) -> None:
    errors = semantic_safety_errors(value)
    _validate_finding(value, "$", errors)
    if errors:
        raise EvaluationEvidenceError("security_finding_record", errors)


def _rule_all() -> dict[str, Any]:
    return {"kind": "ALL", "predicates": []}


def _rule_none() -> dict[str, Any]:
    return {"kind": "NONE", "predicates": []}


def _rule_eq(field: str, value: str) -> dict[str, Any]:
    return {"kind": "FILTER", "predicates": [{"field": field, "comparator": "EQ", "value": value}]}


def _metric_definition(
    name: str,
    population_unit: str,
    artifact_type: str,
    rq: str,
    *,
    ratio_status: str | None = None,
    allowed_origins: tuple[str, ...] = (EvidenceOrigin.CURRENT_V2.value,),
) -> dict[str, Any]:
    ratio = ratio_status is not None
    value = {
        "schema_version": SCHEMA_VERSIONS["metric_definition"],
        "metric_definition_id": "pending",
        "metric_name": name,
        "definition_version": "0.1",
        "research_question_refs": [rq],
        "population_unit": population_unit,
        "selection_rule": _rule_all(),
        "numerator_rule": _rule_eq("attributes.status", ratio_status) if ratio else _rule_all(),
        "denominator_rule": _rule_all() if ratio else _rule_none(),
        "aggregation_rule": "RATIO" if ratio else "COUNT",
        "required_artifact_types": [artifact_type],
        "allowed_origins": list(allowed_origins),
        "allowed_claim_levels": [
            ClaimTaxonomy.ENGINEERING_VALIDATION_CLAIM.value,
            ClaimTaxonomy.PIPELINE_VALIDATION_CLAIM.value,
            ClaimTaxonomy.CURRENT_CAMPAIGN_RESULT_CLAIM.value,
        ],
        "presentation_rule": {"format": "PERCENTAGE" if ratio else "INTEGER", "scale": 100 if ratio else 1, "decimals": 2 if ratio else 0},
        "forbidden_interpretations": [
            "A count is not a vulnerability confirmation",
            "A witness-level metric is not a global library-security conclusion",
        ],
    }
    return identify(value)


_METRIC_SPECS = {
    "schema_count": ("SCHEMA_DOCUMENT", "schema_document", "RQ-ENG", None),
    "test_definition_count": ("TEST_DEFINITION", "test_definition", "RQ-ENG", None),
    "recorded_test_run_count": ("TEST_RUN", "test_run_record", "RQ-ENG", None),
    "golden_fixture_count": ("GOLDEN_FIXTURE", "golden_fixture", "RQ-ENG", None),
    "synthetic_e2e_record_count": ("SYNTHETIC_E2E_RUN", "synthetic_e2e_record", "RQ-ENG", None),
    "artifact_digest_validation_count": ("ARTIFACT", "artifact_record", "RQ-ENG", None),
    "trigger_template_count": ("TRIGGER_TEMPLATE", "trigger_template", "RQ1", None),
    "stable_slot_count": ("TEMPLATE_SLOT", "trigger_template", "RQ1", None),
    "required_slot_coverage": ("REQUIRED_SLOT", "merge_validation", "RQ1", "FILLED"),
    "structural_obligation_count": ("STRUCTURAL_OBLIGATION", "trigger_template", "RQ1", None),
    "merge_slot_coverage": ("MERGE_SLOT", "merge_validation", "RQ1", "FILLED"),
    "protected_region_preservation_rate": ("PROTECTED_REGION", "merge_validation", "RQ1", "PRESERVED"),
    "transfer_signature_count": ("TRANSFER_SIGNATURE", "transfer_signature", "RQ2", None),
    "target_profile_count": ("TARGET_PROFILE", "target_semantic_profile", "RQ2", None),
    "eligibility_evaluation_count": ("ELIGIBILITY_EVALUATION", "ts_evaluation", "RQ2", None),
    "candidate_surface_count": ("CANDIDATE_SURFACE", "matcher_trace", "RQ2", None),
    "candidate_binding_count": ("CANDIDATE_BINDING", "candidate_binding", "RQ2", None),
    "valid_binding_count": ("BINDING_VALIDATION", "candidate_binding_validation", "RQ2", "VALID"),
    "ineligible_filter_count": ("ELIGIBILITY_EVALUATION", "ts_evaluation", "RQ2", "INELIGIBLE"),
    "indeterminate_evidence_gap_count": ("ELIGIBILITY_EVALUATION", "ts_evaluation", "RQ2", "INDETERMINATE"),
    "proposal_to_verified_fact_rate": ("PROPOSED_FACT", "binding_proposal", "RQ2", "VERIFIED"),
    "execution_witness_count": ("EXECUTION_WITNESS", "execution_witness", "RQ3", None),
    "structured_trace_count": ("STRUCTURED_TRACE", "structured_execution_trace", "RQ3", None),
    "relation_evaluation_count": ("RELATION_EVALUATION", "relation_evaluation", "RQ3", None),
    "satisfied_witness_count": ("EXECUTION_VERDICT", "execution_verdict", "RQ3", "SATISFIED"),
    "violated_witness_count": ("EXECUTION_VERDICT", "execution_verdict", "RQ3", "VIOLATED"),
    "unknown_witness_count": ("EXECUTION_VERDICT", "execution_verdict", "RQ3", "UNKNOWN"),
    "unknown_closure_route_count": ("EXECUTION_CLOSURE", "execution_closure", "RQ3", None),
    "violation_package_count": ("VIOLATION_PACKAGE", "violation_package", "RQ3", None),
    "campaign_attempt_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", None),
    "matcher_no_match_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", "MATCHER_NO_MATCH"),
    "merge_failure_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", "MERGE_FAILURE"),
    "build_failure_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", "BUILD_FAILURE"),
    "run_launch_failure_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", "RUN_LAUNCH_FAILURE"),
    "invalid_witness_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", "INVALID_WITNESS"),
    "evidence_exhausted_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", "EVIDENCE_EXHAUSTED"),
    "budget_exhausted_count": ("CAMPAIGN_ATTEMPT", "campaign_attempt", "RQ4", "BUDGET_EXHAUSTED"),
    "reproduced_n_day_count": ("SECURITY_FINDING", "security_finding", "RQ4", "REPRODUCED_RELATION_BEHAVIOR"),
    "v2_violated_witness_count": ("SECURITY_FINDING", "security_finding", "RQ4", "V2_VIOLATED_WITNESS"),
    "impact_analyzed_count": ("SECURITY_FINDING", "security_finding", "RQ4", "IMPACT_ANALYZED"),
    "upstream_reported_count": ("SECURITY_FINDING", "security_finding", "RQ4", "REPORTED_UPSTREAM"),
    "upstream_acknowledged_count": ("SECURITY_FINDING", "security_finding", "RQ4", "UPSTREAM_ACKNOWLEDGED"),
    "fixed_count": ("SECURITY_FINDING", "security_finding", "RQ4", "FIX_CONFIRMED"),
    "cve_or_advisory_confirmed_count": ("SECURITY_FINDING", "security_finding", "RQ4", "CVE_OR_ADVISORY_CONFIRMED"),
}


INITIAL_METRIC_REGISTRY = {
    name: _metric_definition(name, population, artifact, rq, ratio_status=status)
    for name, (population, artifact, rq, status) in sorted(_METRIC_SPECS.items())
}


def metric_registry_snapshot() -> dict[str, Any]:
    return {
        "registry_version": METRIC_REGISTRY_VERSION,
        "definitions": [deepcopy(INITIAL_METRIC_REGISTRY[name]) for name in sorted(INITIAL_METRIC_REGISTRY)],
    }

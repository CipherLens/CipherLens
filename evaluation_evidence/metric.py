"""Deterministic experiment-unit construction and metric recomputation."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Callable, Iterable, Mapping

from evaluation_evidence.canonical import canonical_bytes, canonical_json_bytes, identify
from evaluation_evidence.lineage import validate_link, verify_link
from evaluation_evidence.model import EvidenceOrigin, RecomputeStatus, SCHEMA_VERSIONS
from evaluation_evidence.registry import validate_document_or_raise


class MetricEvaluationError(ValueError):
    pass


def build_experiment_unit(
    *, research_question_refs: Iterable[str], unit_type: str,
    target_scope: Mapping[str, str], input_refs: Iterable[Mapping[str, str]],
    attempt_refs: Iterable[Mapping[str, str]], output_refs: Iterable[Mapping[str, str]],
    inclusion_status: str, completion_status: str, origin: EvidenceOrigin | str,
    notes: Iterable[str] = (),
) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSIONS["experiment_unit"],
        "experiment_unit_id": "pending",
        "research_question_refs": list(research_question_refs),
        "unit_type": unit_type,
        "target_scope": dict(target_scope),
        "input_refs": [dict(item) for item in input_refs],
        "attempt_refs": [dict(item) for item in attempt_refs],
        "output_refs": [dict(item) for item in output_refs],
        "inclusion_status": inclusion_status,
        "completion_status": completion_status,
        "origin": origin.value if isinstance(origin, EvidenceOrigin) else origin,
        "notes": list(notes),
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result


def _field(item: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = item
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _predicate_matches(item: Mapping[str, Any], predicate: Mapping[str, Any]) -> bool:
    present, actual = _field(item, str(predicate["field"]))
    comparator = predicate["comparator"]
    expected = predicate["value"]
    if comparator == "EXISTS":
        return present is bool(expected)
    if not present:
        return False
    if comparator == "EQ":
        return actual == expected
    if comparator == "NE":
        return actual != expected
    if comparator == "IN":
        return actual in expected
    raise MetricEvaluationError(f"unsupported comparator: {comparator}")


def _apply_rule(items: list[dict[str, Any]], rule: Mapping[str, Any]) -> list[dict[str, Any]]:
    if rule["kind"] == "ALL":
        return list(items)
    if rule["kind"] == "NONE":
        return []
    if rule["kind"] == "FILTER":
        return [item for item in items if all(_predicate_matches(item, predicate) for predicate in rule["predicates"])]
    raise MetricEvaluationError(f"unsupported rule kind: {rule['kind']}")


def _rule_digest(rule: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(rule)).hexdigest()


def _item_link(item: Mapping[str, Any]) -> dict[str, str]:
    return dict(item["artifact"])


def _validate_population_item(item: Any, index: int) -> None:
    if not isinstance(item, Mapping):
        raise MetricEvaluationError(f"population[{index}]: expected object")
    expected = {"artifact", "artifact_type", "origin", "attributes"}
    if set(item) != expected:
        raise MetricEvaluationError(f"population[{index}]: expected exactly {sorted(expected)}")
    errors = validate_link(item.get("artifact"), f"population[{index}].artifact")
    if errors:
        raise MetricEvaluationError("; ".join(errors))
    if not isinstance(item["artifact_type"], str) or not isinstance(item["attributes"], Mapping):
        raise MetricEvaluationError(f"population[{index}]: invalid artifact_type or attributes")
    if set(item["attributes"]) != {"status"}:
        raise MetricEvaluationError(f"population[{index}].attributes: expected exactly status")
    if item["origin"] not in {origin.value for origin in EvidenceOrigin}:
        raise MetricEvaluationError(f"population[{index}]: invalid origin")


def build_population_manifest(
    definition: Mapping[str, Any], population: Iterable[Mapping[str, Any]], *,
    origin: EvidenceOrigin | str, complete: bool,
) -> dict[str, Any]:
    validate_document_or_raise(definition)
    origin_value = origin.value if isinstance(origin, EvidenceOrigin) else origin
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(population):
        item = dict(raw)
        if set(item) != {"ref", "digest", "artifact_type", "origin", "attributes"}:
            raise MetricEvaluationError(f"population[{index}]: invalid input shape")
        attributes = dict(item["attributes"])
        if set(attributes) - {"status"}:
            raise MetricEvaluationError(f"population[{index}].attributes: unknown field")
        normalized.append({
            "artifact": {"ref": item["ref"], "digest": item["digest"]},
            "artifact_type": item["artifact_type"], "origin": item["origin"],
            "attributes": {"status": attributes.get("status")},
        })
    normalized.sort(key=lambda item: (item["artifact"]["ref"], item["artifact"]["digest"]))
    value = {
        "schema_version": SCHEMA_VERSIONS["metric_population_manifest"],
        "population_manifest_id": "pending", "population_unit": definition["population_unit"],
        "origin": origin_value, "complete": bool(complete), "items": normalized,
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result


def population_manifest_link(manifest: Mapping[str, Any]) -> dict[str, str]:
    validate_document_or_raise(manifest)
    return {
        "ref": f"metric-population:{manifest['population_manifest_id']}",
        "digest": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
    }


def evaluate_metric(
    definition: Mapping[str, Any], population_manifest: Mapping[str, Any], *,
    resolver: Callable[[str, str], bool], git_revision: str,
    experiment_unit_refs: Iterable[Mapping[str, str]] = (),
    ledger: Mapping[str, str] | None = None,
    producer_id: str = "deterministic-metric-evaluator", producer_version: str = "0.1",
) -> dict[str, Any]:
    """Recompute a metric solely from digest-verified population items."""
    validate_document_or_raise(definition)
    if definition["schema_version"] != SCHEMA_VERSIONS["metric_definition"]:
        raise MetricEvaluationError("definition is not a MetricDefinition")
    validate_document_or_raise(population_manifest)
    if population_manifest["schema_version"] != SCHEMA_VERSIONS["metric_population_manifest"]:
        raise MetricEvaluationError("expected a MetricPopulationManifest")
    manifest_link = population_manifest_link(population_manifest)
    if not verify_link(manifest_link, resolver):
        raise MetricEvaluationError("population manifest is missing or has an invalid digest")
    if population_manifest["population_unit"] != definition["population_unit"]:
        raise MetricEvaluationError("population unit does not match metric definition")
    origin_value = population_manifest["origin"]
    if origin_value not in definition["allowed_origins"]:
        raise MetricEvaluationError("metric definition does not allow this evidence origin")
    items = [deepcopy(dict(item)) for item in population_manifest["items"]]
    unit_links = [dict(item) for item in experiment_unit_refs]
    for link in unit_links:
        if validate_link(link, "experiment_unit_ref") or not verify_link(link, resolver):
            raise MetricEvaluationError("experiment unit ref is missing or digest-invalid")
    if ledger is not None and (validate_link(ledger, "ledger") or not verify_link(ledger, resolver)):
        raise MetricEvaluationError("ledger ref is missing or digest-invalid")
    for index, item in enumerate(items):
        _validate_population_item(item, index)
        if item["origin"] != origin_value:
            raise MetricEvaluationError("mixed or masquerading evidence origin")
        if item["artifact_type"] not in definition["required_artifact_types"]:
            raise MetricEvaluationError("population contains an unsupported artifact type")
        if not resolver(str(item["artifact"]["ref"]), str(item["artifact"]["digest"])):
            raise MetricEvaluationError("population artifact digest could not be verified")
    items.sort(key=lambda item: (str(item["artifact"]["ref"]), str(item["artifact"]["digest"])))
    selected = _apply_rule(items, definition["selection_rule"])
    numerator = _apply_rule(selected, definition["numerator_rule"])
    denominator = _apply_rule(selected, definition["denominator_rule"])
    if definition["aggregation_rule"] == "RATIO":
        if not denominator:
            raise MetricEvaluationError("ratio denominator is missing")
        denominator_keys = {(item["artifact"]["ref"], item["artifact"]["digest"]) for item in denominator}
        if any((item["artifact"]["ref"], item["artifact"]["digest"]) not in denominator_keys for item in numerator):
            raise MetricEvaluationError("numerator is not a subset of denominator")
    elif definition["aggregation_rule"] != "COUNT":
        raise MetricEvaluationError("unsupported aggregation rule")
    population_complete = population_manifest["complete"]
    status = RecomputeStatus.RECOMPUTABLE if population_complete else RecomputeStatus.PARTIALLY_RECOMPUTABLE
    definition_link = {
        "ref": f"metric-definition:{definition['metric_definition_id']}",
        "digest": hashlib.sha256(canonical_bytes(definition)).hexdigest(),
    }
    derived = {
        "kind": definition["aggregation_rule"],
        "numerator": len(numerator),
        "denominator": len(denominator),
    }
    trace = [
        {"step": "selection", "input_count": len(items), "output_count": len(selected), "rule_digest": _rule_digest(definition["selection_rule"])},
        {"step": "numerator", "input_count": len(selected), "output_count": len(numerator), "rule_digest": _rule_digest(definition["numerator_rule"])},
        {"step": "denominator", "input_count": len(selected), "output_count": len(denominator), "rule_digest": _rule_digest(definition["denominator_rule"])},
    ]
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSIONS["metric_record"], "metric_record_id": "pending",
        "metric_definition": definition_link, "population_manifest": manifest_link,
        "experiment_unit_refs": unit_links,
        "numerator_refs": [_item_link(item) for item in numerator],
        "denominator_refs": [_item_link(item) for item in denominator],
        "numerator_value": len(numerator), "denominator_value": len(denominator),
        "derived_value": derived, "origin": origin_value,
        "population_complete": bool(population_complete), "all_source_digests_valid": True,
        "recompute_status": status.value, "recompute_trace": trace,
        "caveats": [] if population_complete else ["Population manifest is explicitly incomplete"],
        "producer": {"producer_id": producer_id, "producer_version": producer_version},
        "git_revision": git_revision, "registry_version": "cipherlens.evaluation_evidence_registry.v0.1",
    }
    if ledger is not None:
        value["ledger"] = dict(ledger)
    result = identify(value)
    validate_document_or_raise(result)
    return result


def is_formal_current_v2_metric(record: Mapping[str, Any]) -> bool:
    validate_document_or_raise(record)
    return (
        record["origin"] == EvidenceOrigin.CURRENT_V2.value
        and record["recompute_status"] == RecomputeStatus.RECOMPUTABLE.value
        and record["population_complete"] is True
        and record["all_source_digests_valid"] is True
    )

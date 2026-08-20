"""Deterministic C1 executable-source completion over frozen byte ranges."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from target_knowledge.canonical import canonical_json_bytes


RENDERER_ID = "cipherlens.c1_executable_bound_source_renderer"
RENDERER_VERSION = "v0.1"
BASE_SOURCE_DIGEST = "ebc9cec8fe314ede00da8aa9b1f11074a192e226eb360e1849e88cd440b0ff3f"
CAPTURE_REGION_REF = "region:c1-overlay:oracle-event-capture"
CAPTURE_LOCATION_REF = "source-location:c1fix10:after-operation-0"
CAPTURE_OFFSET = 7913
CAPTURE_ANCHOR_START = 7838
CAPTURE_ANCHOR_DIGEST = "2f9418a257b4e6d6c3d0e701eca40fad93b25a19e8bd84c01acc9a9506dcec80"


_HOLES = {
    "hole:DER_KIND": {
        "byte_start": 1315,
        "byte_end": 1325,
        "source_digest": "4d523cad98e87040a893ac6897c1f3c639975f5e30ba7bb00f17f4e809972eac",
        "value": "private",
    },
    "hole:PARSE_API_KIND": {
        "byte_start": 1357,
        "byte_end": 1373,
        "source_digest": "7ee5603b49b86ed198a37fef347c36ed1b4d097fbc53b652bb686d86b3003c65",
        "value": "rsa_private",
    },
    "hole:TRAILING_GARBAGE_BYTES": {
        "byte_start": 1405,
        "byte_end": 1429,
        "source_digest": "507096aa4d2a4790ed2983d845155d433192a71e9912cd952061c56cf959da15",
        "value": "020100",
    },
    "hole:TRAILING_GARBAGE_LEN": {
        "byte_start": 1479,
        "byte_end": 1501,
        "source_digest": "61ef5ea06da1ffdbfe85f56ff1d9a4d74ff5d4ecb9c2466e56f73b82291c1b86",
        "value": 3,
    },
    "hole:EXPECT_RET": {
        "byte_start": 1533,
        "byte_end": 1545,
        "source_digest": "12331e156f0de9b5f1634e21a78aebdafc50f20cc5e6a472a9b513cb82cdb1e2",
        "value": "MBEDTLS_ERR_RSA_BAD_INPUT_DATA",
    },
}
_ROLE_ORDER = {"operation_outcome": 0, "consumed_length": 1, "input_length": 2}


class ExecutableCompletionBlocked(ValueError):
    pass


@dataclass(frozen=True)
class ExecutableCompletion:
    source_bytes: bytes
    protected_regions: tuple[dict[str, Any], ...]
    generated_regions: tuple[dict[str, Any], ...]
    hole_records: tuple[dict[str, Any], ...]
    capture_records: tuple[dict[str, Any], ...]


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_digested(item: Mapping[str, Any]) -> None:
    payload = {key: value for key, value in item.items() if key != "digest"}
    if item.get("digest") != _digest(payload):
        raise ExecutableCompletionBlocked("RESOLVED_VALUE_DIGEST_MISMATCH")


def _json_c_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _capture_payload(
    item: Mapping[str, Any],
    merge_capture: Mapping[str, Any],
    observation: Mapping[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    role = item["semantic_role"]
    common = {
        "protocol_version": "0.1",
        "capture_binding_ref": item["capture_binding_ref"],
        "contract_observable_ref": merge_capture["contract_observable_ref"],
        "observation_binding_ref": item["observation_binding_ref"],
        "semantic_role": role,
        "acquisition_kind": item["acquisition_kind"],
        "phase": item["phase"],
        "subject_ref": merge_capture["target_subject_binding_ref"],
        "operation_ref": merge_capture["target_operation_binding_ref"],
        "correlation_group_ref": merge_capture["correlation_refs"][0],
        "status": "PRESENT",
        "value_type": observation["value_type"],
        "value": None,
        "sequence_index": _ROLE_ORDER[role],
    }
    if role == "operation_outcome":
        common["value"] = "__RUNTIME_OUTCOME__"
        encoded = json.dumps(common, sort_keys=True, separators=(",", ":"))
        encoded = encoded.replace('"__RUNTIME_OUTCOME__"', '"%s"')
        arguments = ', ret == 0 ? "success" : "failure"'
        acquisition = "RETURN_VALUE_NORMALIZED"
    elif role == "input_length":
        common["value"] = "__RUNTIME_INPUT_LENGTH__"
        encoded = json.dumps(common, sort_keys=True, separators=(",", ":"))
        encoded = encoded.replace('"__RUNTIME_INPUT_LENGTH__"', "%zu")
        arguments = ", der_len"
        acquisition = "BOUND_VALUE"
    elif role == "consumed_length":
        common["status"] = "ACQUISITION_FAILED"
        encoded = json.dumps(common, sort_keys=True, separators=(",", ":"))
        arguments = ""
        acquisition = "POINTER_DELTA_UNAVAILABLE"
    else:
        raise ExecutableCompletionBlocked("UNSUPPORTED_CAPTURE_SEMANTIC_ROLE")
    c_json = _json_c_string(encoded)
    source = f'    printf("CIPHERLENS_CAPTURE_V0_1 {c_json}\\n"{arguments});\n'.encode("utf-8")
    record = {
        "capture_region_ref": item["capture_region_ref"],
        "source_location_ref": CAPTURE_LOCATION_REF,
        "emitter_ref": item["emitter_ref"],
        "emitter_digest": item["emitter_digest"],
        "observation_binding_ref": item["observation_binding_ref"],
        "semantic_role": role,
        "acquisition_kind": item["acquisition_kind"],
        "phase": item["phase"],
        "runtime_acquisition": acquisition,
        "target_payload_digest": hashlib.sha256(source).hexdigest(),
    }
    record["digest"] = _digest(record)
    return source, record


def render_executable_bound_source(
    base_source: bytes,
    resolved_values: Mapping[str, Any],
    capture_materialization: Mapping[str, Any],
    merge: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
) -> ExecutableCompletion:
    """Complete only registered ranges; all remaining bytes stay protected."""
    if hashlib.sha256(base_source).hexdigest() != BASE_SOURCE_DIGEST:
        raise ExecutableCompletionBlocked("BASE_SOURCE_DIGEST_MISMATCH")
    if resolved_values.get("status") != "READY":
        raise ExecutableCompletionBlocked("EXECUTION_BLOCKING_HOLE_UNRESOLVED")
    values = {item.get("hole_ref"): item for item in resolved_values.get("resolved_values", [])}
    if set(values) != set(_HOLES):
        raise ExecutableCompletionBlocked("EXECUTION_BLOCKING_HOLE_SET_MISMATCH")
    for hole_ref, registry in _HOLES.items():
        item = values[hole_ref]
        _validate_digested(item)
        if item.get("resolved_value") != registry["value"]:
            raise ExecutableCompletionBlocked("SEMANTIC_CHOICE_CHANGE_REQUIRES_WHOLE_BINDING_SWITCH")
        source_slice = base_source[registry["byte_start"]:registry["byte_end"]]
        if hashlib.sha256(source_slice).hexdigest() != registry["source_digest"]:
            raise ExecutableCompletionBlocked("REGISTERED_HOLE_SOURCE_DIGEST_MISMATCH")

    anchor = base_source[CAPTURE_ANCHOR_START:CAPTURE_OFFSET]
    if hashlib.sha256(anchor).hexdigest() != CAPTURE_ANCHOR_DIGEST:
        raise ExecutableCompletionBlocked("CAPTURE_INSERTION_ANCHOR_DIGEST_MISMATCH")
    if capture_materialization.get("status") != "READY":
        raise ExecutableCompletionBlocked("DECLARED_CAPTURE_REGION_NOT_READY")
    capture_items = capture_materialization.get("capture_bindings", [])
    if {item.get("semantic_role") for item in capture_items} != set(_ROLE_ORDER):
        raise ExecutableCompletionBlocked("DECLARED_CAPTURE_ROLE_SET_MISMATCH")
    if any(item.get("capture_region_ref") != CAPTURE_REGION_REF for item in capture_items):
        raise ExecutableCompletionBlocked("CAPTURE_INSERTION_OUTSIDE_DECLARED_REGION")

    merge_captures = {
        item["capture_binding_id"]: item
        for item in merge.get("observation_capture_bindings", [])
    }
    observations = {
        item["observation_binding_id"]: item
        for item in candidate_binding.get("observation_bindings", [])
    }
    capture_source = bytearray()
    capture_records: list[dict[str, Any]] = []
    for item in sorted(capture_items, key=lambda value: _ROLE_ORDER[value["semantic_role"]]):
        merge_capture = merge_captures.get(item["capture_binding_ref"])
        observation = observations.get(item["observation_binding_ref"])
        if merge_capture is None or observation is None:
            raise ExecutableCompletionBlocked("CAPTURE_LINEAGE_MISMATCH")
        source, record = _capture_payload(item, merge_capture, observation)
        capture_source.extend(source)
        capture_records.append(record)

    operations = [
        (registry["byte_start"], registry["byte_end"], str(values[hole_ref]["resolved_value"]).encode("utf-8"), "hole", hole_ref)
        for hole_ref, registry in _HOLES.items()
    ]
    operations.append((CAPTURE_OFFSET, CAPTURE_OFFSET, bytes(capture_source), "capture", CAPTURE_REGION_REF))
    operations.sort(key=lambda item: (item[0], item[1]))

    output = bytearray()
    protected: list[dict[str, Any]] = []
    generated: list[dict[str, Any]] = []
    hole_records: list[dict[str, Any]] = []
    cursor = 0
    for index, (start, end, replacement, kind, ref) in enumerate(operations):
        if start < cursor:
            raise ExecutableCompletionBlocked("REGISTERED_COMPLETION_RANGE_OVERLAP")
        if start > cursor:
            chunk = base_source[cursor:start]
            out_start = len(output)
            output.extend(chunk)
            protected.append({
                "region_ref": f"protected-region:{len(protected):04d}",
                "base_byte_start": cursor,
                "base_byte_end": start,
                "output_byte_start": out_start,
                "output_byte_end": len(output),
                "digest": hashlib.sha256(chunk).hexdigest(),
                "protected": True,
            })
        out_start = len(output)
        output.extend(replacement)
        region = {
            "region_ref": f"generated-region:{index:04d}",
            "region_kind": "CAPTURE_PROTOCOL" if kind == "capture" else "RESOLVED_TEMPLATE_VALUE",
            "semantic_ref": ref,
            "base_byte_start": start,
            "base_byte_end": end,
            "output_byte_start": out_start,
            "output_byte_end": len(output),
            "digest": hashlib.sha256(replacement).hexdigest(),
            "protected": False,
        }
        generated.append(region)
        if kind == "hole":
            value = values[ref]
            hole_records.append({
                "hole_ref": ref,
                "resolved_value": value["resolved_value"],
                "source_refs": list(value["source_refs"]),
                "source_digests": list(value["source_digests"]),
                "resolver_id": value["resolver_id"],
                "resolver_version": value["resolver_version"],
                "derivation_rule": value["derivation_rule"],
                "generated_region_ref": region["region_ref"],
                "generated_region_digest": region["digest"],
            })
        cursor = end
    if cursor < len(base_source):
        chunk = base_source[cursor:]
        out_start = len(output)
        output.extend(chunk)
        protected.append({
            "region_ref": f"protected-region:{len(protected):04d}",
            "base_byte_start": cursor,
            "base_byte_end": len(base_source),
            "output_byte_start": out_start,
            "output_byte_end": len(output),
            "digest": hashlib.sha256(chunk).hexdigest(),
            "protected": True,
        })
    return ExecutableCompletion(
        source_bytes=bytes(output),
        protected_regions=tuple(protected),
        generated_regions=tuple(generated),
        hole_records=tuple(hole_records),
        capture_records=tuple(capture_records),
    )

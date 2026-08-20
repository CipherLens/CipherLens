"""Declared-region gate for fact-only RuntimeEvent capture."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from trigger_template_interface.capture_region import validate_declared_capture_region


CAPTURE_REGION_REF = "region:c1-overlay:oracle-event-capture"
_REQUIRED = {
    "capture_binding_id",
    "observation_binding_ref",
    "semantic_role",
    "acquisition_kind",
    "phase",
}


def capture_emitter_binding(
    capture: Mapping[str, Any],
    source_map_regions: Sequence[Mapping[str, Any]],
    *,
    emitter_ref: str = "runtime_event:emit_runtime_event_v0_1",
) -> dict[str, Any]:
    """Bind one declared observation capture only to a writable declared region.

    The C1 overlay names ``CAPTURE_REGION_REF``.  It is intentionally not
    interchangeable with an existing protected SourceMap region.
    """
    missing = sorted(_REQUIRED - set(capture))
    if missing:
        raise ValueError("capture binding missing fields: " + ", ".join(missing))
    region = next((
        item for item in source_map_regions
        if item.get("capture_region_id", item.get("region_id")) == CAPTURE_REGION_REF
        and item.get("protected") is False
    ), None)
    common = {
        "capture_id": capture["capture_binding_id"],
        "observation_binding_ref": capture["observation_binding_ref"],
        "source_region_ref": CAPTURE_REGION_REF,
        "emitter_ref": emitter_ref,
        "semantic_role": capture["semantic_role"],
        "acquisition_kind": capture["acquisition_kind"],
        "phase": capture["phase"],
    }
    if region is None:
        return {
            "status": "MISSING_DECLARED_CAPTURE_REGION",
            "reason_code": "MISSING_DECLARED_CAPTURE_REGION",
            "declared_region_found": False,
            **common,
        }
    if "capture_region_id" in region:
        validate_declared_capture_region(region)
        if capture["semantic_role"] not in region["semantic_roles"]:
            raise ValueError("semantic role is not allowed by declared capture region")
        if capture["phase"] != region["phase"]:
            raise ValueError("capture phase does not match declared capture region")
    return {"status": "READY", "declared_region_found": True, **common}

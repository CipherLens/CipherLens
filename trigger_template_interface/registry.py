"""Small, evidence-backed legacy-role compatibility registry."""

from __future__ import annotations

from trigger_template_interface.model import SlotKind


ROLE_TO_SLOT_KIND = {
    "trigger_call": SlotKind.OPERATION,
    "mutation_point": SlotKind.INPUT,
    "oracle": SlotKind.OBSERVATION,
    "input_preparation": SlotKind.INPUT,
    "helper_function": SlotKind.ORDER_ANCHOR,
    "cleanup": SlotKind.ORDER_ANCHOR,
}


def infer_slot_kind(unit: dict[str, object]) -> SlotKind | None:
    """Map only legacy roles for which the repository has direct evidence."""

    role = unit.get("role")
    if role == "mutation_point":
        name = str(unit.get("mutation_name") or unit.get("name") or "").upper()
        if "STATE" in name:
            return SlotKind.STATE_ANCHOR
        if "INTERVENTION" in name or "TRAILING" in name or "PADDING" in name:
            return SlotKind.INTERVENTION
    return ROLE_TO_SLOT_KIND.get(str(role))

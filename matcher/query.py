"""Deterministic wide-recall query construction."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from matcher.model import RECALL_QUERY_SCHEMA_VERSION, canonical_json_bytes, semantic_digest


@dataclass(frozen=True)
class RecallQuery:
    schema_version: str
    query_id: str
    contract_context: Mapping[str, Any]
    contract_intervention: Mapping[str, Any]
    contract_execution: Mapping[str, Any]
    contract_observability: Mapping[str, Any]
    controlled_relation_hints: tuple[str, ...]
    required_capabilities: tuple[Mapping[str, Any], ...]
    excluded_semantics: tuple[Mapping[str, Any], ...]
    required_observability: tuple[Mapping[str, Any], ...]
    template_slot_hints: tuple[Mapping[str, Any], ...]
    family_metadata: Mapping[str, Any]

    def semantic_dict(self, *, include_id: bool = True) -> dict[str, Any]:
        result = {
            "schema_version": self.schema_version,
            "contract_context": deepcopy(dict(self.contract_context)),
            "contract_intervention": deepcopy(dict(self.contract_intervention)),
            "contract_execution": deepcopy(dict(self.contract_execution)),
            "contract_observability": deepcopy(dict(self.contract_observability)),
            "controlled_relation_hints": list(self.controlled_relation_hints),
            "required_capabilities": [deepcopy(dict(x)) for x in self.required_capabilities],
            "excluded_semantics": [deepcopy(dict(x)) for x in self.excluded_semantics],
            "required_observability": [deepcopy(dict(x)) for x in self.required_observability],
            "template_slot_hints": [deepcopy(dict(x)) for x in self.template_slot_hints],
            "family_metadata": deepcopy(dict(self.family_metadata)),
        }
        if include_id:
            result["query_id"] = self.query_id
        return result

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.semantic_dict())

    def digest(self) -> str:
        return semantic_digest(self.semantic_dict())


def build_recall_query(
    contract: Mapping[str, Any],
    transfer_signature: Mapping[str, Any],
    template_manifest: Mapping[str, Any],
    *,
    family_metadata: Mapping[str, Any] | None = None,
) -> RecallQuery:
    """Build a query without turning Contract.P prose into truth."""

    relation_hints: set[str] = set()
    expected = contract.get("expected_relation", {})
    for relation in expected.get("relations", []) if isinstance(expected, Mapping) else []:
        if isinstance(relation, Mapping):
            if isinstance(relation.get("type"), str):
                relation_hints.add(relation["type"])
            operands = relation.get("operands", {})
            if isinstance(operands, Mapping):
                relation_hints.update(str(key) for key in operands)

    slots = []
    for slot in template_manifest.get("slots", []):
        if not isinstance(slot, Mapping):
            continue
        slots.append(
            {
                "slot_ref": slot.get("slot_ref"),
                "slot_kind": slot.get("slot_kind"),
                "semantic_role_hint": slot.get("semantic_role_hint"),
                "required": slot.get("required"),
                "multiplicity": slot.get("multiplicity"),
            }
        )

    semantic = {
        "schema_version": RECALL_QUERY_SCHEMA_VERSION,
        "contract_context": deepcopy(dict(contract.get("context", {}))),
        "contract_intervention": deepcopy(dict(contract.get("intervention", {}))),
        "contract_execution": deepcopy(dict(contract.get("execution", {}))),
        "contract_observability": deepcopy(dict(contract.get("observable_evidence", {}))),
        "controlled_relation_hints": sorted(relation_hints),
        "required_capabilities": sorted(
            (deepcopy(dict(x)) for x in transfer_signature.get("required_capabilities", [])),
            key=lambda x: str(x.get("constraint_id", "")),
        ),
        "excluded_semantics": sorted(
            (deepcopy(dict(x)) for x in transfer_signature.get("excluded_semantics", [])),
            key=lambda x: str(x.get("constraint_id", "")),
        ),
        "required_observability": sorted(
            (deepcopy(dict(x)) for x in transfer_signature.get("required_observability", [])),
            key=lambda x: str(x.get("constraint_id", "")),
        ),
        "template_slot_hints": sorted(slots, key=lambda x: str(x.get("slot_ref", ""))),
        "family_metadata": deepcopy(dict(family_metadata or {})),
    }
    query_id = "recall-query:" + semantic_digest(semantic)
    return RecallQuery(
        query_id=query_id,
        **{
            **semantic,
            "controlled_relation_hints": tuple(semantic["controlled_relation_hints"]),
            "required_capabilities": tuple(semantic["required_capabilities"]),
            "excluded_semantics": tuple(semantic["excluded_semantics"]),
            "required_observability": tuple(semantic["required_observability"]),
            "template_slot_hints": tuple(semantic["template_slot_hints"]),
        },
    )

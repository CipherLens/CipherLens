"""Family-scoped, evidence-guided deterministic Contract miner."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import yaml

from contract_miner.divergence import validate_divergence_or_raise
from contract_miner.family_rules import RULE_IDS, apply_family_rule
from contract_miner.schema import canonical_vc_bytes, validate_vc_or_raise


MINING_INPUT_VERSION = "cipherlens.mining_input.v0_1"


class MiningInputError(ValueError):
    pass


def load_mining_input(path: str | Path) -> Any:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def mine_contract(mining_input: Mapping[str, Any], divergence: Mapping[str, Any], repo_root: str | Path | None = None) -> dict[str, Any]:
    """Mine one canonical Contract without LLM or target-library reasoning."""
    _validate_mining_input(mining_input)
    validate_divergence_or_raise(divergence)
    source = mining_input["source"]
    pair = divergence["source_pair"]
    for left, right, label in (
        (source["library"], pair["library"], "library"),
        (source["buggy_revision"], pair["buggy_revision"], "buggy_revision"),
        (source["fixed_revision"], pair["fixed_revision"], "fixed_revision"),
    ):
        if left != right:
            raise MiningInputError(f"divergence/source {label} mismatch")
    intervention_ids = [item["action_id"] for item in mining_input["intervention"]["actions"]]
    if intervention_ids != divergence["intervention_refs"]:
        raise MiningInputError("divergence intervention_refs do not match mining input")
    evidence = mining_input["evidence"]
    evidence_ids = [item["evidence_id"] for item in evidence]
    p, o = apply_family_rule(mining_input["family_rule"], mining_input["rule_parameters"], evidence_ids)
    contract = {
        "schema_version": "cipherlens.vc.v0_3",
        "contract_id": mining_input["contract_id"],
        "contract_family": mining_input["contract_family"],
        "source": dict(source),
        "context": mining_input["context"],
        "intervention": mining_input["intervention"],
        "execution": mining_input["execution"],
        "expected_relation": p,
        "observable_evidence": o,
        "provenance": {
            "producer": {"name": "contract_miner", "version": "v0.3", "mode": "deterministic_family_rule"},
            "evidence": evidence,
            "field_origins": [
                {"field_path": "/expected_relation", "source_refs": evidence_ids, "method": "family_rule", "rule_id": mining_input["family_rule"]},
                {"field_path": "/observable_evidence", "source_refs": evidence_ids, "method": "family_rule", "rule_id": mining_input["family_rule"]},
            ],
            "human_review": mining_input["human_review"],
        },
    }
    validate_vc_or_raise(contract, repo_root=repo_root)
    return contract


def canonical_mined_bytes(mining_input: Mapping[str, Any], divergence: Mapping[str, Any], repo_root: str | Path | None = None) -> bytes:
    return canonical_vc_bytes(mine_contract(mining_input, divergence, repo_root=repo_root))


def _validate_mining_input(value: Mapping[str, Any]) -> None:
    required = {"schema_version", "contract_id", "contract_family", "family_rule", "source", "context", "intervention", "execution", "rule_parameters", "evidence", "human_review"}
    unknown = set(value) - required
    missing = required - set(value)
    if missing or unknown:
        raise MiningInputError(f"invalid mining input keys: missing={sorted(missing)} unknown={sorted(unknown)}")
    if value.get("schema_version") != MINING_INPUT_VERSION:
        raise MiningInputError("unsupported mining input version")
    if value.get("family_rule") not in RULE_IDS:
        raise MiningInputError("unsupported family rule")
    if not isinstance(value.get("rule_parameters"), dict):
        raise MiningInputError("rule_parameters must be an object")
    if not isinstance(value.get("evidence"), list) or not value["evidence"]:
        raise MiningInputError("evidence must be a non-empty list")

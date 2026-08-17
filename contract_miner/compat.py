"""Explicit, conservative v0.2 read-only compatibility."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from contract_miner.schema import validate_vc


UPGRADE_STATUSES = frozenset({"UPGRADED", "NEEDS_STRUCTURED_METADATA", "UNSUPPORTED_LEGACY_SEMANTICS"})


@dataclass(frozen=True)
class UpgradeResult:
    status: str
    contract: Mapping[str, Any] | None
    reasons: tuple[str, ...]


def upgrade_v02(
    legacy: Mapping[str, Any],
    structured_metadata: Mapping[str, Any] | None = None,
    repo_root: str | None = None,
) -> UpgradeResult:
    """Upgrade only when a complete independently structured v0.3 Contract is supplied."""

    if not isinstance(legacy, dict) or legacy.get("schema_version") != "cipherlens.vc.v0_2":
        return UpgradeResult("UNSUPPORTED_LEGACY_SEMANTICS", None, ("input is not a v0.2 Contract",))
    legacy_errors = validate_vc(legacy, repo_root=repo_root)
    if legacy_errors:
        return UpgradeResult("UNSUPPORTED_LEGACY_SEMANTICS", None, tuple(legacy_errors))
    if structured_metadata is None:
        return UpgradeResult(
            "NEEDS_STRUCTURED_METADATA",
            None,
            ("typed C/I/X/P/O and observable bindings are required",),
        )
    forbidden = {"free_text_relation", "candidate_labels", "safe_labels", "effect", "fidelity", "legacy_verdict"}
    attempted = sorted(forbidden & set(structured_metadata))
    if attempted:
        return UpgradeResult(
            "UNSUPPORTED_LEGACY_SEMANTICS",
            None,
            (f"forbidden legacy inference requested: {attempted}",),
        )
    candidate = structured_metadata.get("canonical_contract")
    if not isinstance(candidate, dict):
        return UpgradeResult(
            "NEEDS_STRUCTURED_METADATA",
            None,
            ("canonical_contract is required",),
        )
    source = candidate.get("source", {})
    legacy_source = legacy.get("source", {})
    expected = {
        "pattern_id": legacy_source.get("pattern_id"),
        "library": legacy_source.get("library"),
        "buggy_revision": legacy_source.get("buggy_version"),
        "fixed_revision": legacy_source.get("fixed_version"),
    }
    if any(source.get(key) != value for key, value in expected.items()):
        return UpgradeResult(
            "UNSUPPORTED_LEGACY_SEMANTICS",
            None,
            ("canonical source metadata does not match v0.2 identity",),
        )
    errors = validate_vc(candidate, repo_root=repo_root)
    if errors:
        return UpgradeResult("NEEDS_STRUCTURED_METADATA", None, tuple(errors))
    return UpgradeResult("UPGRADED", candidate, ())

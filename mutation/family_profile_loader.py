"""Load family mutation profiles."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


DEFAULT_PROFILES = Path("config/family_profiles.yaml")


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_family_profiles(path: Path = DEFAULT_PROFILES) -> dict[str, Any]:
    return load_yaml(path)


def family_profile(profiles: dict[str, Any], family: str) -> dict[str, Any]:
    return ((profiles.get("families") or {}).get(family)) or {}


def seed_by_format(manifest: dict[str, Any], fmt: str) -> dict[str, Any] | None:
    for seed in manifest.get("verified_seeds", []) or []:
        if seed.get("format") == fmt and seed.get("copied_path"):
            normalized = dict(seed)
            normalized["path"] = seed["copied_path"]
            normalized["parser_valid"] = True
            normalized["usable_for_valid_prefix_mutation"] = True
            return normalized
    for seed in manifest.get("seeds", []) or []:
        if (
            seed.get("format") == fmt
            and seed.get("parser_valid") is True
            and seed.get("usable_for_valid_prefix_mutation") is True
        ):
            return seed
    return None

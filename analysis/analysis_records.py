"""Shared records and YAML helpers for analysis/refactor modules."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=100)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def md_dump(title: str, data: dict[str, Any]) -> str:
    return f"# {title}\n\n```yaml\n{yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)}```\n"


def write_md(path: Path, title: str, data: dict[str, Any]) -> None:
    write_text(path, md_dump(title, data))


def bool_get(mapping: dict[str, Any], key: str, default: bool = False) -> bool:
    return bool(mapping.get(key, default))

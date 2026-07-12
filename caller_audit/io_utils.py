from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def expand_string(value: str, context: dict[str, str]) -> str:
    expanded = os.path.expandvars(value)
    try:
        return expanded.format_map(context)
    except KeyError as exc:
        raise ValueError(
            f"unknown format placeholder {exc.args[0]!r} in {value!r}"
        ) from exc


def expand_tree(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        return expand_string(value, context)
    if isinstance(value, list):
        return [expand_tree(item, context) for item in value]
    if isinstance(value, dict):
        return {key: expand_tree(item, context) for key, item in value.items()}
    return value

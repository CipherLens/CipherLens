"""Shared render planning record helpers.

These helpers are intentionally side-effect light.  They support render-plan
and case-render modules with YAML IO, markdown dumping, and path formatting,
but they do not render harnesses, compile, run, call GLM, or write feedback.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def rel(path: Path) -> str:
    return path.as_posix()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, width=100)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_md(path: Path, title: str, data: dict[str, Any]) -> None:
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    write_text(path, f"# {title}\n\n```yaml\n{text}```\n")


def md_list(items: list[str]) -> str:
    return "".join(f"- {item}\n" for item in items) if items else "- none\n"


def c_bytes(values: list[int], width: int = 12) -> str:
    chunks: list[str] = []
    for i in range(0, len(values), width):
        part = ", ".join(f"0x{b:02x}" for b in values[i : i + width])
        chunks.append(f"    {part}")
    return ",\n".join(chunks)


def expected_no_execution_policy() -> dict[str, bool]:
    return {
        "harness_generated": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "glm_called": False,
    }

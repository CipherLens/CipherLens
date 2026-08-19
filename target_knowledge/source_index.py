"""Deterministic local source-tree indexing without publishing local paths."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable

from .canonical import identified


_EXCLUDED_DIRS = {".git", "__pycache__", "CMakeFiles"}
_EXCLUDED_SUFFIXES = {".a", ".o", ".so", ".pyc"}


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def iter_source_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in _EXCLUDED_DIRS for part in relative_parts) or path.suffix in _EXCLUDED_SUFFIXES:
            continue
        yield path


def tree_digest(root: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for path in iter_source_files(root):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest(path).encode("ascii"))
        digest.update(b"\n")
        count += 1
    return digest.hexdigest(), count


def source_root_record(root: Path, logical_ref: str) -> dict[str, object]:
    digest, count = tree_digest(root)
    return {"root_ref": logical_ref, "tree_digest": digest, "file_count": count}


def materialize_source_identity_record(root: Path, root_ref: str, identity: dict[str, object]) -> dict[str, object]:
    """Portable identity record for a local source root; no execution involved."""
    record = source_root_record(root, root_ref)
    return identified({
        "schema_version": "cipherlens.source_identity_record.v0.1",
        "source_root_ref": root_ref, "source_tree_digest": record["tree_digest"], "file_count": record["file_count"],
        "identity": identity, "preparation_status": "PREPARED_FOR_7D_B",
    }, "source-identity", "source_identity_id")


def find_symbol(root: Path, symbol: str, suffixes: tuple[str, ...] = (".h", ".c", ".cc", ".cpp")) -> dict[str, object] | None:
    """Find a literal declaration/use and return only portable source evidence."""
    for path in iter_source_files(root):
        if path.suffix not in suffixes:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            if symbol in line:
                return {
                    "evidence_type": "SOURCE_SNIPPET" if path.suffix != ".h" else "HEADER_SIGNATURE",
                    "symbol": symbol,
                    "file_ref": path.relative_to(root).as_posix(),
                    "line": number,
                    "file_digest": file_digest(path),
                    "snippet_digest": hashlib.sha256(line.strip().encode("utf-8")).hexdigest(),
                }
    return None

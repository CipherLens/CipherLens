from __future__ import annotations

import re
from pathlib import Path
from typing import Any


DEFAULT_TEST_MARKERS = (
    "/test/",
    "/tests/",
    "/example/",
    "/examples/",
    "/benchmark/",
    "/benchmarks/",
    "/vendor/",
    "/vendored/",
    "/third_party/",
)


def classify_path(path: str, test_markers: list[str]) -> str:
    normalized = "/" + path.replace("\\", "/").lstrip("/")
    for marker in test_markers:
        marker_norm = marker if marker.startswith("/") else "/" + marker
        if marker_norm in normalized:
            return "test_or_auxiliary"
    return "production"


def scan_call_sites(
    repo: Path,
    api_patterns: list[str],
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    test_markers: list[str] | None = None,
    context_lines: int = 8,
) -> list[dict[str, Any]]:
    include_globs = include_globs or [
        "**/*.c", "**/*.cc", "**/*.cpp", "**/*.h", "**/*.hpp"
    ]
    exclude_globs = exclude_globs or []
    test_markers = test_markers or list(DEFAULT_TEST_MARKERS)
    compiled = [re.compile(pattern) for pattern in api_patterns]

    excluded: set[Path] = set()
    for pattern in exclude_globs:
        excluded.update(repo.glob(pattern))

    candidates: set[Path] = set()
    for pattern in include_globs:
        candidates.update(repo.glob(pattern))

    rows: list[dict[str, Any]] = []
    for path in sorted(candidates):
        if not path.is_file() or path in excluded:
            continue
        try:
            rel = path.relative_to(repo).as_posix()
            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            continue

        for index, line in enumerate(lines):
            matched = [
                pattern.pattern for pattern in compiled if pattern.search(line)
            ]
            if not matched:
                continue
            begin = max(0, index - context_lines)
            end = min(len(lines), index + context_lines + 1)
            rows.append(
                {
                    "path": rel,
                    "line": index + 1,
                    "classification": classify_path(rel, test_markers),
                    "matched_patterns": matched,
                    "source_line": line.strip(),
                    "context": "\n".join(
                        f"{line_no + 1:>5}: {lines[line_no]}"
                        for line_no in range(begin, end)
                    ),
                }
            )
    return rows


def evaluate_static_checks(
    call_sites: list[dict[str, Any]],
    full_consumption_patterns: list[str],
) -> dict[str, Any]:
    checks = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in full_consumption_patterns
    ]
    items = []
    for site in call_sites:
        context = str(site.get("context", ""))
        matched = [
            pattern.pattern for pattern in checks if pattern.search(context)
        ]
        items.append(
            {
                "path": site["path"],
                "line": site["line"],
                "classification": site["classification"],
                "full_consumption_check_found": bool(matched),
                "matched_check_patterns": matched,
            }
        )

    production = [
        item for item in items if item["classification"] == "production"
    ]
    missing = [
        item for item in production
        if not item["full_consumption_check_found"]
    ]
    return {
        "call_site_count": len(items),
        "production_call_site_count": len(production),
        "production_without_full_consumption_check": len(missing),
        "items": items,
    }

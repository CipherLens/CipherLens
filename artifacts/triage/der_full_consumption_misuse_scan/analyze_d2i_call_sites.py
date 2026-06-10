#!/usr/bin/env python3
"""Classify d2i_* call sites for full-consumption checks.

This script is intentionally read-only with respect to source trees. It reads
the grep output produced for this triage sprint and writes CSV/JSON summaries
under the triage results directory.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
INPUT = RESULTS / "d2i_call_sites.txt"
CSV_OUT = RESULTS / "d2i_call_site_triage.csv"
JSON_OUT = RESULTS / "d2i_call_site_summary.json"

TARGET_APIS = (
    "d2i_PUBKEY",
    "d2i_X509",
    "d2i_X509_REQ",
    "d2i_X509_CRL",
    "d2i_PKCS8_PRIV_KEY_INFO",
    "d2i_PKCS12",
)

SOURCE_SUFFIXES = {".c", ".h", ".inc"}
SKIP_PARTS = {
    "doc",
    "docs",
    "include",
    "util",
    "artifacts",
    "runner",
    "template_maker",
    "migration",
    "knowledge_raw",
}

FULL_CONSUMPTION_PATTERNS = (
    r"\b(?:p|pp|derp|datap|certptr|bytes)\s*==\s*(?:end|data\s*\+\s*\w+|\w+\s*\+\s*\w+)\b",
    r"\b(?:p|pp|derp|datap|certptr|bytes)\s*!=\s*(?:end|data\s*\+\s*\w+|\w+\s*\+\s*\w+)\b",
    r"\b(?:end|data\s*\+\s*\w+|\w+\s*\+\s*\w+)\s*==\s*(?:p|pp|derp|datap|certptr|bytes)\b",
    r"\b(?:end|data\s*\+\s*\w+|\w+\s*\+\s*\w+)\s*!=\s*(?:p|pp|derp|datap|certptr|bytes)\b",
    r"\b(?:p|pp|derp|datap|certptr|bytes)\s*-\s*(?:data|der|input|buf|buffer|cert|crl)\b",
    r"\b(?:data|der|input|buf|buffer|cert|crl)\s*-\s*(?:p|pp|derp|datap|certptr|bytes)\b",
    r"\bconsumed(?:_len|len)?\b",
    r"\btrailing(?:_data)?\b",
)

PREFIX_INTENDED_PATTERNS = (
    r"_bio\b",
    r"_fp\b",
    r"\bASN1_item_d2i\b",
    r"\bdecoder\b",
    r"\bdecode_der\b",
    r"\bOSSL_DECODER\b",
    r"\bOSSL_STORE\b",
    r"\bwhile\s*\(",
    r"\bfor\s*\(",
    r"\bnext\b",
)

NULL_ONLY_PATTERNS = (
    r"!=\s*NULL",
    r"==\s*NULL",
    r"\bTEST_ptr\b",
    r"\bTEST_true\b",
    r"\bif\s*\(",
)


def parse_grep_line(line: str) -> tuple[Path, int, str] | None:
    parts = line.rstrip("\n").split(":", 2)
    if len(parts) != 3:
        return None
    path_s, line_s, text = parts
    try:
        line_no = int(line_s)
    except ValueError:
        return None
    return Path(path_s), line_no, text


def api_from_text(text: str) -> str | None:
    for api in sorted(TARGET_APIS, key=len, reverse=True):
        if re.search(r"\b" + re.escape(api) + r"(?:_ex|_bio|_fp)?\b", text):
            return api
    return None


def is_relevant_source(path: Path, text: str) -> bool:
    if path.suffix not in SOURCE_SUFFIXES:
        return False
    parts = set(path.parts)
    if parts & SKIP_PARTS:
        return False
    stripped = text.strip()
    if (
        "typedef" in text
        or "#define" in text
        or "d2i_of_void" in text
        or stripped.startswith("/*")
        or stripped.startswith("*")
    ):
        return False
    if re.match(r"^[A-Za-z_][A-Za-z0-9_ *]+d2i_[A-Za-z0-9_]+\s*\(", stripped):
        return False
    return api_from_text(text) is not None


def read_context(path: Path, line_no: int, radius: int = 8) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line_no - radius - 1)
    end = min(len(lines), line_no + radius)
    numbered = []
    for idx in range(start, end):
        numbered.append(f"{idx + 1}: {lines[idx]}")
    return "\n".join(numbered)


def has_any(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def classify(context: str, call_text: str) -> tuple[str, bool, str]:
    compact = context.replace("\n", " ")
    has_full = has_any(FULL_CONSUMPTION_PATTERNS, compact)
    prefix_intended = has_any(PREFIX_INTENDED_PATTERNS, compact)
    null_only = has_any(NULL_ONLY_PATTERNS, compact)

    if has_full:
        return "checks_full_consumption", True, "nearby code appears to compare or compute consumed input"
    if prefix_intended:
        return "prefix_parse_intended", False, "context suggests decoder/stream/prefix parsing path"
    if null_only or call_text.strip().startswith("if "):
        return "potential_misuse", False, "nearby code appears to check parse success without full-consumption check"
    return "unknown_needs_manual_review", False, "no clear full-consumption check found in local context"


def main() -> int:
    rows = []
    seen = set()
    for raw in INPUT.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = parse_grep_line(raw)
        if parsed is None:
            continue
        path, line_no, text = parsed
        if not is_relevant_source(path, text):
            continue
        api = api_from_text(text)
        if api is None:
            continue
        key = (str(path), line_no, api)
        if key in seen:
            continue
        seen.add(key)
        context = read_context(path, line_no)
        classification, has_full, reason = classify(context, text)
        rows.append(
            {
                "file": str(path),
                "line": line_no,
                "api": api,
                "classification": classification,
                "has_full_consumption_check": str(has_full).lower(),
                "reason": reason,
                "evidence_snippet": context,
            }
        )

    rows.sort(key=lambda r: (r["classification"], r["api"], r["file"], r["line"]))

    counts = {}
    by_api = {}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
        by_api.setdefault(row["api"], {})
        by_api[row["api"]][row["classification"]] = by_api[row["api"]].get(row["classification"], 0) + 1

    with CSV_OUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "file",
                "line",
                "api",
                "classification",
                "has_full_consumption_check",
                "reason",
                "evidence_snippet",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    JSON_OUT.write_text(
        json.dumps(
            {
                "total_relevant_call_sites": len(rows),
                "classification_counts": counts,
                "by_api": by_api,
                "csv": str(CSV_OUT),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(json.loads(JSON_OUT.read_text(encoding="utf-8")), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

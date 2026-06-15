#!/usr/bin/env python3
"""Review staged counterpart API cards before knowledge import.

This script is intentionally staging-only. It reads staged cards and local
source trees, writes review artifacts under --out-dir, and refuses to write
knowledge_raw or knowledge_base.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml


OPENSSL_HEADER_DIRS = ["include"]
OPENSSL_SOURCE_DIRS = ["ssl", "crypto"]
OPENSSL_TEST_DIRS = ["test"]
MBEDTLS_HEADER_DIRS = ["include"]
MBEDTLS_SOURCE_DIRS = ["library"]
MBEDTLS_TEST_DIRS = ["tests", "programs"]
TEXT_SUFFIXES = {".h", ".c", ".cc", ".cpp", ".hpp", ".inc", ".md", ".txt"}


def load_yaml(path: Path) -> Any:
    if not path.exists():
        raise SystemExit(f"missing required input: {path}")
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def records_from(path: Path, key: str) -> list[dict[str, Any]]:
    data = load_yaml(path)
    records = data.get(key)
    if records is None:
        records = data.get("staged_api_cards") or data.get("staged_api_constraints") or data.get("staged_call_sequences")
    if not isinstance(records, list):
        raise SystemExit(f"input does not contain list records: {path}")
    return [x for x in records if isinstance(x, dict)]


def first_records(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    for key in ("staged_api_cards", "staged_api_constraints", "staged_call_sequences", "mapping_support"):
        if isinstance(data.get(key), list):
            return [x for x in data[key] if isinstance(x, dict)]
    raise SystemExit(f"input does not contain recognized records: {path}")


def api_sort_key(card: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(card.get("library", "")),
        str(card.get("family", "")),
        str(card.get("api") or card.get("api_name") or card.get("source_api") or ""),
    )


def iter_files(root: Path, subdirs: list[str]) -> list[Path]:
    files: list[Path] = []
    for subdir in subdirs:
        base = root / subdir
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in TEXT_SUFFIXES:
                files.append(path)
    return sorted(files)


def collect_hits(api: str, files: list[Path], root: Path, limit: int = 12) -> list[dict[str, Any]]:
    if not api:
        return []
    pattern = re.compile(rf"\b{re.escape(api)}\b")
    hits: list[dict[str, Any]] = []
    for path in files:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        line_numbers = [i + 1 for i, line in enumerate(lines) if pattern.search(line)]
        if line_numbers:
            hits.append(
                {
                    "path": str(path.relative_to(root)),
                    "line_numbers": line_numbers[:6],
                    "hit_count": len(line_numbers),
                }
            )
            if len(hits) >= limit:
                break
    return hits


def signature_candidates(api: str, header_files: list[Path], root: Path, limit: int = 8) -> list[dict[str, str]]:
    if not api:
        return []
    pattern = re.compile(rf"\b{re.escape(api)}\b")
    candidates: list[dict[str, str]] = []
    for path in header_files:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for idx, line in enumerate(lines):
            if not pattern.search(line):
                continue
            snippet = [line.strip()]
            end = idx + 1
            while ";" not in snippet[-1] and ")" not in snippet[-1] and end < len(lines) and len(snippet) < 6:
                snippet.append(lines[end].strip())
                end += 1
            text = " ".join(x for x in snippet if x)
            candidates.append({"path": str(path.relative_to(root)), "line": str(idx + 1), "text": text})
            if len(candidates) >= limit:
                return candidates
    return candidates


def evidence_strength(header_hits: list[Any], source_hits: list[Any], test_hits: list[Any]) -> str:
    if header_hits and (source_hits or test_hits):
        return "strong"
    if header_hits:
        return "moderate"
    if source_hits or test_hits:
        return "weak"
    return "none"


def review_from_evidence(card: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    if card.get("staging_status") == "no_direct_counterpart":
        return {
            "reviewed_confidence": "not_found",
            "review_status": "no_direct_counterpart",
            "evidence_strength": "none",
            "evidence_summary": "No direct mbedTLS counterpart for this source API in the staged target set.",
            "source_evidence_refs": [],
            "import_recommendation": "skip_no_direct_counterpart",
            "notes": "Keep as mapping limitation evidence, not as an API card.",
        }
    strength = evidence["evidence_strength"]
    refs = []
    for key in ("header_hits", "source_hits", "test_or_example_hits"):
        refs.extend([f"{key}:{hit['path']}" for hit in evidence.get(key, [])[:3]])
    if strength == "strong":
        return {
            "reviewed_confidence": "high",
            "review_status": "import_ready",
            "evidence_strength": strength,
            "evidence_summary": "API appears in headers and has source/test/example usage evidence.",
            "source_evidence_refs": refs,
            "import_recommendation": "import_now",
            "notes": "Still import as target-side semantic knowledge, not as confirmed vulnerability evidence.",
        }
    if strength == "moderate":
        return {
            "reviewed_confidence": "medium",
            "review_status": "import_ready_with_candidate_label",
            "evidence_strength": strength,
            "evidence_summary": "API appears in headers; usage evidence was not found in scanned source/test/example paths.",
            "source_evidence_refs": refs,
            "import_recommendation": "import_as_candidate",
            "notes": "Import only with candidate label until usage evidence is strengthened.",
        }
    if strength == "weak":
        return {
            "reviewed_confidence": "low",
            "review_status": "needs_manual_review",
            "evidence_strength": strength,
            "evidence_summary": "API string appears outside headers; signature evidence was not confirmed.",
            "source_evidence_refs": refs,
            "import_recommendation": "skip_manual_review",
            "notes": "Needs manual signature and semantics confirmation.",
        }
    return {
        "reviewed_confidence": "not_found_in_source",
        "review_status": "reject_not_found",
        "evidence_strength": strength,
        "evidence_summary": "API was not found in the configured local source tree.",
        "source_evidence_refs": [],
        "import_recommendation": "skip_not_found",
        "notes": "Do not import without source evidence.",
    }


def build_evidence(cards: list[dict[str, Any]], library: str, root: Path) -> list[dict[str, Any]]:
    if library == "openssl":
        header_files = iter_files(root, OPENSSL_HEADER_DIRS)
        source_files = iter_files(root, OPENSSL_SOURCE_DIRS)
        test_files = iter_files(root, OPENSSL_TEST_DIRS)
    else:
        header_files = iter_files(root, MBEDTLS_HEADER_DIRS)
        source_files = iter_files(root, MBEDTLS_SOURCE_DIRS)
        test_files = iter_files(root, MBEDTLS_TEST_DIRS)
    evidence = []
    for card in sorted(cards, key=api_sort_key):
        api = str(card.get("api") or "")
        if not api:
            evidence.append(
                {
                    "library": library,
                    "api_name": "",
                    "source_api": card.get("source_api"),
                    "header_hits": [],
                    "source_hits": [],
                    "test_or_example_hits": [],
                    "signature_candidates": [],
                    "evidence_strength": "none",
                    "notes": "no_direct_counterpart entry",
                }
            )
            continue
        header_hits = collect_hits(api, header_files, root)
        source_hits = collect_hits(api, source_files, root)
        test_hits = collect_hits(api, test_files, root)
        signatures = signature_candidates(api, header_files, root)
        strength = evidence_strength(header_hits, source_hits, test_hits)
        evidence.append(
            {
                "library": library,
                "api_name": api,
                "header_hits": header_hits,
                "source_hits": source_hits,
                "test_or_example_hits": test_hits,
                "signature_candidates": signatures,
                "evidence_strength": strength,
                "notes": "evidence extracted from configured local source tree",
            }
        )
    return evidence


def review_cards(cards: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence_by_api = {str(e.get("api_name") or ""): e for e in evidence}
    reviewed = []
    for card in sorted(cards, key=api_sort_key):
        item = dict(card)
        ev = evidence_by_api.get(str(card.get("api") or ""), {})
        item["review"] = review_from_evidence(card, ev)
        reviewed.append(item)
    return reviewed


def review_constraints(constraints: list[dict[str, Any]], evidence_by_key: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    reviewed = []
    for item in sorted(constraints, key=api_sort_key):
        out = dict(item)
        key = (str(out.get("library")), str(out.get("api")))
        ev = evidence_by_key.get(key, {})
        strength = str(ev.get("evidence_strength", "none"))
        if strength in {"strong", "moderate"}:
            status = "candidate_constraint"
            recommendation = "import_as_candidate"
        else:
            status = "weak_candidate_constraint"
            recommendation = "skip_manual_review"
        out["review"] = {
            "constraint_review_status": status,
            "evidence_strength": strength,
            "import_recommendation": recommendation,
            "notes": "Constraints remain candidate semantics until imported and checked against API docs/tests.",
        }
        reviewed.append(out)
    return reviewed


def review_sequences(sequences: list[dict[str, Any]], library: str, evidence_by_key: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    reviewed = []
    for seq in sorted(sequences, key=lambda x: (str(x.get("family", "")), str(x.get("sequence_name", "")))):
        out = dict(seq)
        apis = [str(x) for x in out.get("apis", [])]
        test_supported = [api for api in apis if evidence_by_key.get((library, api), {}).get("test_or_example_hits")]
        out["review"] = {
            "call_sequence_review_status": "synthetic_lifecycle_sequence",
            "import_recommendation": "import_as_candidate",
            "test_or_example_supported_apis": test_supported,
            "notes": "Do not treat as confirmed usage; sequence was reviewed as a synthetic lifecycle candidate.",
        }
        reviewed.append(out)
    return reviewed


def card_review_index(cards: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(card.get("library")), str(card.get("api"))): card
        for card in cards
        if card.get("api")
    }


def review_mapping(rows: list[dict[str, Any]], cards: dict[tuple[str, str], dict[str, Any]], constraints: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    reviewed = []
    for row in sorted(rows, key=lambda x: (str(x.get("target_library", "")), str(x.get("source_api", "")), str(x.get("target_api", "")))):
        target_library = str(row.get("target_library") or "")
        target_api = str(row.get("target_api") or "")
        target_card = cards.get((target_library, target_api))
        target_constraint = constraints.get((target_library, target_api))
        before = str(row.get("support_status_after_staging") or row.get("previous_review_status") or "")
        if not target_api:
            status = "no_direct_counterpart"
            confidence = "none"
        elif target_card and target_constraint and target_card.get("review", {}).get("import_recommendation") in {"import_now", "import_as_candidate"}:
            status = "import_ready_candidate_mapping"
            confidence = str(target_card.get("review", {}).get("reviewed_confidence", "medium"))
        elif target_card:
            status = "needs_manual_review"
            confidence = str(target_card.get("review", {}).get("reviewed_confidence", "low"))
        else:
            status = "weak_evidence"
            confidence = "low"
        reviewed.append(
            {
                "family": target_card.get("family") if target_card else "",
                "wolfssl_api": row.get("source_api"),
                "target_library": target_library,
                "target_api": target_api,
                "before_status": before,
                "after_review_status": status,
                "source_card_exists": bool(row.get("has_source_card")),
                "target_card_reviewed": bool(target_card),
                "target_constraint_reviewed": bool(target_constraint),
                "mapping_confidence_reviewed": confidence,
                "status": status,
                "notes": "Candidate mapping only; not confirmed equivalence.",
            }
        )
    return reviewed


def markdown_table(items: list[dict[str, Any]], fields: list[str]) -> str:
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for item in items:
        values = []
        for field in fields:
            value: Any = item
            for part in field.split("."):
                value = value.get(part, "") if isinstance(value, dict) else ""
            values.append(str(value))
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines) + "\n"


def reviewed_counts(cards: list[dict[str, Any]]) -> dict[str, Any]:
    recs = Counter(card.get("review", {}).get("import_recommendation", "unknown") for card in cards)
    statuses = Counter(card.get("review", {}).get("review_status", "unknown") for card in cards)
    strong = [
        str(card.get("api") or card.get("source_api"))
        for card in cards
        if card.get("review", {}).get("evidence_strength") == "strong"
    ]
    weak = [
        str(card.get("api") or card.get("source_api"))
        for card in cards
        if card.get("review", {}).get("evidence_strength") in {"weak", "none"}
        and card.get("review", {}).get("review_status") != "no_direct_counterpart"
    ]
    return {
        "total": len(cards),
        "import_recommendation_counts": dict(recs),
        "review_status_counts": dict(statuses),
        "strong_evidence_apis": strong,
        "remaining_weak_apis": weak,
    }


def make_import_decision(
    openssl_cards: list[dict[str, Any]],
    mbedtls_cards: list[dict[str, Any]],
    constraints: list[dict[str, Any]],
    sequences: list[dict[str, Any]],
    mapping: list[dict[str, Any]],
) -> dict[str, Any]:
    def by_rec(cards: list[dict[str, Any]], rec: str) -> list[str]:
        return [
            str(card.get("api") or card.get("source_api"))
            for card in cards
            if card.get("review", {}).get("import_recommendation") == rec
        ]

    openssl_now = by_rec(openssl_cards, "import_now")
    openssl_candidate = by_rec(openssl_cards, "import_as_candidate")
    mbedtls_now = by_rec(mbedtls_cards, "import_now")
    mbedtls_candidate = by_rec(mbedtls_cards, "import_as_candidate")
    importable = len(openssl_now) + len(openssl_candidate) + len(mbedtls_now) + len(mbedtls_candidate)
    next_task = (
        "api_card_import_cross_library_counterparts_to_knowledge_raw_v1"
        if importable >= 10
        else "source_evidence_refinement_for_counterpart_cards_v1"
    )
    return {
        "import_decision": {
            "recommended_next_task": next_task,
            "openssl_import_now": openssl_now,
            "openssl_import_as_candidate": openssl_candidate,
            "openssl_skip": [
                str(card.get("api") or card.get("source_api"))
                for card in openssl_cards
                if card.get("review", {}).get("import_recommendation") not in {"import_now", "import_as_candidate"}
            ],
            "mbedtls_import_now": mbedtls_now,
            "mbedtls_import_as_candidate": mbedtls_candidate,
            "mbedtls_skip": [
                str(card.get("api") or card.get("source_api"))
                for card in mbedtls_cards
                if card.get("review", {}).get("import_recommendation") not in {"import_now", "import_as_candidate"}
            ],
            "constraints_import_as_candidate": [
                f"{item.get('library')}:{item.get('api')}"
                for item in constraints
                if item.get("review", {}).get("import_recommendation") == "import_as_candidate"
            ],
            "call_sequences_import_as_candidate": [
                str(item.get("sequence_name"))
                for item in sequences
                if item.get("review", {}).get("import_recommendation") == "import_as_candidate"
            ],
            "mapping_import_as_candidate": [
                f"{item.get('wolfssl_api')}->{item.get('target_library')}:{item.get('target_api')}"
                for item in mapping
                if item.get("status") == "import_ready_candidate_mapping"
            ],
            "rebuild_required_after_import": True,
            "reason": "Reviewed source/header evidence found enough importable counterpart API cards, mostly as candidate semantic knowledge.",
        }
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl-staged-cards", required=True)
    parser.add_argument("--mbedtls-staged-cards", required=True)
    parser.add_argument("--openssl-constraints", required=True)
    parser.add_argument("--mbedtls-constraints", required=True)
    parser.add_argument("--openssl-call-sequences", required=True)
    parser.add_argument("--mbedtls-call-sequences", required=True)
    parser.add_argument("--mapping-support", required=True)
    parser.add_argument("--openssl-src", required=True)
    parser.add_argument("--mbedtls-src", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--write-knowledge-raw", default="false")
    parser.add_argument("--write-knowledge-base", default="false")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.write_knowledge_raw.lower() != "false" or args.write_knowledge_base.lower() != "false":
        raise SystemExit("refusing to write knowledge_raw or knowledge_base in manual review mode")

    openssl_src = Path(args.openssl_src)
    mbedtls_src = Path(args.mbedtls_src)
    if not openssl_src.exists() or not mbedtls_src.exists():
        raise SystemExit(f"missing source roots: openssl={openssl_src.exists()} mbedtls={mbedtls_src.exists()}")

    out = Path(args.out_dir)
    openssl_cards = first_records(Path(args.openssl_staged_cards))
    mbedtls_cards = first_records(Path(args.mbedtls_staged_cards))
    openssl_constraints = first_records(Path(args.openssl_constraints))
    mbedtls_constraints = first_records(Path(args.mbedtls_constraints))
    openssl_sequences = first_records(Path(args.openssl_call_sequences))
    mbedtls_sequences = first_records(Path(args.mbedtls_call_sequences))
    mapping_support = first_records(Path(args.mapping_support))

    openssl_evidence = build_evidence(openssl_cards, "openssl", openssl_src)
    mbedtls_evidence = build_evidence(mbedtls_cards, "mbedtls", mbedtls_src)
    reviewed_openssl = review_cards(openssl_cards, openssl_evidence)
    reviewed_mbedtls = review_cards(mbedtls_cards, mbedtls_evidence)

    evidence_by_key = {
        ("openssl", str(item.get("api_name"))): item for item in openssl_evidence if item.get("api_name")
    }
    evidence_by_key.update(
        {("mbedtls", str(item.get("api_name"))): item for item in mbedtls_evidence if item.get("api_name")}
    )
    reviewed_constraints = review_constraints(openssl_constraints + mbedtls_constraints, evidence_by_key)
    reviewed_sequences = review_sequences(openssl_sequences, "openssl", evidence_by_key) + review_sequences(mbedtls_sequences, "mbedtls", evidence_by_key)
    constraint_index = {
        (str(item.get("library")), str(item.get("api"))): item for item in reviewed_constraints
    }
    card_index = card_review_index(reviewed_openssl + reviewed_mbedtls)
    reviewed_mapping = review_mapping(mapping_support, card_index, constraint_index)
    import_decision = make_import_decision(
        reviewed_openssl,
        reviewed_mbedtls,
        reviewed_constraints,
        reviewed_sequences,
        reviewed_mapping,
    )

    input_summary = {
        "task": "manual_review_counterpart_staged_cards_before_import_v1",
        "openssl_staged_cards": args.openssl_staged_cards,
        "mbedtls_staged_cards": args.mbedtls_staged_cards,
        "openssl_src": str(openssl_src),
        "mbedtls_src": str(mbedtls_src),
        "source_dirs_usable": {"openssl": openssl_src.exists(), "mbedtls": mbedtls_src.exists()},
        "write_knowledge_raw": False,
        "write_knowledge_base": False,
        "rag_rebuild": False,
        "poc_run": False,
        "glm": False,
        "render": False,
        "template_generated": False,
    }
    report = {
        "openssl_review": reviewed_counts(reviewed_openssl),
        "mbedtls_review": reviewed_counts(reviewed_mbedtls),
        "constraints_review": dict(Counter(item.get("review", {}).get("constraint_review_status") for item in reviewed_constraints)),
        "call_sequences_review": dict(Counter(item.get("review", {}).get("call_sequence_review_status") for item in reviewed_sequences)),
        "mapping_review": dict(Counter(item.get("status") for item in reviewed_mapping)),
        "knowledge_raw_modified": False,
        "knowledge_base_modified": False,
        "rag_rebuild": False,
        "pattern_bank_modified": False,
        "scheduler_seed_modified": False,
        "poc_run": False,
        "compile_run": False,
        "glm": False,
        "render": False,
        "template_generated": False,
        "next_task_name": import_decision["import_decision"]["recommended_next_task"],
    }

    dump_yaml(out / "input/manual_review_input_summary.yaml", input_summary)
    write_text(out / "input/manual_review_input_summary.md", "# Manual Review Input Summary\n\n" + json.dumps(input_summary, indent=2) + "\n")
    dump_yaml(out / "source_evidence/openssl_api_source_evidence.yaml", {"source_evidence": openssl_evidence})
    dump_yaml(out / "source_evidence/mbedtls_api_source_evidence.yaml", {"source_evidence": mbedtls_evidence})
    write_text(out / "source_evidence/openssl_api_source_evidence.md", markdown_table(openssl_evidence, ["api_name", "evidence_strength", "notes"]))
    write_text(out / "source_evidence/mbedtls_api_source_evidence.md", markdown_table(mbedtls_evidence, ["api_name", "source_api", "evidence_strength", "notes"]))
    dump_yaml(out / "reviewed_cards/reviewed_openssl_counterpart_api_cards.yaml", {"reviewed_api_cards": reviewed_openssl})
    dump_yaml(out / "reviewed_cards/reviewed_mbedtls_counterpart_api_cards.yaml", {"reviewed_api_cards": reviewed_mbedtls})
    write_text(out / "reviewed_cards/reviewed_openssl_counterpart_api_cards.md", markdown_table(reviewed_openssl, ["api", "family", "review.reviewed_confidence", "review.import_recommendation"]))
    write_text(out / "reviewed_cards/reviewed_mbedtls_counterpart_api_cards.md", markdown_table(reviewed_mbedtls, ["api", "source_api", "family", "review.reviewed_confidence", "review.import_recommendation"]))
    dump_yaml(out / "reviewed_constraints/reviewed_counterpart_api_constraints.yaml", {"reviewed_api_constraints": reviewed_constraints})
    write_text(out / "reviewed_constraints/reviewed_counterpart_api_constraints.md", markdown_table(reviewed_constraints, ["library", "api", "family", "review.constraint_review_status", "review.import_recommendation"]))
    dump_yaml(out / "reviewed_call_sequences/reviewed_counterpart_call_sequences.yaml", {"reviewed_call_sequences": reviewed_sequences})
    write_text(out / "reviewed_call_sequences/reviewed_counterpart_call_sequences.md", markdown_table(reviewed_sequences, ["sequence_name", "family", "review.call_sequence_review_status", "review.import_recommendation"]))
    dump_yaml(out / "mapping_review/reviewed_mapping_support.yaml", {"reviewed_mapping_support": reviewed_mapping})
    write_text(out / "mapping_review/reviewed_mapping_support.md", markdown_table(reviewed_mapping, ["wolfssl_api", "target_library", "target_api", "status", "mapping_confidence_reviewed"]))
    dump_yaml(out / "import_decision/counterpart_import_decision.yaml", import_decision)
    write_text(out / "import_decision/counterpart_import_decision.md", "# Counterpart Import Decision\n\n" + json.dumps(import_decision, indent=2) + "\n")
    dump_yaml(out / "reports/manual_review_counterpart_staged_cards_before_import_report.yaml", report)
    write_text(out / "reports/manual_review_counterpart_staged_cards_before_import_report.md", "# Manual Review Counterpart Report\n\n" + json.dumps(report, indent=2) + "\n")
    write_text(out / "README.md", "# manual_review_counterpart_staged_cards_before_import_v1\n\nReviewed staged counterpart cards against local source trees only. No knowledge import, RAG rebuild, PoC run, GLM call, render, template generation, commit, or push was performed.\n")
    print(f"[OK] wrote manual review artifacts to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

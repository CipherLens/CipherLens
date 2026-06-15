from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


DEFAULT_BANK = Path("artifacts/pattern_bank/unified_pattern_bank.yaml")
DEFAULT_SCHEDULER = Path("artifacts/pattern_bank/scheduler_seed.yaml")
DEFAULT_MUTATION_FEEDBACK = Path("artifacts/feedback/mutation_feedback.jsonl")
DEFAULT_MUTATION_SCORES = Path("artifacts/feedback/mutation_scores.yaml")
DEFAULT_OUT = Path("artifacts/candidate_queue")


CLEAR_ORACLES = {
    "full_consumption_semantic",
    "behavior_divergence",
    "unexpected_success",
    "safe_reject_baseline",
    "crash_or_sanitizer",
}


CONTROLLED_FAMILIES = {
    "der_full_consumption",
    "pkey_verify_semantic",
    "mac_lifecycle",
    "asn1_nested_boundary",
    "memory_length_boundary",
}


RAG_READY_FAMILIES = {
    "der_full_consumption",
    "mac_lifecycle",
    "pkey_verify_semantic",
    "asn1_nested_boundary",
}


APP_LEVEL_EVIDENCE_PATTERNS = (
    "app_level",
    "minimal_reproducer",
    "command_summary",
    "behavior_summary",
)


def read_yaml(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def clamp_score(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 4)


def normalized_evidence_files(entry: dict[str, Any]) -> list[str]:
    files = entry.get("evidence_files") or entry.get("source_files") or []
    if isinstance(files, str):
        return [files]
    return [str(x) for x in files if x]


def has_existing_path(files: list[str]) -> bool:
    return any(Path(path).exists() for path in files)


def has_app_level_evidence(files: list[str]) -> bool:
    joined = "\n".join(files).lower()
    return any(token in joined for token in APP_LEVEL_EVIDENCE_PATTERNS)


def base_recommended_action(entry: dict[str, Any]) -> str:
    family = entry.get("family", "")
    oracle = entry.get("oracle_type", "")
    status = entry.get("migration_status", "")
    pattern_id = entry.get("pattern_id", "")
    if family == "der_full_consumption":
        return "run_der_full_consumption_v2"
    if family == "mac_lifecycle":
        return "audit_lifecycle_semantic_divergence"
    if oracle == "crash_or_sanitizer":
        return "manual_crash_repro_audit"
    if oracle == "unexpected_success":
        return "manual_unexpected_success_audit"
    if status == "stable_safe_negative" or pattern_id.startswith("PKEY_VERIFY_FAMILY"):
        return "keep_as_stable_safe_negative_baseline"
    if status == "projection_limitation":
        return "document_projection_limitation"
    return "queue_for_family_triage"


def compute_readiness(entry: dict[str, Any], feedback_ids: set[str]) -> float:
    oracle = entry.get("oracle_type", "")
    status = entry.get("migration_status", "")
    family = entry.get("family", "")
    pattern_id = entry.get("pattern_id", "")
    evidence_files = normalized_evidence_files(entry)
    source_path = str(entry.get("source_path") or entry.get("source_file") or "")

    score = 0.0
    if oracle in CLEAR_ORACLES:
        score += 0.30
    if oracle in {"behavior_divergence", "unexpected_success", "full_consumption_semantic"}:
        score += 0.25
    if has_app_level_evidence(evidence_files):
        score += 0.25
    if pattern_id or source_path:
        score += 0.20
    if family in RAG_READY_FAMILIES:
        score += 0.15
    if family in CONTROLLED_FAMILIES:
        score += 0.15
    if pattern_id in feedback_ids or family in feedback_ids:
        score += 0.10

    if oracle in {"pending_inference", "unknown", None, ""}:
        score -= 0.25
    if status == "projection_limitation":
        score -= 0.25
    joined = "\n".join(evidence_files).lower()
    if "harness_error" in joined:
        score -= 0.20
    if not has_existing_path(evidence_files) and not source_path:
        score -= 0.20
    return clamp_score(score)


def compute_severity(entry: dict[str, Any]) -> float:
    oracle = entry.get("oracle_type", "")
    status = entry.get("migration_status", "")
    family = entry.get("family", "")
    text = yaml.safe_dump(entry, sort_keys=True).lower()

    score = 0.0
    if oracle == "crash_or_sanitizer":
        score += 0.40
    if family in {"memory_length_boundary", "asn1_nested_boundary"} or "overflow" in text:
        score += 0.35
    if oracle == "unexpected_success":
        score += 0.30
    if family == "der_full_consumption" or "app-level validation gap" in text:
        score += 0.25
    if oracle == "behavior_divergence":
        score += 0.20
    if family in {"mac_lifecycle", "cipher_aead_lifecycle", "api_state_machine"}:
        score += 0.15

    if status == "stable_safe_negative":
        score -= 0.20
    if "expected behavior" in text or "projection_limitation" in status:
        score -= 0.20
    if status == "projection_limitation":
        score -= 0.25
    return clamp_score(score)


def classify_candidate(entry: dict[str, Any]) -> str:
    family = entry.get("family", "")
    oracle = entry.get("oracle_type", "")
    status = entry.get("migration_status", "")
    pattern_id = entry.get("pattern_id", "")
    if family == "der_full_consumption":
        return "app_level_semantic_candidates"
    if family in {"mac_lifecycle", "cipher_aead_lifecycle", "api_state_machine"}:
        return "lifecycle_semantic_divergence_candidates"
    if oracle == "crash_or_sanitizer":
        return "crash_or_sanitizer_candidates"
    if oracle == "unexpected_success":
        return "unexpected_success_candidates"
    if status == "stable_safe_negative" or pattern_id.startswith("PKEY_VERIFY_FAMILY"):
        return "stable_safe_negative_baselines"
    if status == "projection_limitation":
        return "projection_or_expected_behavior"
    return "general_candidates"


def build_candidate(entry: dict[str, Any], feedback_ids: set[str]) -> dict[str, Any]:
    readiness = compute_readiness(entry, feedback_ids)
    severity = compute_severity(entry)
    combined = clamp_score(0.55 * readiness + 0.45 * severity)
    pattern_id = str(entry.get("pattern_id") or entry.get("id") or entry.get("name") or "unknown")
    family = str(entry.get("family") or entry.get("harness_family") or "unknown")
    candidate_id = f"{family}:{pattern_id}"
    return {
        "candidate_id": candidate_id,
        "pattern_id": pattern_id,
        "family": family,
        "source_path": entry.get("source_path") or entry.get("source_file") or "",
        "oracle_type": entry.get("oracle_type") or "",
        "migration_status": entry.get("migration_status") or "",
        "readiness_score": readiness,
        "severity_score": severity,
        "combined_score": combined,
        "recommended_action": base_recommended_action(entry),
        "evidence_files": normalized_evidence_files(entry),
        "notes": entry.get("notes") or entry.get("summary") or "",
    }


def load_bank_entries(bank: Any) -> list[dict[str, Any]]:
    if isinstance(bank, dict):
        for key in ("patterns", "entries", "items"):
            if isinstance(bank.get(key), list):
                return [x for x in bank[key] if isinstance(x, dict)]
        if all(isinstance(v, dict) for v in bank.values()):
            return [v for v in bank.values()]
    if isinstance(bank, list):
        return [x for x in bank if isinstance(x, dict)]
    return []


def bucketize(candidates: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets: dict[str, list[dict[str, Any]]] = {
        "app_level_semantic_candidates": [],
        "lifecycle_semantic_divergence_candidates": [],
        "crash_or_sanitizer_candidates": [],
        "unexpected_success_candidates": [],
        "stable_safe_negative_baselines": [],
        "projection_or_expected_behavior": [],
        "general_candidates": [],
    }
    for cand in candidates:
        buckets[classify_candidate(cand)].append(cand)
    for values in buckets.values():
        values.sort(key=lambda c: (c["combined_score"], c["readiness_score"], c["severity_score"]), reverse=True)
    return buckets


def top_family(candidates: list[dict[str, Any]], field: str) -> dict[str, Any]:
    totals: dict[str, float] = {}
    counts: dict[str, int] = {}
    for cand in candidates:
        family = cand["family"]
        totals[family] = totals.get(family, 0.0) + float(cand[field])
        counts[family] = counts.get(family, 0) + 1
    ranked = sorted(
        (
            {"family": family, "score": round(total / counts[family], 4), "count": counts[family]}
            for family, total in totals.items()
        ),
        key=lambda x: (x["score"], x["count"]),
        reverse=True,
    )
    return ranked[0] if ranked else {"family": "", "score": 0.0, "count": 0}


def write_markdown(out: Path, queue: dict[str, Any]) -> None:
    lines = [
        "# Candidate Queue",
        "",
        "Generated from `artifacts/pattern_bank/unified_pattern_bank.yaml` with separated readiness and severity scoring.",
        "",
        "## Summary",
        "",
    ]
    summary = queue["summary"]
    for key in (
        "total_candidates",
        "top_readiness_family",
        "top_severity_family",
        "top_combined_family",
    ):
        lines.append(f"- {key}: `{summary[key]}`")
    for bucket_name, values in queue["buckets"].items():
        lines.extend(["", f"## {bucket_name}", ""])
        if not values:
            lines.append("- none")
            continue
        for cand in values[:10]:
            lines.append(
                "- `{candidate_id}` readiness={readiness_score:.2f} severity={severity_score:.2f} "
                "combined={combined_score:.2f} action=`{recommended_action}`".format(**cand)
            )
    (out / "candidate_queue.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_readme(out: Path) -> None:
    text = """# Candidate Queue

This directory is a triage layer between the unified pattern bank and runnable migration sprints.

`readiness_score` estimates whether a candidate has enough evidence, oracle clarity, RAG recall, and reusable rendering support to run now.
`severity_score` estimates the potential security impact. The two are intentionally separate so crash-heavy but poorly grounded cases do not automatically outrank runnable semantic candidates.
"""
    (out / "README.md").write_text(text, encoding="utf-8")


def audit_der(out: Path) -> None:
    text = """# DER Full-Consumption Evidence Audit

## Conclusion

The existing local artifacts support a DER app-level validation gap candidate, not a crash and not a confirmed CVE.

## Evidence

- `artifacts/triage/ossl_store_full_consumption/minimal_reproducer/results/behavior_summary.json`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_summary.json`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_security_commands/command_summary.json`

The controlled command-level evidence shows that valid DER with malformed trailing ASN.1 bytes can still be accepted by OpenSSL app-level commands and converted into normal output artifacts, while malformed-only inputs are rejected. This is consistent with a full-consumption semantic gap at an application boundary.

## Triage Limits

- No ASAN/UBSAN/SEGV evidence is present.
- The result should be described as `app_level_validation_gap_candidate`.
- Impact, documentation expectations, and minimal reproduction scope still need manual confirmation.
"""
    (out / "der_full_consumption_audit.md").write_text(text, encoding="utf-8")


def audit_mac(out: Path) -> None:
    text = """# MAC Lifecycle Evidence Audit

## Conclusion

The local pattern bank and triage artifacts support a lifecycle semantic divergence candidate, not a confirmed crash or vulnerability.

## Interpretation

The observed family centers on MAC lifecycle behavior after finalization. OpenSSL-style CMAC behavior may permit repeated update/final operations in paths where mbedTLS PSA-style MAC APIs reject use after finish. That is useful as a migration semantics target, but it requires API documentation and impact review before any security claim.

## Triage Limits

- Treat as `lifecycle_semantic_divergence_candidate`.
- Do not call it a CVE.
- Next step is a recipe-slot lifecycle harness with explicit state transition observables.
"""
    (out / "mac_lifecycle_audit.md").write_text(text, encoding="utf-8")


def audit_crashes(out: Path, crash_top5: list[dict[str, Any]]) -> None:
    lines = [
        "# Crash Or Sanitizer Top5 Audit",
        "",
        "These candidates are high potential severity, but each requires manual repro evidence before promotion.",
        "",
    ]
    if not crash_top5:
        lines.append("- No `crash_or_sanitizer` candidates found.")
    for cand in crash_top5:
        lines.extend(
            [
                f"## {cand['candidate_id']}",
                "",
                f"- readiness_score: {cand['readiness_score']}",
                f"- severity_score: {cand['severity_score']}",
                f"- combined_score: {cand['combined_score']}",
                f"- recommended_action: `{cand['recommended_action']}`",
                f"- evidence_files: {cand.get('evidence_files') or []}",
                "- audit_status: needs manual confirmation of local repro log, sanitizer signature, version sensitivity, and harness validity.",
                "",
            ]
        )
    (out / "crash_or_sanitizer_top5_audit.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pattern-bank", type=Path, default=DEFAULT_BANK)
    parser.add_argument("--scheduler-seed", type=Path, default=DEFAULT_SCHEDULER)
    parser.add_argument("--mutation-feedback", type=Path, default=DEFAULT_MUTATION_FEEDBACK)
    parser.add_argument("--mutation-scores", type=Path, default=DEFAULT_MUTATION_SCORES)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    bank = read_yaml(args.pattern_bank)
    scheduler = read_yaml(args.scheduler_seed) or {}
    feedback_rows = read_jsonl(args.mutation_feedback)
    mutation_scores = read_yaml(args.mutation_scores) or {}
    feedback_ids = {
        str(row.get("pattern_id") or row.get("family") or "")
        for row in feedback_rows
        if row.get("pattern_id") or row.get("family")
    }

    entries = load_bank_entries(bank)
    candidates = [build_candidate(entry, feedback_ids) for entry in entries]
    candidates.sort(key=lambda c: (c["combined_score"], c["readiness_score"], c["severity_score"]), reverse=True)
    buckets = bucketize(candidates)

    summary = {
        "total_candidates": len(candidates),
        "scheduler_source": str(args.scheduler_seed),
        "mutation_scores_source": str(args.mutation_scores),
        "top_readiness_family": top_family(candidates, "readiness_score"),
        "top_severity_family": top_family(candidates, "severity_score"),
        "top_combined_family": top_family(candidates, "combined_score"),
    }

    queue = {
        "sources": {
            "pattern_bank": str(args.pattern_bank),
            "scheduler_seed": str(args.scheduler_seed),
            "mutation_feedback": str(args.mutation_feedback),
            "mutation_scores": str(args.mutation_scores),
        },
        "summary": summary,
        "scheduler_seed_snapshot": scheduler,
        "mutation_scores_snapshot": mutation_scores,
        "candidates": candidates,
        "buckets": buckets,
    }

    args.out_root.mkdir(parents=True, exist_ok=True)
    audits = args.out_root / "audits"
    audits.mkdir(parents=True, exist_ok=True)
    (args.out_root / "candidate_queue.yaml").write_text(
        yaml.safe_dump(queue, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )
    write_markdown(args.out_root, queue)
    write_readme(args.out_root)
    audit_der(audits)
    audit_mac(audits)
    audit_crashes(audits, buckets["crash_or_sanitizer_candidates"][:5])

    print(f"[OK] wrote {args.out_root / 'candidate_queue.yaml'}")
    print(f"[SUMMARY] total_candidates: {len(candidates)}")
    print(f"[SUMMARY] top_readiness_family: {summary['top_readiness_family']}")
    print(f"[SUMMARY] top_severity_family: {summary['top_severity_family']}")
    print(f"[SUMMARY] top_combined_family: {summary['top_combined_family']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

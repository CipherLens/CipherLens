#!/usr/bin/env python3
"""Rerank auto-scheduler candidates using ingestion staging records."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


ELIGIBLE_IMPORT_STATUS = {"high_confidence_import_candidate", "medium_confidence_staging"}


def load_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if yaml is None:
        return json.loads(text)
    return yaml.safe_load(text)


def dump_yaml(path: Path, obj: Any) -> None:
    if yaml is None:
        path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    path.write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(str(v).replace("\n", " ") for v in row) + " |")
    return "\n".join(out) + "\n"


def load_jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def feedback_summary(feedback_dir: Path) -> dict[str, Any]:
    files = sorted(feedback_dir.glob("*.jsonl")) if feedback_dir.exists() else []
    rows = []
    family_counts = Counter()
    for path in files:
        count = load_jsonl_count(path)
        stem = path.stem
        family = stem
        for suffix in ("_feedback", "_candidate_feedback", "_pattern_expansion_feedback"):
            if family.endswith(suffix):
                family = family[: -len(suffix)]
        family_counts[family] += count
        rows.append({"path": str(path), "count": count, "family_hint": family})
    return {"total_feedback_files": len(files), "total_feedback_rows": sum(r["count"] for r in rows), "files": rows, "family_hint_counts": dict(family_counts)}


def load_candidates(path: Path) -> list[dict[str, Any]]:
    obj = load_yaml(path)
    items = obj.get("reviewed_scheduler_seed_candidates", []) if isinstance(obj, dict) else []
    return sorted(items, key=lambda r: (str(r.get("source_library", "")), str(r.get("poc_id", "")), str(r.get("artifact_path", ""))))


def split_candidates(candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    eligible: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for item in candidates:
        status = item.get("import_status")
        confidence = item.get("quality_confidence")
        if status in ELIGIBLE_IMPORT_STATUS and confidence in {"high", "medium"}:
            eligible.append(item)
        else:
            reason = f"excluded import_status={status}, quality_confidence={confidence}"
            excluded.append({"poc_id": item.get("poc_id"), "source_library": item.get("source_library"), "artifact_path": item.get("artifact_path"), "reason": reason})
    return eligible, excluded


def score_candidate(item: dict[str, Any], family_sanity: dict[str, Any], family_counts: Counter) -> dict[str, Any]:
    confidence = item.get("quality_confidence")
    evidence = item.get("evidence_strength")
    route = item.get("route_guess")
    seed = item.get("seed_status_summary") or {}
    family = item.get("family")
    source_library = item.get("source_library")
    suspicious = family_sanity.get("suspicious_family_concentration") or {}
    correction_ids = {x.get("poc_id") for x in family_sanity.get("correction_suggestions", [])}

    quality_score = {"high": 5, "medium": 3, "low": 1, "blocked": 0}.get(confidence, 0)
    evidence_score = {"high": 5, "medium": 3, "low": 1, "needs_review": 0}.get(evidence, 1)
    template_score = 5 if item.get("template_candidate") else 0
    route_score = 5 if route and route not in {"needs_more_evidence", "blocked_seed_missing"} else 0
    seed_score = 5
    if seed.get("placeholder") or seed.get("synthetic"):
        seed_score -= 2
    if seed.get("input_file_count", 0) == 0 and not seed.get("no_external_input_required"):
        seed_score -= 2
    seed_score = max(seed_score, 0)
    novelty_score = 5 if source_library == "wolfssl" else 3 if source_library == "mbedtls" else 2
    family_balance_bonus = 2 if family_counts[family] <= 2 else 1 if family_counts[family] <= 5 else 0
    suspicious_penalty = 0
    if family == "bignum_serialization_boundary" and suspicious.get("possible_over_broad"):
        suspicious_penalty -= 5
    if item.get("poc_id") in correction_ids:
        suspicious_penalty -= 2
    blocked_penalty = 0
    if item.get("import_status") not in ELIGIBLE_IMPORT_STATUS or confidence not in {"high", "medium"}:
        blocked_penalty -= 10

    final_score = (
        quality_score
        + evidence_score
        + template_score
        + route_score
        + seed_score
        + novelty_score
        + family_balance_bonus
        + suspicious_penalty
        + blocked_penalty
    )
    return {
        "poc_id": item.get("poc_id"),
        "source_library": source_library,
        "artifact_path": item.get("artifact_path"),
        "family": family,
        "harness_family": item.get("harness_family"),
        "route_guess": route,
        "import_status": item.get("import_status"),
        "quality_confidence": confidence,
        "evidence_strength": evidence,
        "template_candidate": item.get("template_candidate"),
        "seed_status_summary": seed,
        "ingestion_scheduler_score": {
            "quality_confidence_score": quality_score,
            "evidence_strength_score": evidence_score,
            "template_candidate_score": template_score,
            "route_clarity_score": route_score,
            "seed_status_score": seed_score,
            "novelty_score": novelty_score,
            "family_balance_bonus": family_balance_bonus,
            "suspicious_family_penalty": suspicious_penalty,
            "blocked_or_review_penalty": blocked_penalty,
            "final_score": final_score,
        },
    }


def recommended_route_for_family(family: str, top_route: str) -> str:
    if family in {"secure_heap_state_lifecycle", "cipher_aead_lifecycle", "mac_lifecycle", "tls_protocol_state_lifecycle"}:
        return "B_controlled_family_mutation"
    if family in {"x509_parsing", "pkcs_container_parsing"}:
        return "C_app_level_validation_gap"
    return top_route or "A_recipe_slot_cross_library_migration"


def next_action_for_family(family: str, suspicious: bool, avg_score: float) -> str:
    if suspicious:
        return "historical_poc_ingestion_rules_refinement_v1"
    if avg_score >= 22:
        return "template_generalizer_v1"
    if family in {"x509_parsing", "pkcs_container_parsing"}:
        return "rag_enrichment_from_ingestion_v1"
    return "template_generalizer_v1"


def family_rerank(scored: list[dict[str, Any]], family_sanity: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in scored:
        grouped[item["family"]].append(item)
    suspicious_bignum = bool((family_sanity.get("suspicious_family_concentration") or {}).get("possible_over_broad"))
    rows = []
    for family, items in grouped.items():
        scores = [i["ingestion_scheduler_score"]["final_score"] for i in items]
        conf = Counter(i["quality_confidence"] for i in items)
        libs = sorted(set(i["source_library"] for i in items))
        suspicious = family == "bignum_serialization_boundary" and suspicious_bignum
        top = sorted(items, key=lambda i: (-i["ingestion_scheduler_score"]["final_score"], i["poc_id"]))[0]
        avg = sum(scores) / len(scores)
        rows.append(
            {
                "family": family,
                "candidate_count": len(items),
                "high_confidence_count": conf.get("high", 0),
                "medium_confidence_count": conf.get("medium", 0),
                "source_libraries": libs,
                "representative_pocs": [i["poc_id"] for i in sorted(items, key=lambda i: (-i["ingestion_scheduler_score"]["final_score"], i["poc_id"]))[:5]],
                "avg_score": round(avg, 2),
                "max_score": max(scores),
                "suspicious_concentration": suspicious,
                "recommended_route": recommended_route_for_family(family, top["route_guess"]),
                "recommended_next_action": next_action_for_family(family, suspicious, avg),
            }
        )
    rows.sort(key=lambda r: (r["suspicious_concentration"], -r["max_score"], -r["avg_score"], r["family"]))
    for idx, row in enumerate(rows, 1):
        row["family_rank"] = idx
    return rows


def decide_next_task(scored: list[dict[str, Any]], families: list[dict[str, Any]], family_sanity: dict[str, Any]) -> dict[str, Any]:
    correction_count = len(family_sanity.get("correction_suggestions", []))
    top_family = families[0] if families else {}
    top_candidates = scored[:10]
    top_need_rag = any(i["family"] in {"x509_parsing", "pkcs_container_parsing", "tls_protocol_state_lifecycle"} for i in top_candidates)
    if correction_count >= 20:
        next_task = "manual_review_family_corrections_v1"
        proposed_path = "先复核 ingestion family 规则，再将高置信候选交给 scheduler"
    elif top_family.get("suspicious_concentration"):
        next_task = "historical_poc_ingestion_rules_refinement_v1"
        proposed_path = "先修正 suspicious family concentration"
    elif top_need_rag:
        next_task = "rag_enrichment_from_ingestion_v1"
        proposed_path = "先补结构化 API/RAG evidence，再进入 template generalization"
    else:
        next_task = "template_generalizer_v1"
        proposed_path = "直接对 top staging candidates 生成 source template 草案"
    return {
        "next_task_name": next_task,
        "proposed_path": proposed_path,
        "why": {
            "correction_suggestion_count": correction_count,
            "top_family": top_family.get("family"),
            "top_family_suspicious": top_family.get("suspicious_concentration"),
            "top_candidates_need_rag": top_need_rag,
        },
        "top_candidates": [i["poc_id"] for i in top_candidates[:5]],
    }


def rag_decision(rag_snippets_count: int, scored: list[dict[str, Any]]) -> dict[str, Any]:
    high = sum(1 for i in scored if i.get("quality_confidence") == "high")
    top_families = {i["family"] for i in scored[:10]}
    needs_mapping = bool(top_families & {"x509_parsing", "pkcs_container_parsing", "tls_protocol_state_lifecycle"})
    if needs_mapping:
        should = True
        task = "rag_enrichment_from_ingestion_v1"
        reason = "top candidates include parser/protocol families likely needing API constraints and cross-library mapping evidence"
    else:
        should = False
        task = "delay_until_template_generalizer"
        reason = "top candidates are mostly template-generalization ready; formal RAG import can wait"
    return {
        "rag_next_action": {
            "rag_candidate_snippets_count": rag_snippets_count,
            "high_confidence_snippets": high,
            "should_import_now": should,
            "reason": reason,
            "recommended_task": task,
        }
    }


def write_input_summary(out: Path, base_dir: Path, candidates: list[dict[str, Any]], eligible: list[dict[str, Any]], excluded: list[dict[str, Any]], feedback: dict[str, Any]) -> None:
    obj = {
        "input_source": "ingestion_review_and_import_v1 plus existing auto_scheduler_v1 outputs",
        "base_scheduler_dir": str(base_dir),
        "reviewed_candidates": len(candidates),
        "eligible": len(eligible),
        "excluded": len(excluded),
        "feedback_files": feedback["total_feedback_files"],
        "feedback_rows": feedback["total_feedback_rows"],
        "constraints": {
            "only_high_and_medium": True,
            "blocked_needs_review_excluded": True,
            "staging_only": True,
            "formal_pattern_bank_write": False,
        },
    }
    dump_yaml(out / "input" / "scheduler_rerun_input_summary.yaml", obj)
    (out / "input" / "scheduler_rerun_input_summary.md").write_text(
        "# scheduler rerun input summary\n\n"
        "- 本轮新增输入来自 `ingestion_review_and_import_v1`。\n"
        "- 只使用 `high_confidence_import_candidate` 和 `medium_confidence_staging`。\n"
        "- `blocked` / `needs_manual_review` 不进入主调度。\n"
        "- 本轮是 staging-only rerun，不写正式 Pattern Bank。\n\n"
        + md_table(["metric", "value"], [[k, v] for k, v in obj.items() if not isinstance(v, dict)]),
        encoding="utf-8",
    )


def write_eligible(out: Path, eligible: list[dict[str, Any]], excluded: list[dict[str, Any]]) -> None:
    obj = {"eligible_candidates": eligible, "excluded_candidates": excluded}
    dump_yaml(out / "parsed" / "eligible_ingestion_candidates.yaml", obj)
    (out / "parsed" / "eligible_ingestion_candidates.md").write_text(
        "# eligible ingestion candidates\n\n"
        + md_table(
            ["poc_id", "library", "family", "confidence", "import_status"],
            [[i.get("poc_id"), i.get("source_library"), i.get("family"), i.get("quality_confidence"), i.get("import_status")] for i in eligible],
        )
        + "\n## excluded\n\n"
        + md_table(["poc_id", "library", "reason"], [[i.get("poc_id"), i.get("source_library"), i.get("reason")] for i in excluded]),
        encoding="utf-8",
    )


def write_scores(out: Path, scored: list[dict[str, Any]]) -> None:
    dump_yaml(out / "scoring" / "ingestion_candidate_scores.yaml", {"scored_candidates": scored})
    (out / "scoring" / "ingestion_candidate_scores.md").write_text(
        "# ingestion candidate scores\n\n"
        + md_table(
            ["rank", "poc_id", "library", "family", "score", "confidence"],
            [[idx, i["poc_id"], i["source_library"], i["family"], i["ingestion_scheduler_score"]["final_score"], i["quality_confidence"]] for idx, i in enumerate(scored, 1)],
        ),
        encoding="utf-8",
    )


def write_family_rerank(out: Path, rows: list[dict[str, Any]]) -> None:
    dump_yaml(out / "scoring" / "family_rerank_with_ingestion.yaml", {"families": rows})
    (out / "scoring" / "family_rerank_with_ingestion.md").write_text(
        "# family rerank with ingestion\n\n"
        + md_table(
            ["rank", "family", "count", "high", "medium", "avg", "max", "suspicious", "next_action"],
            [[r["family_rank"], r["family"], r["candidate_count"], r["high_confidence_count"], r["medium_confidence_count"], r["avg_score"], r["max_score"], r["suspicious_concentration"], r["recommended_next_action"]] for r in rows],
        ),
        encoding="utf-8",
    )


def write_decisions(out: Path, next_task: dict[str, Any], rag: dict[str, Any]) -> None:
    dump_yaml(out / "output" / "next_task_recommendation.yaml", next_task)
    (out / "output" / "next_task_recommendation.md").write_text(
        "# next task recommendation\n\n"
        + md_table(["field", "value"], [[k, v] for k, v in next_task.items() if k != "why"])
        + "\n## why\n\n"
        + md_table(["signal", "value"], [[k, v] for k, v in next_task.get("why", {}).items()]),
        encoding="utf-8",
    )
    dump_yaml(out / "output" / "rag_next_action_decision.yaml", rag)
    (out / "output" / "rag_next_action_decision.md").write_text(
        "# RAG next action decision\n\n"
        + md_table(["field", "value"], [[k, v] for k, v in rag["rag_next_action"].items()]),
        encoding="utf-8",
    )


def write_report(out: Path, candidates: list[dict[str, Any]], eligible: list[dict[str, Any]], excluded: list[dict[str, Any]], scored: list[dict[str, Any]], families: list[dict[str, Any]], next_task: dict[str, Any], rag: dict[str, Any]) -> dict[str, Any]:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reviewed_candidates_read": len(candidates),
        "eligible_count": len(eligible),
        "excluded_count": len(excluded),
        "top_poc_candidates": [{"rank": idx, "poc_id": i["poc_id"], "family": i["family"], "score": i["ingestion_scheduler_score"]["final_score"]} for idx, i in enumerate(scored[:3], 1)],
        "top_families": [{"rank": r["family_rank"], "family": r["family"], "max_score": r["max_score"], "avg_score": r["avg_score"]} for r in families[:3]],
        "bignum_concentration_affects_sorting": any(r["family"] == "bignum_serialization_boundary" and r["suspicious_concentration"] for r in families),
        "wolfssl_pushes_new_family": any("wolfssl" in r["source_libraries"] and r["family"] in {"tls_protocol_state_lifecycle", "pkcs_container_parsing", "x509_parsing"} for r in families),
        "next_task_name": next_task["next_task_name"],
        "rag_recommended_task": rag["rag_next_action"]["recommended_task"],
        "scheduler_seed_modified": False,
        "pattern_bank_modified": False,
        "knowledge_raw_modified": False,
        "run_poc": False,
        "glm": False,
        "render": False,
        "confirmed_vulnerability": False,
        "candidate_only": True,
    }
    dump_yaml(out / "reports" / "auto_scheduler_rerun_with_ingestion_report.yaml", report)
    (out / "reports" / "auto_scheduler_rerun_with_ingestion_report.md").write_text(
        "# auto_scheduler_v1 rerun with ingestion candidates\n\n"
        + md_table(["metric", "value"], [[k, v] for k, v in report.items() if not isinstance(v, list)])
        + "\n## top PoC candidates\n\n"
        + md_table(["rank", "poc_id", "family", "score"], [[i["rank"], i["poc_id"], i["family"], i["score"]] for i in report["top_poc_candidates"]])
        + "\n## top families\n\n"
        + md_table(["rank", "family", "max_score", "avg_score"], [[i["rank"], i["family"], i["max_score"], i["avg_score"]] for i in report["top_families"]]),
        encoding="utf-8",
    )
    (out / "README.md").write_text(
        "# auto_scheduler_v1_rerun_with_ingestion_candidates\n\n"
        "Staging-only scheduler rerun using reviewed ingestion candidates. "
        "No PoCs were run, no rendering/GLM/RAG rebuild happened, and no formal Pattern Bank or scheduler seed files were modified.\n",
        encoding="utf-8",
    )
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-scheduler-dir", required=True)
    ap.add_argument("--ingestion-candidates", required=True)
    ap.add_argument("--quality-review", required=True)
    ap.add_argument("--family-sanity", required=True)
    ap.add_argument("--feedback-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out = Path(args.out_dir)
    for sub in ("input", "parsed", "scoring", "routes", "output", "reports", "logs", "validation"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    candidates = load_candidates(Path(args.ingestion_candidates))
    load_yaml(Path(args.quality_review))
    family_sanity = load_yaml(Path(args.family_sanity))
    feedback = feedback_summary(Path(args.feedback_dir))
    eligible, excluded = split_candidates(candidates)
    write_input_summary(out, Path(args.base_scheduler_dir), candidates, eligible, excluded, feedback)
    write_eligible(out, eligible, excluded)

    family_counts = Counter(i.get("family") for i in eligible)
    scored = [score_candidate(i, family_sanity, family_counts) for i in eligible]
    scored.sort(key=lambda i: (-i["ingestion_scheduler_score"]["final_score"], i["family"], i["poc_id"], str(i.get("artifact_path", ""))))
    write_scores(out, scored)

    families = family_rerank(scored, family_sanity)
    write_family_rerank(out, families)
    next_task = decide_next_task(scored, families, family_sanity)
    rag_count = load_jsonl_count(Path("artifacts/sprints/ingestion_review_and_import_v1/rag/rag_candidate_snippets.jsonl"))
    rag = rag_decision(rag_count, scored)
    write_decisions(out, next_task, rag)
    report = write_report(out, candidates, eligible, excluded, scored, families, next_task, rag)
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

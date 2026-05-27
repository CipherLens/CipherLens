import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


VERDICT_SCORE = {
    "bug_candidate": 100,
    "sanitizer_crash": 90,
    "ubsan_crash": 85,
    "nonzero_needs_triage": 60,
    "normal_behavior_needs_triage": 50,
    "fixed_behavior": 20,
    "safe_behavior": 10,
    "harness_input_error": -20,
    "build_or_template_error": -50,
    "compile_error": -50,
    "timeout": -30,
    "unknown": 0,
}


def load_summary(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v), 0)
    except Exception:
        return default


def is_negative(v: Any) -> bool:
    try:
        return int(str(v), 0) < 0
    except Exception:
        return False


def hex_digit_len(v: Any) -> int:
    s = str(v).lower()
    if s.startswith("0x"):
        s = s[2:]
    return len(s)


def boundary_score(case: Dict[str, Any]) -> int:
    mapping = case.get("mutation_mapping", {}) or {}
    template_id = case.get("template_id", "")

    score = 0

    if template_id == "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER":
        value = mapping.get("[VALUE]")
        buflen = parse_int(mapping.get("[BUFLEN]"), 999)
        radix = parse_int(mapping.get("[RADIX]"), 10)

        if is_negative(value):
            score += 10

        if buflen == 0:
            score += 20
        elif buflen <= 2:
            score += 15
        elif buflen <= 4:
            score += 8

        if radix in (2, 16):
            score += 5

    elif template_id == "BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY":
        a_value = mapping.get("[A_VALUE]", "0")
        b_value = mapping.get("[B_VALUE]", "0")
        x_limb_count = parse_int(mapping.get("[X_LIMB_COUNT]"), 99)

        if x_limb_count == 1:
            score += 20
        elif x_limb_count == 2:
            score += 12
        elif x_limb_count == 3:
            score += 6

        if hex_digit_len(b_value) > hex_digit_len(a_value):
            score += 10

    return score


def trigger_path_score(case: Dict[str, Any]) -> int:
    mapping = case.get("mutation_mapping", {}) or {}
    template_id = case.get("template_id", "")

    score = 0

    if template_id == "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER":
        if is_negative(mapping.get("[VALUE]")) and parse_int(mapping.get("[BUFLEN]"), 999) <= 4:
            score += 15

    elif template_id == "BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY":
        # This template targets A < B with undersized X.
        x_limb_count = parse_int(mapping.get("[X_LIMB_COUNT]"), 99)
        if x_limb_count <= 2:
            score += 15

    return score


def wycheproof_seed_bonus(case: Dict[str, Any]) -> int:
    """
    Reserved for templates backed by Wycheproof vectors.

    Current bignum templates are API-boundary templates rather than direct
    Wycheproof test-vector templates, so this returns 0 for now.
    """
    mapping = case.get("mutation_mapping", {}) or {}
    source = mapping.get("[SEED_SOURCE]") or case.get("seed_source")
    result = mapping.get("[WYCHEPROOF_RESULT]") or case.get("wycheproof_result")

    if source == "wycheproof":
        if result == "invalid":
            return 20
        if result == "acceptable":
            return 10
        if result == "valid":
            return 5

    return 0


def score_case(case: Dict[str, Any]) -> Dict[str, Any]:
    verdict = case.get("verdict", "unknown")

    v_score = VERDICT_SCORE.get(verdict, 0)
    b_score = boundary_score(case)
    t_score = trigger_path_score(case)
    w_score = wycheproof_seed_bonus(case)

    total = v_score + b_score + t_score + w_score

    scored = dict(case)
    scored["fitness"] = {
        "total": total,
        "verdict_score": v_score,
        "boundary_score": b_score,
        "trigger_path_score": t_score,
        "wycheproof_seed_bonus": w_score,
    }

    return scored


def main() -> int:
    parser = argparse.ArgumentParser(description="Score analyzed cases for feedback-driven mutation.")
    parser.add_argument(
        "--input",
        default="runner/results/run_bignum_batch.summary.json",
        help="Input summary json from runner.analyze_results.",
    )
    parser.add_argument(
        "--output",
        default="runner/results/run_bignum_batch.scored.jsonl",
        help="Output scored cases jsonl.",
    )
    parser.add_argument(
        "--summary-output",
        default="runner/results/run_bignum_batch.score_summary.json",
        help="Output score summary json.",
    )
    args = parser.parse_args()

    summary = load_summary(Path(args.input))
    cases = summary.get("cases", [])

    scored_cases = [score_case(c) for c in cases]
    scored_cases.sort(key=lambda c: c["fitness"]["total"], reverse=True)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        for c in scored_cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    score_summary = {
        "input": args.input,
        "total_cases": len(scored_cases),
        "top_cases": scored_cases[:10],
        "score_distribution": {
            "max": max((c["fitness"]["total"] for c in scored_cases), default=0),
            "min": min((c["fitness"]["total"] for c in scored_cases), default=0),
        },
    }

    summary_path = Path(args.summary_output)
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(score_summary, f, ensure_ascii=False, indent=2)

    print(f"[OK] scored cases written to {out_path}")
    print(f"[OK] score summary written to {summary_path}")
    print(f"[INFO] total cases: {len(scored_cases)}")

    for c in scored_cases[:10]:
        print(
            c.get("relative_source"),
            "verdict=", c.get("verdict"),
            "fitness=", c["fitness"]["total"],
            "mapping=", c.get("mutation_mapping"),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

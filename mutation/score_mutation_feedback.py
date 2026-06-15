import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Tuple

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


CATEGORY_WEIGHTS = {
    "crash_candidate": 5.0,
    "unexpected_success_candidate": 4.0,
    "behavior_divergence_candidate": 2.5,
    "triage": 2.0,
    "harness_error": 0.5,
    "normal_expected_behavior": 0.0,
    "safe_negative": -0.2,
    "projection_limitation": -1.0,
}

HIGH_VALUE_PRIOR = {
    "wrong_hash_length": 1.2,
    "wrong_digest_algorithm": 0.8,
    "wrong_key": 0.8,
    "invalid_signature": 0.8,
    "pss_saltlen_mismatch": 1.2,
}


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def classify(score: float, counts: Counter) -> str:
    total = sum(counts.values())
    safe = counts.get("safe_negative", 0) + counts.get("normal_expected_behavior", 0)
    if counts.get("projection_limitation", 0) and counts.get("projection_limitation", 0) >= safe:
        return "projection_limitation"
    if score >= 1.0:
        return "upweighted"
    if total and safe == total:
        return "stable_safe_negative"
    if score <= 0.1:
        return "downweighted"
    return "neutral"


def score_feedback(feedback_path: Path) -> Dict[str, Any]:
    rows = list(read_jsonl(feedback_path))
    family_counts = Counter(str(row.get("family", "")) for row in rows)
    aggregates: DefaultDict[Tuple[str, str, str], Dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "weighted_sum": 0.0,
            "feedback_categories": Counter(),
            "verdicts": Counter(),
            "examples": [],
        }
    )

    for row in rows:
        family = str(row.get("family") or "")
        category = str(row.get("feedback_category") or "")
        weight = CATEGORY_WEIGHTS.get(category, 0.0)
        values = row.get("mutation_values") or {}
        for dimension, value in values.items():
            key = (family, str(dimension), str(value))
            agg = aggregates[key]
            agg["count"] += 1
            agg["weighted_sum"] += weight
            agg["feedback_categories"][category] += 1
            agg["verdicts"][str(row.get("verdict") or "")] += 1
            if len(agg["examples"]) < 5:
                agg["examples"].append(str(row.get("case_id") or ""))

    families: Dict[str, Any] = {}
    for (family, dimension, value), agg in sorted(aggregates.items()):
        family_obj = families.setdefault(family, {"dimensions": {}})
        dim_obj = family_obj["dimensions"].setdefault(dimension, {"values": {}})
        prior = HIGH_VALUE_PRIOR.get(value, 0.0)
        raw_score = (agg["weighted_sum"] / max(agg["count"], 1)) + prior
        value_score = max(0.05, round(raw_score, 4))
        categories = Counter(agg["feedback_categories"])
        dim_obj["values"][value] = {
            "score": value_score,
            "raw_score": round(raw_score, 4),
            "count": agg["count"],
            "feedback_categories": dict(categories),
            "verdicts": dict(agg["verdicts"]),
            "classification": classify(value_score, categories),
            "examples": agg["examples"],
            "high_value_prior": prior,
        }

    return {
        "schema_version": 1,
        "source_feedback": str(feedback_path),
        "summary": {
            "total_rows": len(rows),
            "families": dict(family_counts),
        },
        "families": families,
        "notes": [
            "Scores are value-level priorities for feedback-guided mutation planning.",
            "Stable safe-negative values are downweighted but retained for regression coverage.",
            "High-value priors keep promising semantic dimensions alive even after an all-safe v0 run.",
        ],
    }


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Score mutation feedback by dimension/value.")
    parser.add_argument("--feedback", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    scores = score_feedback(args.feedback)
    dump_yaml(args.out, scores)
    print(f"[OK] mutation scores written to {args.out}")
    print(f"[INFO] feedback_rows: {scores.get('summary', {}).get('total_rows')}")
    print(f"[INFO] families: {scores.get('summary', {}).get('families')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

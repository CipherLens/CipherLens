import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def load_optional_yaml(path: Optional[Path]) -> Dict[str, Any]:
    if not path:
        return {}
    if not path.exists():
        return {}
    return load_yaml(path)


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def candidate_list_key(obj: Dict[str, Any]) -> str:
    if "target_candidates" in obj:
        return "target_candidates"
    if "candidates" in obj:
        return "candidates"
    return "target_candidates"


def family_rule(rules: Dict[str, Any], family: str) -> Dict[str, Any]:
    families = rules.get("families", {})
    if family in families:
        return families[family] or {}
    wanted = normalize(family)
    for name, rule in families.items():
        aliases = {normalize(name)}
        aliases.update(normalize(x) for x in as_list((rule or {}).get("aliases")))
        if wanted in aliases:
            return rule or {}
    return {}


def apply_profile(rule: Dict[str, Any], profile: str) -> Dict[str, Any]:
    if not profile:
        return rule
    profiles = rule.get("profiles", {}) or {}
    profile_rule = profiles.get(profile)
    if not isinstance(profile_rule, dict):
        raise ValueError(f"No mutation profile {profile!r} found for selected family")

    merged = dict(rule)
    for key, value in profile_rule.items():
        if key == "mutation_dimensions" and isinstance(value, dict):
            base_dims = dict((rule.get("mutation_dimensions", {}) or {}))
            merged_dims = dict(value)
            for dim_name, dim_value in base_dims.items():
                if dim_name not in merged_dims:
                    merged_dims[dim_name] = dim_value
            merged[key] = merged_dims
        else:
            merged[key] = value
    merged["selected_profile"] = profile
    return merged


def select_candidate(candidates_obj: Dict[str, Any]) -> Dict[str, Any]:
    candidates = candidates_obj.get(candidate_list_key(candidates_obj), []) or []
    for cand in candidates:
        if isinstance(cand, dict) and cand.get("decision") == "generate":
            return cand
    for cand in candidates:
        if isinstance(cand, dict):
            return cand
    raise ValueError("No candidate entries found")


def select_optional_candidate(candidates_obj: Dict[str, Any]) -> Dict[str, Any]:
    if not candidates_obj:
        return {}
    return select_candidate(candidates_obj)


def cards_from_candidate(candidate: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = candidate.get("api_card_evidence", {})
    if not isinstance(evidence, dict):
        evidence = candidate.get("evidence", {}).get("api_card_evidence", {})
    cards = evidence.get("matched_cards", []) if isinstance(evidence, dict) else []
    return [card for card in cards if isinstance(card, dict)]


def discover_family_cards(api_cards_root: Path, family: str, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not api_cards_root.exists():
        return []
    wanted = {normalize(family)}
    wanted.update(normalize(x) for x in as_list(rule.get("aliases")))
    cards: List[Dict[str, Any]] = []
    for path in sorted(api_cards_root.glob("*/*.yaml")):
        try:
            card = load_yaml(path)
        except Exception:
            continue
        if not isinstance(card, dict):
            continue
        card_family = normalize(card.get("family"))
        if card_family not in wanted:
            continue
        card = dict(card)
        card["path"] = str(path)
        card["match_reason"] = "family_card_fallback"
        cards.append(card)
    return cards


def lifecycle_values_from_hints(cards: List[Dict[str, Any]]) -> Set[str]:
    values: Set[str] = set()
    text = "\n".join(
        " ".join(str(x) for x in card.get("mutation_hints", []) or [])
        for card in cards
    ).lower()
    if "final before setup" in text or "finish before setup" in text:
        values.add("final_before_setup")
    if "update before setup" in text:
        values.add("update_before_setup")
    if "get size before setup" in text:
        values.add("query_size_before_setup")
    if "double final" in text or "double finish" in text:
        values.update({"setup_update_final_final", "setup_final_final"})
    if "abort then final" in text:
        values.add("abort_then_final")
    if "wrong digest" in text:
        values.add("wrong_digest_combo")
    return values


def merge_dimensions(
    rule: Dict[str, Any],
    cards: List[Dict[str, Any]],
    merge_card_hints: bool = True,
) -> Dict[str, Dict[str, Any]]:
    dimensions: Dict[str, Dict[str, Any]] = {}
    for name, cfg in (rule.get("mutation_dimensions", {}) or {}).items():
        if not isinstance(cfg, dict):
            continue
        dimensions[name] = {
            "values": [str(x) for x in as_list(cfg.get("values"))],
            "source": "family_rule",
        }

    lifecycle_from_cards = lifecycle_values_from_hints(cards) if merge_card_hints else set()
    if lifecycle_from_cards:
        existing = set(dimensions.get("lifecycle_sequence", {}).get("values", []) or [])
        merged = sorted(existing | lifecycle_from_cards)
        dimensions["lifecycle_sequence"] = {
            "values": merged,
            "source": "family_rule+api_cards",
        }
    return dimensions


def load_feedback_scores(path: Optional[Path]) -> Dict[str, Any]:
    return load_optional_yaml(path)


def feedback_family(scores: Dict[str, Any], family: str) -> Dict[str, Any]:
    families = scores.get("families", {}) if isinstance(scores, dict) else {}
    if not isinstance(families, dict):
        return {}
    if family in families:
        return families.get(family) or {}
    wanted = normalize(family)
    for name, obj in families.items():
        if normalize(name) == wanted:
            return obj or {}
    return {}


def apply_feedback_guidance(
    dimensions: Dict[str, Dict[str, Any]],
    scores: Dict[str, Any],
    family: str,
    high_value_sequences: List[str],
) -> Dict[str, Any]:
    family_scores = feedback_family(scores, family)
    scored_dims = family_scores.get("dimensions", {}) if isinstance(family_scores, dict) else {}
    guidance = {
        "enabled": True,
        "source_feedback": scores.get("source_feedback", ""),
        "upweighted_values": {},
        "downweighted_values": {},
        "stable_safe_negative": {},
        "projection_limitations": {},
    }
    high_value = {str(x) for x in high_value_sequences}

    for dim_name, dim_cfg in dimensions.items():
        values = [str(x) for x in dim_cfg.get("values", []) or []]
        value_scores = ((scored_dims.get(dim_name) or {}).get("values") or {}) if isinstance(scored_dims, dict) else {}
        annotated = {}

        def value_priority(value: str) -> float:
            score_obj = value_scores.get(value) if isinstance(value_scores, dict) else None
            score = float((score_obj or {}).get("score", 0.5))
            if value in high_value:
                score += 1.0
            return score

        ordered = sorted(values, key=lambda value: (-value_priority(value), values.index(value)))
        dim_cfg["values"] = ordered
        for value in ordered:
            score_obj = value_scores.get(value, {}) if isinstance(value_scores, dict) else {}
            score = float(score_obj.get("score", 0.5))
            classification = str(score_obj.get("classification", "unseen"))
            annotated[value] = {
                "score": score,
                "classification": classification,
                "count": int(score_obj.get("count", 0) or 0),
                "feedback_categories": score_obj.get("feedback_categories", {}) or {},
            }
            if classification == "upweighted" or value in high_value:
                guidance["upweighted_values"].setdefault(dim_name, []).append(value)
            if classification in {"downweighted", "stable_safe_negative"} and value not in high_value:
                guidance["downweighted_values"].setdefault(dim_name, []).append(value)
            if classification == "stable_safe_negative":
                guidance["stable_safe_negative"].setdefault(dim_name, []).append(value)
            if classification == "projection_limitation":
                guidance["projection_limitations"].setdefault(dim_name, []).append(value)
        dim_cfg["feedback"] = {
            "ordered_by_feedback": True,
            "value_scores": annotated,
        }

    return guidance


def api_card_summary(cards: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for card in cards:
        out.append({
            "path": card.get("path", ""),
            "library": card.get("library", ""),
            "api": card.get("api", ""),
            "family": card.get("family", ""),
            "match_reason": card.get("match_reason", ""),
            "mutation_hints": card.get("mutation_hints", []) or [],
            "oracle_observables": card.get("oracle_observables", []) or [],
        })
    return out


def build_plan(
    family: str,
    candidates_with_evidence: Optional[Path],
    rules_path: Path,
    api_cards_root: Path,
    profile: str = "",
    feedback_scores: Optional[Path] = None,
    feedback_guided: bool = False,
) -> Dict[str, Any]:
    candidates_obj = load_optional_yaml(candidates_with_evidence)
    rules = load_yaml(rules_path)
    rule = family_rule(rules, family)
    if not rule:
        raise ValueError(f"No family mutation rule found for {family!r}")
    rule = apply_profile(rule, profile)

    candidate = select_optional_candidate(candidates_obj)
    cards = cards_from_candidate(candidate)
    if not cards:
        cards = discover_family_cards(api_cards_root, family, rule)
    dimensions = merge_dimensions(rule, cards, merge_card_hints=not bool(rule.get("selected_profile")))
    high_value_sequences = [str(x) for x in as_list(rule.get("high_value_sequences"))]
    feedback_obj = load_feedback_scores(feedback_scores)
    feedback_guidance = {}
    if feedback_guided:
        feedback_guidance = apply_feedback_guidance(dimensions, feedback_obj, family, high_value_sequences)

    return {
        "family": family,
        "profile": rule.get("selected_profile", ""),
        "feedback_guided": bool(feedback_guided),
        "feedback_scores": str(feedback_scores or ""),
        "feedback_guidance": feedback_guidance,
        "source": {
            "pattern_id": candidates_obj.get("source_pattern_id", ""),
            "template_id": candidates_obj.get("template_id", ""),
            "source_library": candidates_obj.get("source_library", ""),
            "source_api": candidates_obj.get("source_api", ""),
            "oracle_type": candidates_obj.get("oracle_type", ""),
        },
        "target_candidate": {
            "target_library": candidate.get("target_library", ""),
            "target_api": candidate.get("target_api") or candidate.get("api", ""),
            "decision": candidate.get("decision", ""),
            "migration_applicability": candidate.get("migration_applicability", ""),
            "final_score": candidate.get("final_score", ""),
        },
        "evidence_sources": {
            "candidates_with_evidence": str(candidates_with_evidence or ""),
            "api_cards_root": str(api_cards_root),
            "api_cards": api_card_summary(cards),
        },
        "mutation_dimensions": dimensions,
        "legal_combinations": rule.get("legal_combinations", {}) or {},
        "projection_limitations": rule.get("projection_limitations", {}) or {},
        "feedback_sources": [str(x) for x in as_list(rule.get("feedback_sources"))],
        "high_value_sequences": high_value_sequences,
        "oracle_observables": [str(x) for x in as_list(rule.get("oracle_observables"))],
        "expected_candidate_types": [str(x) for x in as_list(rule.get("expected_candidate_types"))],
        "notes": [
            "This file is a family-level mutation plan only.",
            "It does not generate C harness code.",
            "render_cases.py does not consume this plan directly in the current pipeline.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a family-level mutation plan from candidate evidence.")
    parser.add_argument("--family", required=True)
    parser.add_argument("--candidates-with-evidence", type=Path)
    parser.add_argument("--api-cards-root", default="knowledge_base/api_cards", type=Path)
    parser.add_argument("--rules", default="config/family_mutation_rules.yaml", type=Path)
    parser.add_argument("--profile", default="", help="Optional family mutation profile name.")
    parser.add_argument("--feedback-scores", type=Path)
    parser.add_argument("--feedback-guided", action="store_true")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    plan = build_plan(
        family=args.family,
        candidates_with_evidence=args.candidates_with_evidence,
        rules_path=args.rules,
        api_cards_root=args.api_cards_root,
        profile=args.profile,
        feedback_scores=args.feedback_scores,
        feedback_guided=args.feedback_guided,
    )
    dump_yaml(args.out, plan)
    print(f"[OK] mutation plan written to {args.out}")
    print(f"[INFO] family: {plan.get('family')}")
    if plan.get("profile"):
        print(f"[INFO] profile: {plan.get('profile')}")
    print(f"[INFO] dimensions: {list((plan.get('mutation_dimensions') or {}).keys())}")
    print(f"[INFO] api_cards: {[c.get('api') for c in plan.get('evidence_sources', {}).get('api_cards', [])]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

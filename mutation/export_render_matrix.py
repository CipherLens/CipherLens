import argparse
import itertools
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import yaml

from template_maker.mac_lifecycle_sequences import build_mac_lifecycle_plan


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


def dimension_values(plan: Dict[str, Any]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for name, cfg in (plan.get("mutation_dimensions", {}) or {}).items():
        if not isinstance(cfg, dict):
            continue
        values = [str(x) for x in (cfg.get("values", []) or [])]
        if values:
            out[str(name)] = values
    return out


def classify_case(plan: Dict[str, Any], values: Dict[str, str]) -> Tuple[str, List[Dict[str, Any]], List[str], bool]:
    family = str(plan.get("family") or "")
    high_value_sequences = set(str(x) for x in plan.get("high_value_sequences", []) or [])
    lifecycle_sequence = str(values.get("lifecycle_sequence", ""))
    is_high_value = lifecycle_sequence in high_value_sequences
    if not is_high_value:
        is_high_value = any(str(value) in high_value_sequences for value in values.values())

    if family == "mac_lifecycle":
        mac_plan = build_mac_lifecycle_plan(
            str(values.get("mac_algorithm", "")),
            str(values.get("digest_or_cipher", "")),
            lifecycle_sequence,
        )
        status = "supported" if mac_plan.supported else "projection_limitation"
        return status, mac_plan.unsupported_dimensions, mac_plan.expected_candidate_types, is_high_value

    return "supported", [], plan.get("expected_candidate_types", []) or [], is_high_value


def case_feedback_score(plan: Dict[str, Any], values: Dict[str, str]) -> float:
    if not plan.get("feedback_guided"):
        return 0.0
    total = 0.0
    dims = plan.get("mutation_dimensions", {}) or {}
    for dim_name, value in values.items():
        dim_cfg = dims.get(dim_name, {}) if isinstance(dims, dict) else {}
        feedback = dim_cfg.get("feedback", {}) if isinstance(dim_cfg, dict) else {}
        value_scores = feedback.get("value_scores", {}) if isinstance(feedback, dict) else {}
        score_obj = value_scores.get(value, {}) if isinstance(value_scores, dict) else {}
        total += float(score_obj.get("score", 0.5) or 0.5)
        if str(score_obj.get("classification", "")) == "projection_limitation":
            total -= 1.0
    return round(total, 4)


def _ranked(value: str, order: List[str]) -> int:
    try:
        return order.index(value)
    except ValueError:
        return len(order)


def pkey_verify_sort_key(case: Dict[str, Any]) -> Tuple[int, ...]:
    values = case.get("values", {}) or {}
    return (
        0 if case.get("matrix_status") == "supported" else 1,
        _ranked(str(values.get("key_type", "")), ["rsa", "ec"]),
        _ranked(str(values.get("digest_mutation", "")), ["matching_digest", "wrong_digest_algorithm", "wrong_hash_length", "zero_length_hash", "one_byte_hash"]),
        _ranked(str(values.get("key_mutation", "")), ["matching_key", "wrong_key", "public_only", "mismatched_key_type"]),
        _ranked(str(values.get("signature_mutation", "")), ["valid_signature", "truncated_signature", "all_zero_signature", "bitflip_signature", "invalid_signature", "random_signature", "oversized_signature"]),
        _ranked(str(values.get("verify_api", "")), ["EVP_DigestVerify", "EVP_PKEY_verify", "psa_verify_hash", "mbedtls_pk_verify"]),
        _ranked(str(values.get("padding_mutation", "")), ["rsa_pkcs1_v15", "rsa_pss", "pss_saltlen_mismatch"]),
    )


def select_pkey_verify_cases(matrix: List[Dict[str, Any]], max_cases: int) -> List[Dict[str, Any]]:
    if max_cases <= 0 or len(matrix) <= max_cases:
        return matrix

    dims = [
        "verify_api",
        "padding_mutation",
        "signature_mutation",
        "digest_mutation",
        "key_mutation",
    ]
    selected: List[Dict[str, Any]] = []
    selected_ids: Set[str] = set()
    coverage: Dict[Tuple[str, str], int] = {}

    def add(case: Dict[str, Any]) -> None:
        case_id = str(case.get("case_id"))
        if case_id in selected_ids or len(selected) >= max_cases:
            return
        selected.append(case)
        selected_ids.add(case_id)
        values = case.get("values", {}) or {}
        for dim in dims:
            key = (dim, str(values.get(dim, "")))
            coverage[key] = coverage.get(key, 0) + 1

    preferred_baselines = [
        {"verify_api": api, "padding_mutation": padding}
        for api in ["EVP_DigestVerify", "EVP_PKEY_verify"]
        for padding in ["rsa_pkcs1_v15", "rsa_pss", "pss_saltlen_mismatch"]
    ]
    for wanted in preferred_baselines:
        for case in matrix:
            values = case.get("values", {}) or {}
            if (
                values.get("key_type") == "rsa"
                and values.get("signature_mutation") == "valid_signature"
                and values.get("digest_mutation") == "matching_digest"
                and values.get("key_mutation") == "matching_key"
                and all(values.get(k) == v for k, v in wanted.items())
            ):
                add(case)
                break

    value_targets = []
    for dim in dims:
        values = sorted({str((case.get("values", {}) or {}).get(dim, "")) for case in matrix})
        for value in values:
            value_targets.append((dim, value))

    for dim, value in value_targets:
        if coverage.get((dim, value), 0):
            continue
        for case in matrix:
            values = case.get("values", {}) or {}
            if str(values.get(dim, "")) == value:
                add(case)
                break

    def score(case: Dict[str, Any]) -> Tuple[int, int, int, Tuple[int, ...]]:
        values = case.get("values", {}) or {}
        novelty = 0
        scarcity = 0
        for dim in dims:
            key = (dim, str(values.get(dim, "")))
            count = coverage.get(key, 0)
            if count == 0:
                novelty += 4
            elif count < 4:
                novelty += 2
            scarcity -= count
        high_value = 1 if case.get("high_value") else 0
        feedback = int(float(case.get("feedback_score", 0.0) or 0.0) * 100)
        return (novelty, high_value, feedback, scarcity, tuple(-x for x in pkey_verify_sort_key(case)))

    candidates = [case for case in matrix if str(case.get("case_id")) not in selected_ids]
    while candidates and len(selected) < max_cases:
        best = max(candidates, key=score)
        add(best)
        candidates = [case for case in candidates if str(case.get("case_id")) not in selected_ids]

    return selected


def build_case_matrix(plan: Dict[str, Any], max_cases: int) -> List[Dict[str, Any]]:
    dims = dimension_values(plan)
    keys = list(dims.keys())
    matrix: List[Dict[str, Any]] = []
    for idx, combo in enumerate(itertools.product(*(dims[key] for key in keys))):
        values = dict(zip(keys, combo))
        status, unsupported, expected_candidate_types, is_high_value = classify_case(plan, values)
        matrix.append({
            "case_id": f"{plan.get('family', 'family')}_{idx:04d}",
            "values": values,
            "matrix_status": status,
            "unsupported_dimensions": unsupported,
            "high_value": is_high_value,
            "feedback_score": case_feedback_score(plan, values),
            "oracle_observables": plan.get("oracle_observables", []) or [],
            "expected_candidate_types": expected_candidate_types,
        })
    if str(plan.get("family") or "") == "pkey_verify_semantic":
        matrix.sort(key=pkey_verify_sort_key)
        matrix = select_pkey_verify_cases(matrix, max_cases)
    elif max_cases > 0:
        matrix = matrix[:max_cases]
    return matrix


def matrix_counts(case_matrix: List[Dict[str, Any]]) -> Dict[str, Any]:
    supported = [case for case in case_matrix if case.get("matrix_status") == "supported"]
    projection = [case for case in case_matrix if case.get("matrix_status") == "projection_limitation"]
    skipped = [case for case in case_matrix if case.get("matrix_status") not in {"supported", "projection_limitation"}]
    high_value = [case for case in case_matrix if case.get("high_value")]
    supported_high_value = [case for case in supported if case.get("high_value")]
    projection_high_value = [case for case in projection if case.get("high_value")]
    return {
        "case_count": len(case_matrix),
        "supported_cases": len(supported),
        "skipped_cases": len(skipped),
        "projection_limitation_cases": len(projection),
        "high_value_cases": len(high_value),
        "supported_high_value_cases": len(supported_high_value),
        "projection_high_value_cases": len(projection_high_value),
        "high_value_projection_limitation_cases": len(projection_high_value),
    }


def build_render_matrix(plan_path: Path, plan: Dict[str, Any], max_cases: int) -> Dict[str, Any]:
    case_matrix = build_case_matrix(plan, max_cases=max_cases)
    counts = matrix_counts(case_matrix)
    return {
        "source_mutation_plan": str(plan_path),
        "family": plan.get("family", ""),
        "profile": plan.get("profile", ""),
        "target_candidate": plan.get("target_candidate", {}),
        "feedback_guided": bool(plan.get("feedback_guided")),
        "feedback_scores": plan.get("feedback_scores", ""),
        "feedback_guidance": plan.get("feedback_guidance", {}) or {},
        "feedback_sources": plan.get("feedback_sources", []) or [],
        "high_value_sequences": plan.get("high_value_sequences", []) or [],
        "expected_candidate_types": plan.get("expected_candidate_types", []) or [],
        "legal_combinations": plan.get("legal_combinations", {}) or {},
        "projection_limitations": plan.get("projection_limitations", {}) or {},
        **counts,
        "render_pipeline_status": {
            "render_cases_direct_support": False,
            "blocking_point": (
                "template_maker/render_cases.py currently consumes cross-template "
                "case metadata, not external render_matrix.yaml."
            ),
            "next_integration_step": (
                "Add a renderer-side adapter that maps render_matrix entries into "
                "template_meta mutation_points or recipe slot bindings."
            ),
        },
        "mutation_dimensions": plan.get("mutation_dimensions", {}),
        "case_matrix": case_matrix,
        "notes": [
            "This matrix is an intermediate planning artifact.",
            "No C harness files are generated by this tool.",
            "Unsupported MAC lifecycle combinations are counted as projection_limitation_cases.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a render matrix from a family mutation plan.")
    parser.add_argument("--mutation-plan", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-cases", type=int, default=64)
    args = parser.parse_args()

    plan = load_yaml(args.mutation_plan)
    matrix = build_render_matrix(args.mutation_plan, plan, max_cases=args.max_cases)
    dump_yaml(args.out, matrix)
    print(f"[OK] render matrix written to {args.out}")
    print(f"[INFO] family: {matrix.get('family')}")
    print(f"[INFO] cases: {len(matrix.get('case_matrix', []))}")
    print(f"[INFO] supported_cases: {matrix.get('supported_cases')}")
    print(f"[INFO] projection_limitation_cases: {matrix.get('projection_limitation_cases')}")
    print(f"[INFO] high_value_cases: {matrix.get('high_value_cases')}")
    print(f"[INFO] supported_high_value_cases: {matrix.get('supported_high_value_cases')}")
    print(f"[INFO] projection_high_value_cases: {matrix.get('projection_high_value_cases')}")
    print(f"[INFO] render_cases_direct_support: {matrix.get('render_pipeline_status', {}).get('render_cases_direct_support')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

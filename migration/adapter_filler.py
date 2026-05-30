import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml

from utils.query_llm import get_glm_response


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


def sanitize_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s)


def candidate_library(candidate: Dict[str, Any]) -> str:
    return str(candidate.get("target_library") or candidate.get("library") or "")


def candidate_api(candidate: Dict[str, Any]) -> str:
    return str(candidate.get("target_api") or candidate.get("api") or "")


def strip_code_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_llm_json(text: str) -> Dict[str, Any]:
    text = strip_code_fence(text)

    try:
        return json.loads(text)
    except Exception:
        pass

    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON object found in LLM output")

    return json.loads(m.group(0))


def compact_evidence(
    candidate: Dict[str, Any],
    max_chars_per_query: int = 1200,
    max_chars_per_result: int = 900,
) -> Dict[str, Any]:
    ev = candidate.get("evidence", {})
    out = {
        "inferred_features": ev.get("inferred_features", {}),
        "queries": [],
    }

    for q in ev.get("queries", []):
        compact_query = {
            "kind": q.get("kind"),
            "use_for_feature_inference": q.get("use_for_feature_inference"),
            "query": q.get("query"),
            "json_mode": q.get("json_mode"),
            "top_k_requested": q.get("top_k_requested"),
            "returncode": q.get("returncode"),
            "results": [],
        }

        results = q.get("results", []) or []
        if results:
            for idx, r in enumerate(results, start=1):
                if not isinstance(r, dict):
                    continue
                metadata = r.get("metadata", {})
                if not isinstance(metadata, dict):
                    metadata = {}
                compact_query["results"].append(
                    {
                        "rank": r.get("rank", idx),
                        "score": r.get("score"),
                        "distance": r.get("distance"),
                        "layer": r.get("layer", ""),
                        "source_file": r.get("source_file", ""),
                        "text": (r.get("text") or "")[:max_chars_per_result],
                        "metadata": metadata,
                    }
                )
        else:
            compact_query["stdout_preview"] = (q.get("stdout_preview") or "")[:max_chars_per_query]

        out["queries"].append(compact_query)

    return out


def load_selected_mask_context(mask_report_path: Path, max_code_chars: int = 500) -> Dict[str, Any]:
    selected_path = mask_report_path.parent / "selected_mask_units.yaml"

    if not selected_path.exists():
        return {
            "available": False,
            "source_file": str(selected_path),
            "selected_units": [],
        }

    obj = load_yaml(selected_path)
    units = []

    for item in obj.get("selected_units", []) or []:
        if not isinstance(item, dict):
            continue
        units.append(
            {
                "unit_id": item.get("unit_id", ""),
                "mask_level": item.get("mask_level", ""),
                "role": item.get("role", ""),
                "placeholder": item.get("placeholder", ""),
                "code": (item.get("code") or "")[:max_code_chars],
                "suggested_use": item.get("suggested_use", ""),
                "selection_reason": item.get("selection_reason", ""),
                "selection_score": item.get("selection_score"),
            }
        )

    return {
        "available": True,
        "source_file": str(selected_path),
        "template_id": obj.get("template_id", ""),
        "source_api": obj.get("source_api", ""),
        "selected_units": units,
    }


def load_template_meta_for_mask(mask_report_path: Path) -> Dict[str, Any]:
    template_meta_path = mask_report_path.parent / "template_meta.yaml"
    if not template_meta_path.exists():
        return {}
    return load_yaml(template_meta_path)


def infer_harness_family(mask_report: Dict[str, Any], template_meta: Dict[str, Any]) -> str:
    return str(
        template_meta.get("harness_family")
        or mask_report.get("harness_family")
        or mask_report.get("poc_pattern", {}).get("harness_family")
        or ""
    )


def infer_oracle_type(mask_report: Dict[str, Any], template_meta: Dict[str, Any]) -> str:
    oracle = mask_report.get("oracle", {})
    return str(
        template_meta.get("oracle_type")
        or mask_report.get("oracle_type")
        or (oracle.get("type") if isinstance(oracle, dict) else "")
        or ""
    )


def find_adapter_recipe(
    candidate: Dict[str, Any],
    mask_report: Dict[str, Any],
    template_meta: Dict[str, Any],
) -> tuple[Path | None, Dict[str, Any]]:
    lib = candidate_library(candidate)
    api = candidate_api(candidate)
    harness_family = infer_harness_family(mask_report, template_meta)
    if not lib or not api or not harness_family:
        return None, {}

    recipe_path = Path("adapter_recipes") / lib / f"{api}.{harness_family}.yaml"
    if not recipe_path.exists():
        return None, {}

    recipe = load_yaml(recipe_path)
    if not recipe:
        return recipe_path, {}
    return recipe_path, recipe


def recipe_defaults(recipe: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    allowed = recipe.get("allowed_slots", {})
    if not isinstance(allowed, dict):
        return out
    for name, spec in allowed.items():
        if isinstance(spec, dict) and "default" in spec:
            out[str(name)] = spec["default"]
    return out


def clean_slot_bindings(bindings: Any, recipe: Dict[str, Any]) -> Dict[str, Any]:
    allowed = recipe.get("allowed_slots", {})
    allowed_keys = set(allowed.keys()) if isinstance(allowed, dict) else set()
    cleaned: Dict[str, Any] = {}
    if isinstance(bindings, dict):
        for key, value in bindings.items():
            if key in allowed_keys:
                cleaned[str(key)] = str(value)

    defaults = recipe_defaults(recipe)
    for key, value in defaults.items():
        cleaned.setdefault(key, str(value))
    return cleaned


def build_recipe_prompt(
    mask_report: Dict[str, Any],
    template_meta: Dict[str, Any],
    candidate: Dict[str, Any],
    recipe_path: Path,
    recipe: Dict[str, Any],
    selected_mask_context: Dict[str, Any] = None,
) -> List[Dict[str, str]]:
    poc_pattern = mask_report.get("poc_pattern", {})
    selected_mask_context = selected_mask_context or {"available": False, "selected_units": []}
    forbidden_terms = recipe.get("forbidden_terms", []) or []
    allowed_slots = recipe.get("allowed_slots", {}) or {}

    system_prompt = """You are an expert in cryptographic C API harness migration.
Your task is recipe-based adapter slot filling.

Important rules:
1. Output JSON only. No markdown. No code fences.
2. The C harness skeleton is fixed by the adapter recipe.
3. You must only bind slot names listed in allowed_slots.
4. Output only one top-level field: slot_bindings.
5. Do not output init_block, input_construction_block, trigger_block, cleanup_block, oracle_strategy, features, rationale, or any C code block.
6. Do not introduce forbidden terms.
7. Use mask_report, selected_mask_units, and RAG evidence only to choose slot bindings.
8. Prefer recipe defaults unless local evidence clearly requires a different variable name.
"""

    user_obj = {
        "task": "Generate recipe-based slot_bindings for a target API adapter.",
        "source": {
            "source_pattern_id": template_meta.get("source_pattern_id") or mask_report.get("poc_pattern", {}).get("pattern_id"),
            "template_id": template_meta.get("template_id") or mask_report.get("template_id"),
            "source_api": template_meta.get("source_api") or mask_report.get("source_api"),
            "harness_family": recipe.get("harness_family"),
            "oracle_type": recipe.get("oracle_type"),
            "root_cause": poc_pattern.get("root_cause", {}),
            "vulnerability_path_features": poc_pattern.get("vulnerability_path_features", {}),
            "mutation_points": template_meta.get("mutation_points") or poc_pattern.get("mutation_points", []),
        },
        "target": {
            "target_library": recipe.get("target_library"),
            "target_api": recipe.get("target_api"),
        },
        "recipe": {
            "path": str(recipe_path),
            "include_headers": recipe.get("include_headers", []),
            "fixed_setup_sequence": recipe.get("fixed_setup_sequence", []),
            "trigger_call": recipe.get("trigger_call", {}),
            "allowed_slots": allowed_slots,
            "safe_behavior": recipe.get("safe_behavior", {}),
            "bug_behavior": recipe.get("bug_behavior", {}),
            "unexpected_success": recipe.get("unexpected_success", {}),
            "forbidden_terms": forbidden_terms,
        },
        "candidate": {
            "library": candidate_library(candidate),
            "api": candidate_api(candidate),
            "decision": candidate.get("decision"),
            "scores": candidate.get("scores"),
            "reason": candidate.get("reason") or candidate.get("migration_reason"),
            "parameter_mapping": candidate.get("parameter_mapping"),
            "preserved_vulnerability_features": candidate.get("preserved_vulnerability_features") or candidate.get("preserved_features"),
            "lost_or_weakened_features": candidate.get("lost_or_weakened_features"),
        },
        "evidence": compact_evidence(candidate),
        "selected_mask_context": selected_mask_context,
        "preferred_bindings_for_this_template": recipe_defaults(recipe),
        "forbidden_output_fields": [
            "target_library",
            "target_api",
            "harness_family",
            "oracle_type",
            "adapter_recipe",
            "init_block",
            "input_construction_block",
            "trigger_block",
            "cleanup_block",
            "oracle_strategy",
            "include_headers",
            "type_mapping",
            "constant_mapping",
            "preserved_features",
            "lost_or_weakened_features",
            "slot_binding_rationale",
            "notes",
        ],
        "forbidden_terms": forbidden_terms,
        "required_output_schema": {
            "slot_bindings": {name: "string value" for name in allowed_slots.keys()},
        },
    }

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_obj, ensure_ascii=False, indent=2)},
    ]


def build_prompt(
    mask_report: Dict[str, Any],
    candidate: Dict[str, Any],
    selected_mask_context: Dict[str, Any] = None,
) -> List[Dict[str, str]]:
    poc_pattern = mask_report.get("poc_pattern", {})
    source_api = mask_report.get("source_api") or mask_report.get("source", {}).get("api")
    template_id = mask_report.get("template_id")
    selected_mask_context = selected_mask_context or {"available": False, "selected_units": []}

    adapter_hard_constraints = [
        "The harness already declares buf[BUFLEN + CANARY_SIZE].",
        "Do not malloc buf.",
        "Do not free(buf).",
        "Do not redeclare buf.",
        "Do not use bare [VALUE] or [BUFLEN] placeholders inside adapter blocks.",
        "Use signed_value, magnitude, and BUFLEN.",
        "trigger_block must only perform the target API call and assign its result to ret.",
        "cleanup_block must only release target-library objects.",
        "Do not write semantics from lost_or_weakened_features back into oracle_strategy.",
    ]

    system_prompt = """You are an expert in cryptographic C API harness migration.
Your task is to generate a STRUCTURED adapter JSON for cross-library vulnerability-pattern migration.

Important rules:
1. Output JSON only. No markdown. No code fences.
2. Do not invent unsupported APIs.
3. Do not generate a full C file.
4. Fill only adapter-level blocks: includes, type mapping, initialization, input construction, trigger call, oracle, cleanup.
5. Preserve the source vulnerability path where possible.
6. Explicitly list lost or weakened features.
7. Keep the adapter compilable in principle for C/OpenSSL style harnesses.
8. Respect all adapter hard constraints from the user message exactly.
9. selected_mask_units are high-value masked units extracted from the source harness.
10. Preserve oracle and cleanup units unless adapting library-specific object cleanup.
11. Use trigger_call units to understand the source API call structure.
12. Use mutation_point and api_argument units to map source placeholders to target API arguments.
13. Do not mutate oracle/canary layout unless explicitly required.
14. Do not reintroduce lost_or_weakened_features.
"""

    user_obj = {
        "task": "Generate adapter JSON for target API harness migration.",
        "source": {
            "template_id": template_id,
            "source_api": source_api,
            "root_cause": poc_pattern.get("root_cause", {}),
            "vulnerability_path_features": poc_pattern.get("vulnerability_path_features", {}),
            "mutation_points": poc_pattern.get("mutation_points", []),
        },
        "candidate": {
            "library": candidate.get("library"),
            "api": candidate.get("api"),
            "decision": candidate.get("decision"),
            "scores": candidate.get("scores"),
            "reason": candidate.get("reason"),
            "parameter_mapping": candidate.get("parameter_mapping"),
            "preserved_vulnerability_features": candidate.get("preserved_vulnerability_features"),
            "lost_or_weakened_features": candidate.get("lost_or_weakened_features"),
        },
        "evidence": compact_evidence(candidate),
        "selected_mask_context": selected_mask_context,
        "selected_mask_context_guidance": [
            "selected_mask_units are high-value masked units extracted from the source harness.",
            "Preserve oracle and cleanup units unless adapting library-specific object cleanup.",
            "Use trigger_call units to understand source API call structure.",
            "Use mutation_point and api_argument units to map source placeholders to target API arguments.",
            "Do not mutate oracle/canary layout unless explicitly required.",
            "Do not reintroduce lost_or_weakened_features.",
        ],
        "adapter_hard_constraints": adapter_hard_constraints,
        "required_output_schema": {
            "target_library": "string",
            "target_api": "string",
            "applicability": "generate | migration_not_applicable | needs_review",
            "include_headers": ["string"],
            "type_mapping": {"source_type_or_object": "target_type_or_object"},
            "constant_mapping": {"source_placeholder": "target_meaning"},
            "init_block": "C code snippet",
            "input_construction_block": "C code snippet",
            "trigger_block": "C code snippet",
            "return_value_semantics": "string",
            "oracle_strategy": {
                "memory_safety": ["string"],
                "semantic_checks": ["string"],
                "bug_signals": ["string"],
                "safe_signals": ["string"],
            },
            "cleanup_block": "C code snippet",
            "preserved_features": ["string"],
            "lost_or_weakened_features": ["string"],
            "notes": ["string"],
        },
    }

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(user_obj, ensure_ascii=False, indent=2)},
    ]


def fallback_adapter(candidate: Dict[str, Any]) -> Dict[str, Any]:
    lib = candidate_library(candidate)
    api = candidate_api(candidate)

    return {
        "target_library": lib,
        "target_api": api,
        "applicability": candidate.get("decision", "needs_review"),
        "include_headers": ["openssl/bn.h"] if lib == "openssl" else [],
        "type_mapping": {
            "mbedtls_mpi X": "BIGNUM *X",
            "output buffer": "unsigned char buf[BUFLEN + CANARY_SIZE]",
        },
        "constant_mapping": candidate.get("parameter_mapping", {}),
        "init_block": "BIGNUM *X = BN_new();",
        "input_construction_block": "BN_set_word(X, magnitude); if (signed_value < 0) { BN_set_negative(X, 1); }",
        "trigger_block": f"ret = {api}(X, buf, BUFLEN);",
        "return_value_semantics": "Return value should be checked according to the target OpenSSL API.",
        "oracle_strategy": {
            "memory_safety": ["canary_intact", "asan_clean", "ubsan_clean"],
            "semantic_checks": ["ret value is observable"],
            "bug_signals": ["canary_corrupted", "sanitizer_crash"],
            "safe_signals": ["canary intact", "no sanitizer crash"],
        },
        "cleanup_block": "BN_free(X);",
        "preserved_features": candidate.get("preserved_vulnerability_features", []),
        "lost_or_weakened_features": candidate.get("lost_or_weakened_features", []),
        "notes": ["Fallback adapter generated without valid LLM JSON."],
    }


def recipe_fallback_adapter(
    mask_report: Dict[str, Any],
    template_meta: Dict[str, Any],
    candidate: Dict[str, Any],
    recipe_path: Path,
    recipe: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "source_pattern_id": template_meta.get("source_pattern_id") or mask_report.get("poc_pattern", {}).get("pattern_id"),
        "template_id": template_meta.get("template_id") or mask_report.get("template_id"),
        "harness_family": recipe.get("harness_family"),
        "oracle_type": recipe.get("oracle_type"),
        "target_library": recipe.get("target_library") or candidate_library(candidate),
        "target_api": recipe.get("target_api") or candidate_api(candidate),
        "applicability": candidate.get("decision", "needs_review"),
        "adapter_recipe": str(recipe_path),
        "evidence_file": "",
        "slot_bindings": recipe_defaults(recipe),
        "preserved_features": candidate.get("preserved_vulnerability_features") or candidate.get("preserved_features") or [],
        "lost_or_weakened_features": candidate.get("lost_or_weakened_features", []),
        "slot_binding_rationale": {
            key: "recipe default used because LLM output was unavailable"
            for key in recipe_defaults(recipe)
        },
        "notes": ["Recipe fallback adapter generated from recipe defaults."],
    }


def build_recipe_adapter_from_llm(
    raw_adapter: Dict[str, Any],
    mask_report: Dict[str, Any],
    template_meta: Dict[str, Any],
    candidate: Dict[str, Any],
    recipe_path: Path,
    recipe: Dict[str, Any],
) -> Dict[str, Any]:
    disallowed_fields = [
        "target_library",
        "target_api",
        "harness_family",
        "oracle_type",
        "adapter_recipe",
        "init_block",
        "input_construction_block",
        "trigger_block",
        "cleanup_block",
        "oracle_strategy",
        "include_headers",
        "type_mapping",
        "constant_mapping",
        "preserved_features",
        "lost_or_weakened_features",
        "slot_binding_rationale",
        "notes",
    ]
    ignored = [field for field in disallowed_fields if field in raw_adapter]
    ignored_non_slot_fields = sorted(str(field) for field in raw_adapter if field != "slot_bindings")

    return {
        "source_pattern_id": template_meta.get("source_pattern_id") or mask_report.get("poc_pattern", {}).get("pattern_id"),
        "template_id": template_meta.get("template_id") or mask_report.get("template_id"),
        "harness_family": recipe.get("harness_family"),
        "oracle_type": recipe.get("oracle_type"),
        "target_library": recipe.get("target_library") or raw_adapter.get("target_library") or candidate_library(candidate),
        "target_api": recipe.get("target_api") or raw_adapter.get("target_api") or candidate_api(candidate),
        "applicability": candidate.get("decision", "needs_review"),
        "adapter_recipe": str(recipe_path),
        "evidence_file": "",
        "slot_bindings": clean_slot_bindings(raw_adapter.get("slot_bindings"), recipe),
        "preserved_features": candidate.get("preserved_vulnerability_features") or candidate.get("preserved_features") or [],
        "lost_or_weakened_features": candidate.get("lost_or_weakened_features", []),
        "_adapter_mode": "recipe_slot_filling",
        "_ignored_disallowed_fields": ignored,
        "_ignored_non_slot_fields": ignored_non_slot_fields,
    }


def generate_adapter(
    mask_report: Dict[str, Any],
    template_meta: Dict[str, Any],
    candidate: Dict[str, Any],
    use_llm: bool,
    selected_mask_context: Dict[str, Any] = None,
    use_recipes: bool = True,
    require_recipes: bool = False,
    adapter_recipe: Path | None = None,
) -> Dict[str, Any]:
    recipe_path, recipe = (None, {})
    if adapter_recipe is not None:
        recipe_path = adapter_recipe
        recipe = load_yaml(adapter_recipe) if adapter_recipe.exists() else {}
    elif use_recipes:
        recipe_path, recipe = find_adapter_recipe(candidate, mask_report, template_meta)

    if recipe_path is not None and recipe:
        if not use_llm:
            adapter = recipe_fallback_adapter(mask_report, template_meta, candidate, recipe_path, recipe)
            adapter["_llm_status"] = "not_requested"
            return adapter

        messages = build_recipe_prompt(
            mask_report,
            template_meta,
            candidate,
            recipe_path,
            recipe,
            selected_mask_context=selected_mask_context,
        )
        try:
            raw = get_glm_response(messages)
            parsed = parse_llm_json(raw)
            adapter = build_recipe_adapter_from_llm(
                parsed,
                mask_report,
                template_meta,
                candidate,
                recipe_path,
                recipe,
            )
            adapter["_llm_raw_preview"] = raw[:1200]
            adapter["_llm_status"] = "ok"
            return adapter
        except Exception as e:
            if require_recipes:
                raise RuntimeError(
                    f"recipe slot-filling LLM failed for {recipe_path}; "
                    "refusing fallback adapter generation"
                ) from e
            adapter = recipe_fallback_adapter(mask_report, template_meta, candidate, recipe_path, recipe)
            adapter["_llm_status"] = "fallback"
            adapter["_llm_error"] = str(e)
            return adapter

    if require_recipes:
        lib = candidate_library(candidate)
        api = candidate_api(candidate)
        raise RuntimeError(f"adapter recipe not found for {lib} {api}; refusing free-form adapter fallback")

    if not use_llm:
        return fallback_adapter(candidate)

    messages = build_prompt(mask_report, candidate, selected_mask_context=selected_mask_context)

    try:
        raw = get_glm_response(messages)
        adapter = parse_llm_json(raw)
        adapter["_llm_raw_preview"] = raw[:1200]
        adapter["_llm_status"] = "ok"
        return adapter
    except Exception as e:
        adapter = fallback_adapter(candidate)
        adapter["_llm_status"] = "fallback"
        adapter["_llm_error"] = str(e)
        return adapter


def main() -> int:
    parser = argparse.ArgumentParser(description="Fill structured target-library adapter YAML using LLM + RAG evidence.")
    parser.add_argument("--mask-report", required=True)
    parser.add_argument("--candidates-with-evidence", required=True)
    parser.add_argument("--out-root", default="adapters")
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument(
        "--no-recipes",
        action="store_true",
        help="Disable adapter recipe/slot-filling mode and use legacy free-form adapter mode.",
    )
    parser.add_argument(
        "--require-recipes",
        action="store_true",
        help="Fail instead of falling back to free-form adapter mode when no adapter recipe is found.",
    )
    parser.add_argument("--target-library", help="Only generate adapters for this target library.")
    parser.add_argument("--target-api", help="Only generate adapters for this target API.")
    parser.add_argument("--adapter-recipe", help="Use this adapter recipe instead of auto-discovering one.")
    parser.add_argument("--include-non-generate", action="store_true")
    args = parser.parse_args()

    mask_report_path = Path(args.mask_report)
    mask_report = load_yaml(mask_report_path)
    template_meta = load_template_meta_for_mask(mask_report_path)
    candidates_obj = load_yaml(Path(args.candidates_with_evidence))
    selected_mask_context = load_selected_mask_context(mask_report_path)
    adapter_recipe = Path(args.adapter_recipe) if args.adapter_recipe else None
    if adapter_recipe is not None and not adapter_recipe.exists():
        parser.error(f"adapter recipe not found: {adapter_recipe}")

    template_id = candidates_obj.get("template_id") or mask_report.get("template_id")
    out_root = Path(args.out_root)

    count = 0

    for candidate in candidates_obj.get("target_candidates", []):
        lib = candidate_library(candidate)
        api = candidate_api(candidate)
        if args.target_library and lib != args.target_library:
            print(f"[SKIP] {lib} {api} target_library filter={args.target_library}")
            continue
        if args.target_api and api != args.target_api:
            print(f"[SKIP] {lib} {api} target_api filter={args.target_api}")
            continue

        decision = candidate.get("decision")

        if decision != "generate" and not args.include_non_generate:
            print(f"[SKIP] {lib} {api} decision={decision}")
            continue

        adapter = generate_adapter(
            mask_report,
            template_meta,
            candidate,
            use_llm=args.use_llm,
            selected_mask_context=selected_mask_context,
            use_recipes=not args.no_recipes,
            require_recipes=args.require_recipes,
            adapter_recipe=adapter_recipe,
        )
        if adapter.get("adapter_recipe"):
            adapter["evidence_file"] = args.candidates_with_evidence

        out_dir = out_root / sanitize_name(str(template_id)) / f"{lib}_{sanitize_name(api)}"
        dump_yaml(out_dir / "adapter.yaml", adapter)

        metadata = {
            "template_id": template_id,
            "candidate": {
                "library": lib,
                "api": api,
                "decision": decision,
                "scores": candidate.get("scores"),
            },
            "source_files": {
                "mask_report": args.mask_report,
                "candidates_with_evidence": args.candidates_with_evidence,
                "selected_mask_units": selected_mask_context.get("source_file", ""),
            },
        }
        dump_yaml(out_dir / "adapter_meta.yaml", metadata)

        print(f"[OK] adapter written: {out_dir / 'adapter.yaml'}")
        count += 1

    print("=" * 80)
    print(f"[SUMMARY] adapters generated: {count}")
    print(f"[SUMMARY] output root: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

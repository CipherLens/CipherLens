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
    lib = candidate.get("library")
    api = candidate.get("api")

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


def generate_adapter(
    mask_report: Dict[str, Any],
    candidate: Dict[str, Any],
    use_llm: bool,
    selected_mask_context: Dict[str, Any] = None,
) -> Dict[str, Any]:
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
    parser.add_argument("--include-non-generate", action="store_true")
    args = parser.parse_args()

    mask_report_path = Path(args.mask_report)
    mask_report = load_yaml(mask_report_path)
    candidates_obj = load_yaml(Path(args.candidates_with_evidence))
    selected_mask_context = load_selected_mask_context(mask_report_path)

    template_id = candidates_obj.get("template_id") or mask_report.get("template_id")
    out_root = Path(args.out_root)

    count = 0

    for candidate in candidates_obj.get("target_candidates", []):
        decision = candidate.get("decision")

        if decision != "generate" and not args.include_non_generate:
            print(f"[SKIP] {candidate.get('library')} {candidate.get('api')} decision={decision}")
            continue

        lib = candidate.get("library")
        api = candidate.get("api")
        adapter = generate_adapter(
            mask_report,
            candidate,
            use_llm=args.use_llm,
            selected_mask_context=selected_mask_context,
        )

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

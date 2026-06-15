import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}



def load_optional_yaml(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {}
    return load_yaml(path)


def normalize_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def card_known_pitfalls(card: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for note in as_list(card.get("notes")):
        text = str(note)
        if "pitfall" in text.lower():
            out.append(text)
    return out


def compact_api_card(path: Path, root: Path, card: Dict[str, Any]) -> Dict[str, Any]:
    try:
        rel_path = str(path.relative_to(root))
    except ValueError:
        rel_path = str(path)
    return {
        "path": rel_path,
        "api": str(card.get("api") or ""),
        "library": str(card.get("library") or ""),
        "family": str(card.get("family") or ""),
        "related_apis": [str(x) for x in as_list(card.get("related_apis"))],
        "mutation_hints": [str(x) for x in as_list(card.get("mutation_hints"))],
        "oracle_observables": [str(x) for x in as_list(card.get("oracle_observables"))],
        "state_preconditions": [str(x) for x in as_list(card.get("state_preconditions"))],
        "known_pitfalls": card_known_pitfalls(card),
    }


def load_api_cards(api_cards_root: Optional[Path]) -> Tuple[List[Dict[str, Any]], List[str]]:
    if api_cards_root is None:
        return [], []
    if not api_cards_root.exists():
        return [], [f"api_cards_root_not_found: {api_cards_root}"]

    cards: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for path in sorted(api_cards_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
            continue
        try:
            raw = load_yaml(path)
        except Exception as exc:
            warnings.append(f"failed_to_load_api_card: {path}: {exc}")
            continue
        if not isinstance(raw, dict):
            warnings.append(f"api_card_not_mapping: {path}")
            continue
        cards.append(compact_api_card(path, api_cards_root, raw))
    return cards, warnings


def family_aliases(*families: Any) -> Set[str]:
    aliases: Set[str] = set()
    for family in families:
        token = normalize_token(family)
        if not token:
            continue
        aliases.add(token)
        if token in {"object_state_lifecycle", "mac_context_size_lifecycle_oracle", "mac_lifecycle"}:
            aliases.update({"object_state_lifecycle", "mac_context_size_lifecycle_oracle", "mac_lifecycle", "lifecycle"})
    return aliases


def infer_selected_mask_units_path(mask_report_path: Optional[Path]) -> Optional[Path]:
    if mask_report_path is None:
        return None
    candidate = mask_report_path.parent / "selected_mask_units.yaml"
    return candidate if candidate.exists() else None


def selected_unit_compact(unit: Dict[str, Any]) -> Dict[str, Any]:
    keep = [
        "unit_id",
        "role",
        "mask_level",
        "placeholder",
        "suggested_use",
        "function",
        "code",
        "selection_reason",
        "source",
    ]
    out = {key: unit.get(key) for key in keep if unit.get(key) not in (None, "", [])}
    if "code" in out:
        out["code"] = " ".join(str(out["code"]).split())[:240]
    if "selection_reason" in out:
        out["selection_reason"] = " ".join(str(out["selection_reason"]).split())[:240]
    return out


def selected_units_by_use(selected_report: Dict[str, Any], limit_per_use: int = 6) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for unit in selected_report.get("selected_units", []) or []:
        if not isinstance(unit, dict):
            continue
        key = str(unit.get("suggested_use") or "unspecified")
        bucket = grouped.setdefault(key, [])
        if len(bucket) < limit_per_use:
            bucket.append(selected_unit_compact(unit))
    return grouped


def selected_units_summary(selected_report: Dict[str, Any]) -> Dict[str, Any]:
    if not selected_report:
        return {}
    units = [u for u in selected_report.get("selected_units", []) or [] if isinstance(u, dict)]
    summary = selected_report.get("selection_summary", {}) if isinstance(selected_report.get("selection_summary"), dict) else {}
    return {
        "selected_count": len(units),
        "source_unit_count": summary.get("source_unit_count"),
        "harness_family": selected_report.get("harness_family", ""),
        "trigger_apis": selected_report.get("trigger_apis", []),
        "by_role": summary.get("by_role", {}),
        "by_mask_level": summary.get("by_mask_level", {}),
        "by_suggested_use": summary.get("by_suggested_use", {}),
    }


def selected_query_terms(selected_report: Dict[str, Any]) -> Dict[str, str]:
    if not selected_report:
        return {}

    grouped = selected_units_by_use(selected_report, limit_per_use=4)

    def codes_for(use: str) -> str:
        return " ".join(str(unit.get("code", "")) for unit in grouped.get(use, []))

    return {
        "harness_family": str(selected_report.get("harness_family") or ""),
        "trigger_apis": " ".join(str(x) for x in selected_report.get("trigger_apis", []) or []),
        "migrate_api_call": codes_for("migrate_api_call"),
        "preserve_oracle": codes_for("preserve_oracle"),
        "mutate_value": codes_for("mutate_value"),
        "mutate_api_argument": codes_for("mutate_api_argument"),
        "preserve_input_preparation": codes_for("preserve_input_preparation"),
    }


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def rag_query_help() -> str:
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "knowledge.rag_query", "--help"],
            cwd=Path.cwd(),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception:
        return ""



def raw_knowledge_layer(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
        return rel.parts[0] if rel.parts else ""
    except ValueError:
        return ""


RAW_SEARCH_STOPWORDS = {
    "and", "or", "the", "a", "an", "to", "of", "in", "on", "for", "from",
    "with", "without", "by", "is", "are", "be", "can", "must", "not", "as",
    "at", "into", "through", "value", "values", "source", "target", "api",
    "function", "parameters", "parameter", "return", "error", "code", "usage",
    "example", "test", "unit", "pattern", "selected", "mask", "mutation", "points",
}


def query_terms(query: str) -> List[str]:
    terms: List[str] = []
    seen: Set[str] = set()
    for term in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+", query or ""):
        lowered = term.lower()
        if len(lowered) < 2 or lowered in seen or lowered in RAW_SEARCH_STOPWORDS:
            continue
        seen.add(lowered)
        terms.append(lowered)
    return terms


def api_like_terms(terms: List[str]) -> List[str]:
    prefixes = ("evp_", "bn_", "d2i_", "mbedtls_", "psa_", "x509", "rsa_")
    return [t for t in terms if "_" in t and t.startswith(prefixes)]


def required_target_anchor(query: str, terms: List[str]) -> str:
    raw_terms = [t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", query or "")]
    for idx, term in enumerate(raw_terms[:-1]):
        if term in {"openssl", "mbedtls", "botan"}:
            for later in raw_terms[idx + 1:]:
                if later in terms and later in api_like_terms(terms):
                    return later
    return ""


def best_snippet(text: str, terms: List[str], max_chars: int = 900, preferred: str = "") -> str:
    if not text:
        return ""
    lowered = text.lower()
    ordered_terms = ([preferred] if preferred else []) + [t for t in terms if t != preferred]
    positions = [lowered.find(t) for t in ordered_terms if t and lowered.find(t) >= 0]
    if not positions:
        return " ".join(text[:max_chars].split())
    pos = min(positions)
    start = max(0, pos - max_chars // 3)
    end = min(len(text), start + max_chars)
    return " ".join(text[start:end].split())


def raw_knowledge_search(query: str, top_k: int = 5, max_chars: int = 6000, root: Path = Path("knowledge_raw")) -> List[Dict[str, Any]]:
    terms = query_terms(query)
    if not terms or not root.exists():
        return []

    required_anchor = required_target_anchor(query, terms)
    api_anchors = api_like_terms(terms)
    suffixes = {".md", ".yaml", ".yml", ".json", ".jsonl", ".txt", ".c", ".h"}
    hits: List[Dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        lowered = text.lower()
        path_text = str(path).lower()
        if required_anchor and required_anchor not in lowered and required_anchor not in path_text:
            continue
        if not required_anchor and api_anchors and not any(a in lowered or a in path_text for a in api_anchors):
            continue

        matched_terms = [t for t in terms if t in lowered or t in path_text]
        if not matched_terms:
            continue

        exact_phrase_bonus = 8 if query.lower() in lowered else 0
        anchor_bonus = 20 if required_anchor and required_anchor in matched_terms else 0
        path_bonus = sum(3 for t in terms if t in path_text)
        content_score = sum(min(lowered.count(t), 8) for t in matched_terms)
        score_value = exact_phrase_bonus + anchor_bonus + path_bonus + content_score + len(set(matched_terms)) * 2
        hits.append({
            "_score_value": score_value,
            "_matched_terms": sorted(set(matched_terms)),
            "path": path,
            "text": text,
        })

    hits.sort(key=lambda h: (-h["_score_value"], str(h["path"])))
    normalized: List[Dict[str, Any]] = []
    for rank, hit in enumerate(hits[:top_k], start=1):
        path = hit["path"]
        score_value = float(hit["_score_value"])
        normalized.append({
            "rank": rank,
            "score": round(score_value / (score_value + 10.0), 4),
            "distance": None,
            "layer": raw_knowledge_layer(path, root),
            "source_file": str(path),
            "text": best_snippet(hit["text"], hit["_matched_terms"], max_chars=min(max_chars, 1200), preferred=required_anchor),
            "metadata": {
                "fallback": "knowledge_raw_keyword_search",
                "matched_terms": hit["_matched_terms"],
            },
        })
    return normalized


def with_raw_knowledge_fallback(
    payload: Dict[str, Any],
    query: str,
    top_k: int,
    max_chars: int,
    reason: str,
) -> Dict[str, Any]:
    if payload.get("results"):
        payload.setdefault("raw_fallback", {"enabled": False})
        return payload

    fallback_results = raw_knowledge_search(query, top_k=top_k, max_chars=max_chars)
    payload["raw_fallback"] = {
        "enabled": bool(fallback_results),
        "reason": reason,
        "root": "knowledge_raw",
        "hits": len(fallback_results),
    }
    if fallback_results:
        payload["results"] = fallback_results
    return payload


def run_rag_query(query: str, top_k: int = 5, timeout: int = 90, max_chars: int = 6000) -> Dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = "."

    help_text = rag_query_help()
    base_cmd = [
        sys.executable,
        "-m",
        "knowledge.rag_query",
        "--query",
        query,
    ]

    if "--top-k" in help_text:
        top_k_mode = "--top-k"
    elif "--k" in help_text:
        top_k_mode = "--k"
    else:
        top_k_mode = "not_supported_by_rag_query"

    cmd = list(base_cmd)
    if top_k_mode == "--top-k":
        cmd.extend(["--top-k", str(top_k)])
    elif top_k_mode == "--k":
        cmd.extend(["--k", str(top_k)])

    json_supported = "--json" in help_text
    json_cmd = list(cmd)
    if json_supported:
        json_cmd.append("--json")

    try:
        proc = subprocess.run(
            json_cmd if json_supported else cmd,
            cwd=Path.cwd(),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if json_supported:
            try:
                payload = json.loads(stdout)
                if not isinstance(payload, dict):
                    raise ValueError("RAG JSON output is not an object")
                raw_results = payload.get("results", [])
                results = raw_results if isinstance(raw_results, list) else []
                normalized_results = []
                for idx, item in enumerate(results, start=1):
                    hit = item if isinstance(item, dict) else {}
                    metadata = hit.get("metadata", {})
                    if not isinstance(metadata, dict):
                        metadata = {}
                    normalized_results.append({
                        "rank": hit.get("rank", idx),
                        "score": hit.get("score"),
                        "distance": hit.get("distance"),
                        "base_score": hit.get("base_score"),
                        "rerank_score": hit.get("rerank_score"),
                        "rerank_reasons": hit.get("rerank_reasons", []),
                        "layer": hit.get("layer") or metadata.get("layer", ""),
                        "source_file": hit.get("source_file") or metadata.get("source_file", ""),
                        "text": hit.get("text", ""),
                        "metadata": metadata,
                    })

                result = {
                    "query": payload.get("query", query),
                    "top_k_requested": top_k,
                    "top_k_returned": payload.get("top_k", top_k),
                    "top_k_mode": top_k_mode,
                    "returncode": proc.returncode,
                    "json_mode": True,
                    "results": normalized_results,
                    "error": payload.get("error", ""),
                    "stdout_preview": stdout[:max_chars],
                    "stderr_preview": stderr[:max_chars],
                    "truncated": len(stdout) > max_chars,
                }
                reason = "rag_query_empty_results" if proc.returncode == 0 else "rag_query_failed"
                return with_raw_knowledge_fallback(result, query, top_k, max_chars, reason)
            except (json.JSONDecodeError, ValueError):
                pass

            fallback = subprocess.run(
                cmd,
                cwd=Path.cwd(),
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            fallback_stdout = fallback.stdout or ""
            fallback_stderr = fallback.stderr or ""
            result = {
                "query": query,
                "top_k_requested": top_k,
                "top_k_mode": top_k_mode,
                "returncode": fallback.returncode,
                "json_mode": False,
                "results": [],
                "stdout_preview": fallback_stdout[:max_chars],
                "stderr_preview": (stderr + "\n" + fallback_stderr).strip()[:max_chars],
                "json_parse_error": True,
                "json_stdout_preview": stdout[:max_chars],
                "truncated": len(fallback_stdout) > max_chars,
            }
            return with_raw_knowledge_fallback(result, query, top_k, max_chars, "rag_json_parse_or_plain_query_failed")

        result = {
            "query": query,
            "top_k_requested": top_k,
            "top_k_mode": top_k_mode,
            "returncode": proc.returncode,
            "json_mode": False,
            "results": [],
            "stdout_preview": stdout[:max_chars],
            "stderr_preview": stderr[:max_chars],
            "truncated": len(stdout) > max_chars,
        }
        reason = "rag_query_empty_results" if proc.returncode == 0 else "rag_query_failed"
        return with_raw_knowledge_fallback(result, query, top_k, max_chars, reason)

    except subprocess.TimeoutExpired as e:
        result = {
            "query": query,
            "top_k_requested": top_k,
            "top_k_mode": top_k_mode,
            "returncode": -1,
            "json_mode": False,
            "results": [],
            "stdout_preview": (e.stdout or "")[:max_chars] if isinstance(e.stdout, str) else "",
            "stderr_preview": "RAG query timeout",
            "truncated": True,
        }
        return with_raw_knowledge_fallback(result, query, top_k, max_chars, "rag_query_timeout")

def get_source_context(mask_report: Dict[str, Any], selected_mask_report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    poc_pattern = mask_report.get("poc_pattern", {})
    root_cause = poc_pattern.get("root_cause", {})
    features = poc_pattern.get("vulnerability_path_features", {})
    guidance = poc_pattern.get("migration_guidance", {})

    selected_mask_report = selected_mask_report or {}
    return {
        "pattern_id": poc_pattern.get("pattern_id"),
        "source_library": mask_report.get("source_library", ""),
        "root_cause_summary": root_cause.get("summary", ""),
        "must_preserve_features": features.get("must_preserve", []),
        "optional_features": features.get("optional", []),
        "not_required_features": features.get("not_required", []),
        "good_target_api_features": guidance.get("good_target_api_features", []),
        "bad_target_api_features": guidance.get("bad_target_api_features", []),
        "rag_query_context": mask_report.get("rag_query_context", ""),
        "harness_family": selected_mask_report.get("harness_family") or mask_report.get("harness_family", ""),
        "oracle_type": mask_report.get("oracle_type", ""),
        "trigger_apis": selected_mask_report.get("trigger_apis") or mask_report.get("trigger_apis", []),
        "selected_mask_units": {
            "summary": selected_units_summary(selected_mask_report),
            "selected_units_by_use": selected_units_by_use(selected_mask_report),
            "query_terms": selected_query_terms(selected_mask_report),
        },
    }


def candidate_list_key(candidates_obj: Dict[str, Any]) -> str:
    if "target_candidates" in candidates_obj:
        return "target_candidates"
    if "candidates" in candidates_obj:
        return "candidates"
    return "target_candidates"


def candidate_api(candidate: Dict[str, Any]) -> str:
    return str(candidate.get("target_api") or candidate.get("api") or "")


def candidate_library(candidate: Dict[str, Any]) -> str:
    return str(candidate.get("target_library") or candidate.get("library") or "")


def get_bug_classes(mask_report: Dict[str, Any], candidates_obj: Dict[str, Any], feature_rules: Dict[str, Any] = None) -> List[str]:
    out: List[str] = []

    # From mask_report operation if present.
    op = mask_report.get("operation", {})
    bug_class = op.get("bug_class", [])
    if isinstance(bug_class, list):
        out.extend(str(x) for x in bug_class)
    elif bug_class:
        out.append(str(bug_class))

    # From poc_pattern classification.
    poc_pattern = mask_report.get("poc_pattern", {})
    cls = poc_pattern.get("classification", {})
    if cls.get("bug_category"):
        out.append(str(cls.get("bug_category")))

    # From candidates source if present.
    source = candidates_obj.get("source", {})
    vpf = source.get("vulnerability_path_features", {})
    for x in vpf.get("must_preserve", []) or []:
        out.append(str(x))

    # Fallback by template_id when older templates do not carry poc_pattern/bug_class.
    if feature_rules:
        tid = mask_report.get("template_id") or candidates_obj.get("template_id")
        fallback = feature_rules.get("template_bug_class_fallback", {}).get(tid, [])
        if isinstance(fallback, list):
            out.extend(str(x) for x in fallback)
        elif fallback:
            out.append(str(fallback))

    # Normalize to unique order.
    seen = set()
    uniq = []
    for x in out:
        if x and x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def make_generic_queries(
    candidate: Dict[str, Any],
    source_ctx: Dict[str, Any],
    bug_classes: List[str],
) -> List[Dict[str, str]]:
    lib = candidate_library(candidate)
    api = candidate_api(candidate)
    root = source_ctx.get("root_cause_summary", "")
    must = " ".join(source_ctx.get("must_preserve_features", []))
    mapping = " ".join(str(x) for x in candidate.get("parameter_mapping", {}).values())
    preserved = " ".join(candidate.get("preserved_vulnerability_features", []))
    lost = " ".join(candidate.get("lost_or_weakened_features", []))
    bug = " ".join(bug_classes)
    selected = source_ctx.get("selected_mask_units", {}).get("query_terms", {})
    family = selected.get("harness_family") or source_ctx.get("harness_family", "")
    trigger_apis = selected.get("trigger_apis") or " ".join(str(x) for x in source_ctx.get("trigger_apis", []) or [])
    migrate_call = selected.get("migrate_api_call", "")
    oracle_terms = selected.get("preserve_oracle", "")
    mutation_terms = " ".join([
        selected.get("mutate_value", ""),
        selected.get("mutate_api_argument", ""),
    ]).strip()
    input_terms = selected.get("preserve_input_preparation", "")

    queries = [
        {
            "kind": "source_pattern",
            "query": f"{root} {must}",
            "use_for_feature_inference": "source_only",
        },
        {
            "kind": "target_api_signature",
            "query": f"{lib} {api} function declaration signature parameters return value",
            "use_for_feature_inference": "target",
        },
        {
            "kind": "target_api_implementation",
            "query": f"{lib} {api} implementation source code parameters return error",
            "use_for_feature_inference": "target",
        },
        {
            "kind": "target_api_usage",
            "query": f"{lib} {api} usage example unit test API call pattern",
            "use_for_feature_inference": "target",
        },
        {
            "kind": "vulnerability_path_compatibility",
            "query": f"{lib} {api} {bug} {must} {preserved} {lost} {mapping}",
            "use_for_feature_inference": "target",
        },
    ]

    if selected:
        queries.extend([
            {
                "kind": "selected_mask_migration_constraints",
                "query": f"{lib} {api} {family} selected mask units trigger APIs {trigger_apis} migrate API call {migrate_call} mutation points {mutation_terms}",
                "use_for_feature_inference": "target",
            },
            {
                "kind": "selected_mask_oracle_observability",
                "query": f"{lib} {api} {family} oracle observability return value output state pointer consumption sanitizer {oracle_terms} input setup {input_terms}",
                "use_for_feature_inference": "target",
            },
        ])

    return queries


def contains_any(text: str, patterns: List[str]) -> bool:
    text = text.lower()
    return any(str(p).lower() in text for p in patterns)


def evidence_pattern_matches(text: str, pattern: str) -> bool:
    pat = str(pattern or "").strip().lower()
    if not pat:
        return False
    if re.fullmatch(r"[a-z0-9_ ]+", pat):
        pieces = [re.escape(x) for x in pat.split()]
        body = r"\s+".join(pieces)
        return re.search(rf"(?<![a-z0-9_]){body}(?![a-z0-9_])", text.lower()) is not None
    return pat in text.lower()


def normalize_feature_name(s: str) -> str:
    return str(s).strip()


FAMILY_ALLOWED_RULE_FEATURES = {
    "buffer_canary_boundary": {
        "caller_provided_output_buffer",
        "explicit_output_buffer_length",
        "library_writes_to_caller_buffer",
        "library_allocated_output",
        "signed_or_negative_encoding",
        "radix_or_textual_base_context",
        "bignum_subtraction",
        "manual_output_limb_boundary_control",
        "direct_canary_after_output_limbs",
    },
    "null_deref_dispatch": {
        "verification_return_code",
    },
    "invalid_parameter_setup_oracle": {
        "explicit_tag_input",
        "tag_length_parameter",
        "verification_return_code",
    },
}


def candidate_harness_family(candidate: Dict[str, Any]) -> str:
    alignment = candidate.get("ast_mask_alignment", {})
    if isinstance(alignment, dict) and alignment.get("harness_family"):
        return str(alignment.get("harness_family"))
    return str(candidate.get("harness_family") or "")


def candidate_preserved_features(candidate: Dict[str, Any]) -> List[str]:
    return [
        str(x)
        for x in (
            as_list(candidate.get("preserved_vulnerability_features"))
            or as_list(candidate.get("preserved_features"))
        )
    ]


def candidate_lost_features(candidate: Dict[str, Any]) -> List[str]:
    return [
        str(x)
        for x in (
            as_list(candidate.get("lost_or_weakened_features"))
            or as_list(candidate.get("weakened_features"))
        )
    ]


def card_api_names(card: Dict[str, Any]) -> Set[str]:
    names = {normalize_token(card.get("api"))}
    names.update(normalize_token(x) for x in card.get("related_apis", []) or [])
    return {x for x in names if x}


def api_card_matches(
    card: Dict[str, Any],
    candidate: Dict[str, Any],
    source_ctx: Dict[str, Any],
    candidate_family_aliases: Set[str],
) -> Tuple[bool, str]:
    card_library = normalize_token(card.get("library"))
    card_family = normalize_token(card.get("family"))
    target_library = normalize_token(candidate_library(candidate))
    target_api = normalize_token(candidate_api(candidate))
    source_library = normalize_token(source_ctx.get("source_library"))
    trigger_apis = {normalize_token(x) for x in source_ctx.get("trigger_apis", []) or []}
    card_names = card_api_names(card)

    family_match = bool(card_family and card_family in candidate_family_aliases)
    target_api_match = bool(target_api and target_api in card_names)
    trigger_api_match = bool(trigger_apis & card_names)

    if target_library and card_library == target_library and target_api_match:
        return True, "target_api_exact_or_related"
    if source_library and card_library == source_library and trigger_api_match:
        return True, "source_trigger_api_exact_or_related"
    if family_match and (target_api_match or trigger_api_match):
        return True, "family_api_related"
    if family_match and card_library in {target_library, source_library}:
        return True, "same_family_same_library_context"
    return False, ""


def infer_from_api_cards(cards: List[Dict[str, Any]]) -> Dict[str, Any]:
    text = "\n".join(
        " ".join(
            str(x)
            for x in (
                [card.get("family"), card.get("api")]
                + card.get("mutation_hints", [])
                + card.get("oracle_observables", [])
                + card.get("state_preconditions", [])
                + card.get("known_pitfalls", [])
            )
        )
        for card in cards
    ).lower()

    dims: Set[str] = set()
    if any(term in text for term in ["lifecycle", "before setup", "double final", "abort", "after final", "uninitialized"]):
        dims.add("lifecycle_sequence")
    if any(term in text for term in ["hmac", "cmac", "mac implementation", "selected mac"]):
        dims.add("mac_algorithm")
    if any(term in text for term in ["digest", "sha", "cipher", "aes"]):
        dims.add("digest_or_cipher")
    if any(term in text for term in ["outl", "mac_length", "output length", "output_buffer", "undersized", "small mac_size"]):
        dims.add("output_length")

    return {
        "state_sensitive": any(term in text for term in ["state", "lifecycle", "uninitialized", "inactive", "stale"]),
        "lifecycle_sensitive": any(term in text for term in ["lifecycle", "before setup", "double final", "abort", "after final"]),
        "output_length_observable": any(term in text for term in ["outl", "mac_length", "output length", "returned_size"]),
        "suggested_mutation_dimensions": sorted(dims),
    }


def collect_api_card_evidence(
    candidate: Dict[str, Any],
    source_ctx: Dict[str, Any],
    api_cards: List[Dict[str, Any]],
    api_card_warnings: List[str],
) -> Dict[str, Any]:
    aliases = family_aliases(
        candidate_harness_family(candidate),
        candidate.get("oracle_type"),
        source_ctx.get("harness_family"),
        source_ctx.get("oracle_type"),
    )
    matched: List[Dict[str, Any]] = []
    seen_paths: Set[str] = set()
    for card in api_cards:
        ok, reason = api_card_matches(card, candidate, source_ctx, aliases)
        if not ok:
            continue
        path = str(card.get("path") or "")
        if path in seen_paths:
            continue
        seen_paths.add(path)
        compact = {k: v for k, v in card.items() if k != "related_apis"}
        compact["match_reason"] = reason
        matched.append(compact)

    matched.sort(key=lambda c: (str(c.get("library")), str(c.get("api")), str(c.get("path"))))
    return {
        "api_cards_root_loaded": bool(api_cards),
        "matched_cards": matched,
        "warnings": list(api_card_warnings),
        "inferred_from_cards": infer_from_api_cards(matched),
    }


def feedback_family_aliases(family: str) -> Set[str]:
    token = normalize_token(family)
    aliases = {token} if token else set()
    if token in {"pkey_verify_semantic", "pkey_verify", "signature_verify_semantic"}:
        aliases.update({
            "pkey_verify_semantic",
            "pkey_verify",
            "signature_verify_semantic",
            "signature_verification",
        })
    return aliases


def candidate_feedback_aliases(
    candidate: Dict[str, Any],
    source_ctx: Dict[str, Any],
    api_card_evidence: Dict[str, Any],
) -> Set[str]:
    aliases = family_aliases(
        candidate_harness_family(candidate),
        candidate.get("oracle_type"),
        source_ctx.get("harness_family"),
        source_ctx.get("oracle_type"),
        candidate.get("operation_family"),
    )
    text = " ".join([
        candidate_api(candidate),
        candidate_library(candidate),
        str(candidate.get("source_api") or ""),
        str(source_ctx.get("root_cause_summary") or ""),
        " ".join(str(x) for x in source_ctx.get("trigger_apis", []) or []),
        " ".join(str(card.get("family") or "") for card in api_card_evidence.get("matched_cards", []) or []),
        " ".join(str(card.get("api") or "") for card in api_card_evidence.get("matched_cards", []) or []),
    ]).lower()
    if any(term in text for term in [
        "evp_digestverify",
        "evp_pkey_verify",
        "mbedtls_pk_verify",
        "mbedtls_pk_verify_ext",
        "psa_verify_hash",
        "signature",
        "verify",
    ]):
        aliases.update(feedback_family_aliases("pkey_verify_semantic"))
    return aliases


def summarize_feedback_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    verdicts = Counter(str(row.get("verdict") or "") for row in rows)
    categories = Counter(str(row.get("feedback_category") or "") for row in rows)
    return {
        "total_feedback_cases": len(rows),
        "verdict_counts": dict(verdicts),
        "feedback_category_counts": dict(categories),
    }


def score_entries_for_family(scores_obj: Dict[str, Any], family: str) -> Dict[str, Any]:
    families = scores_obj.get("families", {}) if isinstance(scores_obj, dict) else {}
    if not isinstance(families, dict):
        return {}
    if family in families:
        return families.get(family) or {}
    wanted = normalize_token(family)
    for name, obj in families.items():
        if normalize_token(name) == wanted:
            return obj or {}
    return {}


def flatten_score_entries(scores_obj: Dict[str, Any], family: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    family_obj = score_entries_for_family(scores_obj, family)
    dimensions = family_obj.get("dimensions", {}) if isinstance(family_obj, dict) else {}
    high: List[Dict[str, Any]] = []
    down: List[Dict[str, Any]] = []
    for dimension, dim_obj in sorted((dimensions or {}).items()):
        values = dim_obj.get("values", {}) if isinstance(dim_obj, dict) else {}
        for value, score_obj in sorted((values or {}).items()):
            if not isinstance(score_obj, dict):
                continue
            entry = {
                "dimension": str(dimension),
                "value": str(value),
                "score": score_obj.get("score"),
                "classification": score_obj.get("classification", ""),
                "count": score_obj.get("count", 0),
            }
            classification = str(score_obj.get("classification", ""))
            score = float(score_obj.get("score", 0.0) or 0.0)
            if classification == "upweighted" or score >= 1.0:
                high.append(entry)
            if classification in {"downweighted", "stable_safe_negative"} and score <= 0.1:
                down.append(entry)
    high.sort(key=lambda x: (-float(x.get("score") or 0.0), x["dimension"], x["value"]))
    down.sort(key=lambda x: (float(x.get("score") or 0.0), x["dimension"], x["value"]))
    return high, down


def collect_feedback_evidence(
    candidate: Dict[str, Any],
    source_ctx: Dict[str, Any],
    api_card_evidence: Dict[str, Any],
    feedback_rows: List[Dict[str, Any]],
    feedback_scores_obj: Dict[str, Any],
    feedback_file: Optional[Path],
    feedback_scores: Optional[Path],
) -> Dict[str, Any]:
    if not feedback_rows and not feedback_scores_obj:
        return {"enabled": False}

    candidate_aliases = candidate_feedback_aliases(candidate, source_ctx, api_card_evidence)
    rows_by_family: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in feedback_rows:
        family = str(row.get("family") or "")
        if feedback_family_aliases(family) & candidate_aliases:
            rows_by_family[family].append(row)

    score_families = (feedback_scores_obj.get("families", {}) or {}) if isinstance(feedback_scores_obj, dict) else {}
    matched_family = ""
    matched_rows: List[Dict[str, Any]] = []
    for family, rows in sorted(rows_by_family.items(), key=lambda item: (-len(item[1]), item[0])):
        matched_family = family
        matched_rows = rows
        break
    if not matched_family:
        for family in sorted(score_families):
            if feedback_family_aliases(family) & candidate_aliases:
                matched_family = family
                break

    if not matched_family:
        return {
            "enabled": False,
            "reason": "no_feedback_family_match_for_candidate",
            "candidate_feedback_aliases": sorted(candidate_aliases),
        }

    high, down = flatten_score_entries(feedback_scores_obj, matched_family)
    summary = summarize_feedback_rows(matched_rows)
    notes = [
        "Feedback evidence is an auxiliary signal and does not override RAG or API-card evidence.",
        "Safe-negative feedback is treated as a stable baseline, not as a vulnerability.",
    ]
    if summary.get("verdict_counts", {}).get("safe_reject_behavior") or summary.get("feedback_category_counts", {}).get("safe_negative"):
        notes.append("PKEY verify v0 produced stable safe-negative results and no unexpected_success_candidate.")
    if high:
        notes.append("High-value mutations are kept with prior score even if v0 rejected them safely.")
    return {
        "enabled": True,
        "feedback_file": str(feedback_file or ""),
        "feedback_scores": str(feedback_scores or ""),
        "matched_family": matched_family,
        "summary": summary,
        "high_score_mutations": high[:12],
        "downweighted_mutations": down[:12],
        "notes": notes,
    }


def filter_rule_features_for_family(
    features: Set[str],
    evidence_hits: Dict[str, Dict[str, List[str]]],
    harness_family: str,
) -> Tuple[Set[str], Dict[str, Dict[str, List[str]]]]:
    allowed = FAMILY_ALLOWED_RULE_FEATURES.get(harness_family)
    if not allowed:
        return features, evidence_hits
    filtered = {f for f in features if f in allowed}
    return filtered, {k: v for k, v in evidence_hits.items() if k in filtered}


def extract_features_by_rules(
    target_text: str,
    feature_rules: Dict[str, Any],
) -> Tuple[Set[str], Set[str], Dict[str, Dict[str, List[str]]]]:
    observed: Set[str] = set()
    negative: Set[str] = set()
    evidence_hits: Dict[str, Dict[str, List[str]]] = {}

    features = feature_rules.get("generic_features", {})

    for fname, rule in features.items():
        pos = rule.get("positive", []) or []
        neg = rule.get("negative", []) or []

        pos_hits = [p for p in pos if evidence_pattern_matches(target_text, p)]
        neg_hits = [p for p in neg if evidence_pattern_matches(target_text, p)]

        if pos_hits:
            observed.add(fname)
        if neg_hits:
            negative.add(fname)

        if pos_hits or neg_hits:
            evidence_hits[fname] = {
                "positive_hits": pos_hits,
                "negative_hits": neg_hits,
            }

    return observed, negative, evidence_hits


def collect_required_features(
    bug_classes: List[str],
    feature_rules: Dict[str, Any],
) -> Dict[str, List[str]]:
    req: Set[str] = set()
    disallowed: Set[str] = set()
    optional: Set[str] = set()

    cfg = feature_rules.get("bug_class_requirements", {})

    for bug in bug_classes:
        rule = cfg.get(bug, {})
        for x in rule.get("required", []) or []:
            req.add(x)
        for x in rule.get("disallowed", []) or []:
            disallowed.add(x)
        for x in rule.get("optional", []) or []:
            optional.add(x)

    return {
        "required": sorted(req),
        "disallowed": sorted(disallowed),
        "optional": sorted(optional),
    }


def infer_features(
    candidate: Dict[str, Any],
    rag_results: List[Dict[str, Any]],
    feature_rules: Dict[str, Any],
    bug_classes: List[str],
) -> Dict[str, Any]:
    target_chunks = []
    for r in rag_results:
        if r.get("use_for_feature_inference") != "target":
            continue

        result_texts = [
            str(hit.get("text", ""))
            for hit in r.get("results", []) or []
            if isinstance(hit, dict) and hit.get("text")
        ]
        if result_texts:
            target_chunks.extend(result_texts)
        else:
            target_chunks.append(r.get("stdout_preview", ""))

    target_text = "\n".join(target_chunks)

    rule_observed, rule_negative, evidence_hits = extract_features_by_rules(target_text, feature_rules)
    harness_family = candidate_harness_family(candidate)
    rule_observed, evidence_hits = filter_rule_features_for_family(rule_observed, evidence_hits, harness_family)
    rule_negative, _ = filter_rule_features_for_family(rule_negative, {}, harness_family)

    # Candidate mapper already knows some weakened/lost features.
    candidate_lost = {normalize_feature_name(x) for x in candidate_lost_features(candidate)}
    candidate_preserved = {normalize_feature_name(x) for x in candidate_preserved_features(candidate)}

    # Keep the raw observed/negative sets visible for debugging, then compute a
    # conflict-free effective set for required_present/required_missing.
    observed = set(rule_observed)
    negative = set(rule_negative)
    for x in candidate_preserved:
        if x not in candidate_lost:
            observed.add(x)
    negative.update(candidate_lost)

    conflicts = sorted(observed & negative)
    effective_observed = observed - negative
    feature_conflicts = [
        {
            "feature": feature,
            "resolution": "removed_from_effective_observed_due_to_negative_or_lost_feature",
        }
        for feature in conflicts
    ]

    req = collect_required_features(bug_classes, feature_rules)
    required = set(req["required"])
    disallowed = set(req["disallowed"])
    optional = set(req["optional"])

    required_present = sorted(required & effective_observed)
    required_missing = sorted(required - effective_observed)
    disallowed_present = sorted(disallowed & effective_observed)
    optional_present = sorted(optional & effective_observed)

    return {
        "observed_features_from_target_evidence": sorted(observed),
        "negative_or_weakened_features": sorted(negative),
        "effective_observed_features": sorted(effective_observed),
        "feature_conflicts": feature_conflicts,
        "candidate_preserved_features": sorted(candidate_preserved),
        "candidate_lost_or_weakened_features": sorted(candidate_lost),
        "bug_class_requirements": req,
        "required_present": required_present,
        "required_missing": required_missing,
        "disallowed_present": disallowed_present,
        "optional_present": optional_present,
        "evidence_hits": evidence_hits,
    }


def collect_evidence(
    candidates_obj: Dict[str, Any],
    mask_report: Dict[str, Any],
    feature_rules: Dict[str, Any],
    timeout: int = 90,
    max_chars: int = 6000,
    top_k: int = 5,
    selected_mask_report: Optional[Dict[str, Any]] = None,
    target_api: Optional[str] = None,
    max_candidates: Optional[int] = None,
    max_queries: Optional[int] = None,
    api_cards_root: Optional[Path] = None,
    use_feedback_evidence: bool = False,
    feedback_file: Optional[Path] = None,
    feedback_scores: Optional[Path] = None,
    progress: bool = False,
) -> Dict[str, Any]:
    selected_mask_report = selected_mask_report or {}
    source_ctx = get_source_context(mask_report, selected_mask_report)
    bug_classes = get_bug_classes(mask_report, candidates_obj, feature_rules)
    key = candidate_list_key(candidates_obj)
    candidates = list(candidates_obj.get(key, []) or [])
    api_cards, api_card_warnings = load_api_cards(api_cards_root)
    feedback_rows = read_jsonl(feedback_file) if use_feedback_evidence and feedback_file else []
    feedback_scores_obj = load_optional_yaml(feedback_scores) if use_feedback_evidence and feedback_scores else {}

    if target_api:
        candidates = [
            cand for cand in candidates
            if candidate_api(cand) == target_api
        ]
        if not candidates:
            raise ValueError(f"No candidate matched --target-api {target_api!r}")

    if max_candidates is not None:
        candidates = candidates[:max_candidates]

    out = dict(candidates_obj)
    out["evidence_collection"] = {
        "method": "config_driven_rag_evidence_collector",
        "top_k": top_k,
        "target_api_filter": target_api or "",
        "max_candidates": max_candidates,
        "max_queries_per_candidate": max_queries,
        "feature_rules": "config/evidence_feature_rules.yaml",
        "bug_classes": bug_classes,
        "source_pattern": source_ctx,
        "selected_mask_units": {
            "loaded": bool(selected_mask_report),
            "summary": selected_units_summary(selected_mask_report),
        },
        "api_cards": {
            "root": str(api_cards_root or ""),
            "loaded": bool(api_cards),
            "count": len(api_cards),
            "warnings": api_card_warnings,
        },
        "feedback_evidence": {
            "enabled": bool(use_feedback_evidence),
            "feedback_file": str(feedback_file or ""),
            "feedback_scores": str(feedback_scores or ""),
            "feedback_rows": len(feedback_rows),
            "score_families": sorted(
                (feedback_scores_obj.get("families", {}) or {}).keys()
            ) if isinstance(feedback_scores_obj, dict) else [],
            "note": (
                "Feedback evidence is attached as mutation-planning context only; "
                "safe-negative feedback is a stable baseline, not a vulnerability."
            ),
        },
        "note": (
            "Evidence is retrieved before LLM adapter filling. Source-pattern evidence "
            "is kept separate from target-API evidence to avoid feature contamination."
        ),
    }

    updated_candidates = []

    for cand_idx, cand in enumerate(candidates, start=1):
        cand = dict(cand)
        queries = make_generic_queries(cand, source_ctx, bug_classes)
        if max_queries is not None:
            queries = queries[:max_queries]

        if progress:
            print(
                f"[PROGRESS] candidate {cand_idx}/{len(candidates)} "
                f"api={candidate_api(cand)} decision={cand.get('decision')}",
                flush=True,
            )

        rag_results = []
        for query_idx, q in enumerate(queries, start=1):
            if progress:
                print(
                    f"[PROGRESS] query {query_idx}/{len(queries)} "
                    f"kind={q['kind']} text={q['query']}",
                    flush=True,
                )
            result = run_rag_query(
                q["query"],
                top_k=top_k,
                timeout=timeout,
                max_chars=max_chars,
            )
            result["kind"] = q["kind"]
            result["use_for_feature_inference"] = q["use_for_feature_inference"]
            rag_results.append(result)

        inferred = infer_features(
            candidate=cand,
            rag_results=rag_results,
            feature_rules=feature_rules,
            bug_classes=bug_classes,
        )

        cand["evidence"] = {
            "top_k": top_k,
            "queries": rag_results,
            "inferred_features": inferred,
        }
        api_card_evidence = collect_api_card_evidence(
            candidate=cand,
            source_ctx=source_ctx,
            api_cards=api_cards,
            api_card_warnings=api_card_warnings,
        )
        cand["api_card_evidence"] = api_card_evidence
        cand["evidence"]["api_card_evidence"] = api_card_evidence
        if use_feedback_evidence:
            feedback_evidence = collect_feedback_evidence(
                candidate=cand,
                source_ctx=source_ctx,
                api_card_evidence=api_card_evidence,
                feedback_rows=feedback_rows,
                feedback_scores_obj=feedback_scores_obj,
                feedback_file=feedback_file,
                feedback_scores=feedback_scores,
            )
            cand["feedback_evidence"] = feedback_evidence
            cand["evidence"]["feedback_evidence"] = feedback_evidence

        updated_candidates.append(cand)

    out[key] = updated_candidates
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect config-driven RAG evidence for migration candidate APIs."
    )
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--mask-report", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--selected-mask-units",
        help=(
            "Optional selected_mask_units.yaml. If omitted, evidence_collector "
            "looks next to --mask-report."
        ),
    )
    parser.add_argument(
        "--feature-rules",
        default="config/evidence_feature_rules.yaml",
    )
    parser.add_argument(
        "--api-cards-root",
        help="Optional API cards root used to attach structured API-card evidence to each candidate.",
    )
    parser.add_argument(
        "--feedback-file",
        help="Optional mutation feedback JSONL used as auxiliary evidence.",
    )
    parser.add_argument(
        "--feedback-scores",
        help="Optional mutation feedback score YAML used as auxiliary evidence.",
    )
    parser.add_argument(
        "--use-feedback-evidence",
        action="store_true",
        help="Attach feedback_evidence blocks to matching candidates without changing legacy evidence behavior.",
    )
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--max-chars", type=int, default=6000)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument(
        "--target-api",
        help="Only process candidates whose target_api/api exactly matches this value.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        help="Process at most N candidates after optional filtering.",
    )
    parser.add_argument(
        "--max-queries",
        type=int,
        help="Run at most N generated RAG queries per candidate.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Print candidate and query progress logs to the terminal.",
    )
    args = parser.parse_args()

    candidates_obj = load_yaml(Path(args.candidates))
    mask_report_path = Path(args.mask_report)
    mask_report = load_yaml(mask_report_path)
    selected_mask_path = Path(args.selected_mask_units) if args.selected_mask_units else infer_selected_mask_units_path(mask_report_path)
    selected_mask_report = load_optional_yaml(selected_mask_path)
    feature_rules = load_yaml(Path(args.feature_rules))

    try:
        result = collect_evidence(
            candidates_obj=candidates_obj,
            mask_report=mask_report,
            feature_rules=feature_rules,
            selected_mask_report=selected_mask_report,
            timeout=args.timeout,
            max_chars=args.max_chars,
            top_k=args.top_k,
            target_api=args.target_api,
            max_candidates=args.max_candidates,
            max_queries=args.max_queries,
            api_cards_root=Path(args.api_cards_root) if args.api_cards_root else None,
            use_feedback_evidence=args.use_feedback_evidence,
            feedback_file=Path(args.feedback_file) if args.feedback_file else None,
            feedback_scores=Path(args.feedback_scores) if args.feedback_scores else None,
            progress=args.progress,
        )
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2

    dump_yaml(Path(args.output), result)
    key = candidate_list_key(result)

    print(f"[OK] evidence written to {args.output}")
    print(f"[INFO] candidates: {len(result.get(key, []))}")
    print(f"[INFO] bug_classes: {result.get('evidence_collection', {}).get('bug_classes', [])}")
    selected_info = result.get('evidence_collection', {}).get('selected_mask_units', {})
    print(f"[INFO] selected_mask_units_loaded: {selected_info.get('loaded', False)}")

    for c in result.get(key, []):
        inf = c.get("evidence", {}).get("inferred_features", {})
        print(
            candidate_library(c),
            candidate_api(c),
            "decision=",
            c.get("decision"),
            "observed=",
            inf.get("observed_features_from_target_evidence", []),
            "required_missing=",
            inf.get("required_missing", []),
            "negative=",
            inf.get("negative_or_weakened_features", []),
            "api_cards=",
            [
                card.get("api")
                for card in c.get("api_card_evidence", {}).get("matched_cards", [])
            ],
            "feedback=",
            c.get("feedback_evidence", {}).get("matched_family", "")
            if c.get("feedback_evidence", {}).get("enabled")
            else "disabled",
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

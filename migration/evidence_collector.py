import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

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
                        "layer": hit.get("layer") or metadata.get("layer", ""),
                        "source_file": hit.get("source_file") or metadata.get("source_file", ""),
                        "text": hit.get("text", ""),
                        "metadata": metadata,
                    })

                return {
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
            return {
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

        return {
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

    except subprocess.TimeoutExpired as e:
        return {
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


def get_source_context(mask_report: Dict[str, Any]) -> Dict[str, Any]:
    poc_pattern = mask_report.get("poc_pattern", {})
    root_cause = poc_pattern.get("root_cause", {})
    features = poc_pattern.get("vulnerability_path_features", {})
    guidance = poc_pattern.get("migration_guidance", {})

    return {
        "pattern_id": poc_pattern.get("pattern_id"),
        "root_cause_summary": root_cause.get("summary", ""),
        "must_preserve_features": features.get("must_preserve", []),
        "optional_features": features.get("optional", []),
        "not_required_features": features.get("not_required", []),
        "good_target_api_features": guidance.get("good_target_api_features", []),
        "bad_target_api_features": guidance.get("bad_target_api_features", []),
        "rag_query_context": mask_report.get("rag_query_context", ""),
    }


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
    lib = candidate.get("library", "")
    api = candidate.get("api", "")
    root = source_ctx.get("root_cause_summary", "")
    must = " ".join(source_ctx.get("must_preserve_features", []))
    mapping = " ".join(str(x) for x in candidate.get("parameter_mapping", {}).values())
    preserved = " ".join(candidate.get("preserved_vulnerability_features", []))
    lost = " ".join(candidate.get("lost_or_weakened_features", []))
    bug = " ".join(bug_classes)

    return [
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


def contains_any(text: str, patterns: List[str]) -> bool:
    text = text.lower()
    return any(str(p).lower() in text for p in patterns)


def normalize_feature_name(s: str) -> str:
    return str(s).strip()


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

        pos_hits = [p for p in pos if str(p).lower() in target_text.lower()]
        neg_hits = [p for p in neg if str(p).lower() in target_text.lower()]

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

    # Candidate mapper already knows some weakened/lost features.
    candidate_lost = {normalize_feature_name(x) for x in candidate.get("lost_or_weakened_features", []) or []}
    candidate_preserved = {normalize_feature_name(x) for x in candidate.get("preserved_vulnerability_features", []) or []}

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
    timeout: int,
    max_chars: int,
    top_k: int,
) -> Dict[str, Any]:
    source_ctx = get_source_context(mask_report)
    bug_classes = get_bug_classes(mask_report, candidates_obj, feature_rules)

    out = dict(candidates_obj)
    out["evidence_collection"] = {
        "method": "config_driven_rag_evidence_collector",
        "top_k": top_k,
        "feature_rules": "config/evidence_feature_rules.yaml",
        "bug_classes": bug_classes,
        "source_pattern": source_ctx,
        "note": (
            "Evidence is retrieved before LLM adapter filling. Source-pattern evidence "
            "is kept separate from target-API evidence to avoid feature contamination."
        ),
    }

    updated_candidates = []

    for cand in candidates_obj.get("target_candidates", []):
        cand = dict(cand)
        queries = make_generic_queries(cand, source_ctx, bug_classes)

        rag_results = []
        for q in queries:
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

        updated_candidates.append(cand)

    out["target_candidates"] = updated_candidates
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect config-driven RAG evidence for migration candidate APIs."
    )
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--mask-report", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--feature-rules",
        default="config/evidence_feature_rules.yaml",
    )
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--max-chars", type=int, default=6000)
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args()

    candidates_obj = load_yaml(Path(args.candidates))
    mask_report = load_yaml(Path(args.mask_report))
    feature_rules = load_yaml(Path(args.feature_rules))

    result = collect_evidence(
        candidates_obj=candidates_obj,
        mask_report=mask_report,
        feature_rules=feature_rules,
        timeout=args.timeout,
        max_chars=args.max_chars,
        top_k=args.top_k,
    )

    dump_yaml(Path(args.output), result)

    print(f"[OK] evidence written to {args.output}")
    print(f"[INFO] candidates: {len(result.get('target_candidates', []))}")
    print(f"[INFO] bug_classes: {result.get('evidence_collection', {}).get('bug_classes', [])}")

    for c in result.get("target_candidates", []):
        inf = c.get("evidence", {}).get("inferred_features", {})
        print(
            c.get("library"),
            c.get("api"),
            "decision=",
            c.get("decision"),
            "observed=",
            inf.get("observed_features_from_target_evidence", []),
            "required_missing=",
            inf.get("required_missing", []),
            "negative=",
            inf.get("negative_or_weakened_features", []),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

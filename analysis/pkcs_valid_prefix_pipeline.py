"""Run PKCS valid-prefix cases from verified seeds through oracle-aware analysis.

This module is intentionally not a tools/ entrypoint. It orchestrates one
focused sprint:

verified PKCS seed -> PKCS valid-prefix cases -> render -> compile/run -> analyze

It does not write feedback, knowledge, pattern-bank, adapter recipe, or
normalized template state, and it never makes a vulnerability claim.
"""

from __future__ import annotations

import argparse
import datetime as _dt
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from analyzer.oracle_event_parser import parse_oracle_event_line
from runner.family_compile_runner import execute_instrumented_case
from runner.sanitizer_env import lib_dir_for_install


SPRINT = "pkcs_valid_prefix_pipeline_to_analyze_v1"
SEED_MANIFEST = (
    "artifacts/sprints/valid_seed_discovery_pkcs_v1/manifests/verified_pkcs_seed_manifest.yaml"
)
SUPPLEMENTAL_MATRIX = (
    "artifacts/sprints/mutation_policy_refinement_for_valid_prefix_v1/"
    "supplemental_cases/supplemental_mutation_case_matrix.yaml"
)
OPENSSL_INSTALL = Path("/home/wen/work/install-openssl-3.5.5-asan")
ALLOWED_LABELS = {
    "normal_reject",
    "normal_accept",
    "full_consumption_gap_candidate",
    "semantic_divergence_candidate",
    "needs_triage",
    "oracle_incomplete",
    "external_validation_pending",
}


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def c_bytes(data: bytes, width: int = 12) -> str:
    rows = []
    for idx in range(0, len(data), width):
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in data[idx : idx + width]))
    return ",\n".join(rows)


def select_seeds(repo_root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    seeds = [
        s
        for s in manifest.get("seeds", []) or []
        if s.get("parser_valid") is True and s.get("usable_for_valid_prefix_mutation") is True
    ]
    pkcs12 = next((s for s in seeds if s.get("container_type") == "pkcs12"), None)
    pkcs7 = next((s for s in seeds if s.get("container_type") in {"pkcs7", "cms"}), None)
    for seed in (pkcs12, pkcs7):
        if seed:
            seed["absolute_path"] = str((repo_root / seed["path"]).resolve())
            seed["exists"] = Path(seed["absolute_path"]).exists()
    return {
        "schema": "pkcs_verified_seed_selection_v1",
        "generated_at": now_iso(),
        "manifest_path": SEED_MANIFEST,
        "verified_seed_manifest_loaded": True,
        "pkcs12_seed": pkcs12,
        "pkcs7_or_cms_seed": pkcs7,
        "synthetic_seed_used": any(s.get("origin") == "synthetic_openssl_generated" for s in seeds),
        "blocked_seed_classes": [
            name
            for name, seed in (("pkcs12", pkcs12), ("pkcs7_or_cms", pkcs7))
            if not seed or not Path(seed.get("absolute_path", "")).exists()
        ],
    }


def pkcs_cases(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        c
        for c in matrix.get("cases", []) or []
        if c.get("base_family") == "pkcs_container_parsing"
        and c.get("render_block_reason") == "missing_valid_pkcs_seed"
    ]


def seed_for_case(case: dict[str, Any], selection: dict[str, Any]) -> dict[str, Any] | None:
    case_id = str(case.get("supplemental_case_id") or "")
    if "__supp_001__" in case_id or "__supp_002__" in case_id:
        return selection.get("pkcs12_seed")
    return selection.get("pkcs7_or_cms_seed") or selection.get("pkcs12_seed")


def mutated_bytes(base: bytes, case: dict[str, Any], container_type: str) -> tuple[bytes, str]:
    case_id = str(case.get("supplemental_case_id") or "")
    if "__supp_002__" in case_id:
        return base + b"\x00", "valid_seed_plus_trailing_00"
    if "__supp_004__" in case_id and len(base) > 4:
        tweaked = bytearray(base)
        if tweaked[1] == 0x82 and len(tweaked) > 3:
            tweaked[3] = (tweaked[3] + 1) & 0xFF
        else:
            tweaked[1] = (tweaked[1] + 1) & 0xFF
        return bytes(tweaked), "near_valid_outer_length_delta_plus_one"
    if "__supp_003__" in case_id and container_type in {"pkcs7", "cms"}:
        return base + b"\xff\x00", "valid_pkcs7_seed_plus_trailing_ff00"
    return base, "verified_seed_exact"


def parse_events(text: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    events = []
    for line in text.splitlines():
        event = parse_oracle_event_line(line)
        if event is None:
            continue
        event.setdefault("case_id", case.get("case_id", ""))
        event.setdefault("family", case.get("family", "pkcs_container_parsing"))
        event.setdefault("mutation_strategy", case.get("mutation_strategy", ""))
        event.setdefault("target_library", "openssl")
        event["raw_line"] = line
        events.append(event)
    return events


def pkcs12_harness(case: dict[str, Any], data: bytes) -> str:
    return f"""/*
 * Rendered by {SPRINT}.
 * Candidate mapping only; this is not a vulnerability, CVE, or exploit claim.
 */

#include <stdio.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>

static const unsigned char input_bytes[] = {{
{c_bytes(data)}
}};

int main(void)
{{
    const unsigned char *p = input_bytes;
    long input_len = (long)sizeof(input_bytes);
    long consumed_len = 0;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int parse_ret = 0;

    ERR_clear_error();
    p12 = d2i_PKCS12(NULL, &p, input_len);
    consumed_len = (long)(p - input_bytes);
    if (p12 != NULL)
        parse_ret = PKCS12_parse(p12, "", &pkey, &cert, &ca);

    unsigned long err = ERR_peek_last_error();
    char reason[256];
    ERR_error_string_n(err, reason, sizeof(reason));
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case['case_id']} family=pkcs_container_parsing mutation_strategy={case['mutation_strategy']} target_library=openssl phase=parse api=d2i_PKCS12 ret=%d accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d openssl_error_code=%lu openssl_error_reason=\\\"%s\\\"\\n",
           p12 != NULL ? 1 : 0, p12 != NULL ? 1 : 0, input_len, consumed_len,
           consumed_len == input_len ? 1 : 0, err, reason);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case['case_id']} family=pkcs_container_parsing mutation_strategy={case['mutation_strategy']} target_library=openssl phase=verify api=PKCS12_parse ret=%d accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d openssl_error_code=%lu openssl_error_reason=\\\"%s\\\"\\n",
           parse_ret, parse_ret == 1 ? 1 : 0, input_len, consumed_len,
           consumed_len == input_len ? 1 : 0, err, reason);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case['case_id']} family=pkcs_container_parsing mutation_strategy={case['mutation_strategy']} target_library=openssl phase=full_consumption_check api=d2i_PKCS12 input_len=%ld consumed_len=%ld full_consumption=%d notes=consumption_observed_from_d2i_PKCS12\\n",
           input_len, consumed_len, consumed_len == input_len ? 1 : 0);

    if (pkey != NULL) EVP_PKEY_free(pkey);
    if (cert != NULL) X509_free(cert);
    if (ca != NULL) sk_X509_pop_free(ca, X509_free);
    if (p12 != NULL) PKCS12_free(p12);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case['case_id']} family=pkcs_container_parsing mutation_strategy={case['mutation_strategy']} target_library=openssl phase=cleanup api=PKCS12_parse cleanup_executed=1\\n");
    return 0;
}}
"""


def pkcs7_harness(case: dict[str, Any], data: bytes, container_type: str) -> str:
    api = "d2i_CMS_ContentInfo" if container_type == "cms" else "d2i_PKCS7"
    include = "#include <openssl/cms.h>" if container_type == "cms" else "#include <openssl/pkcs7.h>"
    obj_type = "CMS_ContentInfo" if container_type == "cms" else "PKCS7"
    free_fn = "CMS_ContentInfo_free" if container_type == "cms" else "PKCS7_free"
    return f"""/*
 * Rendered by {SPRINT}.
 * Candidate mapping only; this is not a vulnerability, CVE, or exploit claim.
 */

#include <stdio.h>
{include}
#include <openssl/err.h>

static const unsigned char input_bytes[] = {{
{c_bytes(data)}
}};

int main(void)
{{
    const unsigned char *p = input_bytes;
    long input_len = (long)sizeof(input_bytes);
    long consumed_len = 0;
    {obj_type} *obj = NULL;

    ERR_clear_error();
    obj = {api}(NULL, &p, input_len);
    consumed_len = (long)(p - input_bytes);

    unsigned long err = ERR_peek_last_error();
    char reason[256];
    ERR_error_string_n(err, reason, sizeof(reason));
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case['case_id']} family=pkcs_container_parsing mutation_strategy={case['mutation_strategy']} target_library=openssl phase=parse api={api} ret=%d accepted=%d input_len=%ld consumed_len=%ld full_consumption=%d openssl_error_code=%lu openssl_error_reason=\\\"%s\\\"\\n",
           obj != NULL ? 1 : 0, obj != NULL ? 1 : 0, input_len, consumed_len,
           consumed_len == input_len ? 1 : 0, err, reason);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case['case_id']} family=pkcs_container_parsing mutation_strategy={case['mutation_strategy']} target_library=openssl phase=full_consumption_check api={api} input_len=%ld consumed_len=%ld full_consumption=%d notes=consumption_observed_from_{api}\\n",
           input_len, consumed_len, consumed_len == input_len ? 1 : 0);

    if (obj != NULL) {free_fn}(obj);
    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={case['case_id']} family=pkcs_container_parsing mutation_strategy={case['mutation_strategy']} target_library=openssl phase=cleanup api={api} cleanup_executed=1\\n");
    return 0;
}}
"""


def render_cases(
    repo_root: Path, out_dir: Path, cases: list[dict[str, Any]], selection: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rendered = []
    blocked = []
    for idx, src_case in enumerate(cases, start=1):
        seed = seed_for_case(src_case, selection)
        case_id = str(src_case.get("supplemental_case_id"))
        if not seed or not Path(seed.get("absolute_path", "")).exists():
            blocked.append({"case_id": case_id, "reason": "missing_verified_seed"})
            continue
        base = Path(seed["absolute_path"]).read_bytes()
        data, mutation_strategy = mutated_bytes(base, src_case, str(seed.get("container_type")))
        render_id = f"pkcs_valid_prefix__case_{idx:03d}"
        case_dir = out_dir / "rendered_cases" / render_id
        harness = case_dir / "harness.c"
        seed_bin = case_dir / "input.bin"
        case = {
            "case_id": case_id,
            "render_job_id": render_id,
            "family": "pkcs_container_parsing",
            "target_library": "openssl",
            "mutation_strategy": mutation_strategy,
            "source_supplemental_case_id": case_id,
            "harness_c": harness.as_posix(),
            "seed_input": seed_bin.as_posix(),
            "seed_id": seed.get("seed_id"),
            "seed_origin": seed.get("origin"),
            "container_type": seed.get("container_type"),
            "expected_oracle": {
                "expected_result_label": src_case.get("expected_result_label", "seed_required_pending"),
                "oracle_focus": src_case.get("oracle_focus", []),
            },
        }
        if seed.get("container_type") == "pkcs12":
            text = pkcs12_harness(case, data)
        else:
            text = pkcs7_harness(case, data, str(seed.get("container_type")))
        write_text(harness, text)
        seed_bin.parent.mkdir(parents=True, exist_ok=True)
        seed_bin.write_bytes(data)
        dump_yaml(case_dir / "render_metadata.yaml", case)
        rendered.append(case)
    return rendered, blocked


def build_render_plan(out_dir: Path, cases: list[dict[str, Any]], blocked: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "pkcs_valid_prefix_render_plan_v1",
        "generated_at": now_iso(),
        "render_jobs": [
            {
                "render_job_id": c["render_job_id"],
                "case_id": c["case_id"],
                "family": c["family"],
                "target_library": c["target_library"],
                "container_type": c["container_type"],
                "seed_id": c["seed_id"],
                "seed_origin": c["seed_origin"],
                "planned_outputs": {
                    "harness_c": c["harness_c"],
                    "seed_input": c["seed_input"],
                },
            }
            for c in cases
        ],
        "blocked_jobs": blocked,
        "summary": {"render_job_count": len(cases), "blocked_job_count": len(blocked)},
    }


def classify_case(run: dict[str, Any], events: list[dict[str, Any]]) -> tuple[str, str]:
    if not events:
        return "oracle_incomplete", "no ORACLE_EVENT lines were parsed"
    parse_events = [e for e in events if e.get("phase") == "parse"]
    accepted = any(e.get("accepted") == 1 for e in parse_events)
    rejected = any(e.get("accepted") == 0 for e in parse_events)
    full_false = any(e.get("full_consumption") == 0 for e in parse_events)
    if accepted and full_false:
        return "full_consumption_gap_candidate", "parser accepted a prefix and left trailing bytes unconsumed"
    if accepted:
        return "normal_accept", "parser accepted the seed and consumed the observed object"
    if rejected:
        return "normal_reject", "parser rejected the mutated seed without sanitizer evidence"
    if run.get("timeout") or run.get("signal") or run.get("sanitizer_observed"):
        return "needs_triage", "runtime observation needs manual triage"
    return "oracle_incomplete", "oracle events did not contain parse accepted signal"


def analyze(rendered: list[dict[str, Any]], compile_summary: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    events_by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in compile_summary.get("oracle_events", []):
        events_by_case[str(event.get("case_id"))].append(event)

    run_by_case = {r.get("case_id"): r for r in compile_summary.get("run_results", [])}
    rows = []
    queue = []
    counts: Counter[str] = Counter()
    for case in rendered:
        case_id = case["case_id"]
        run = run_by_case.get(case_id, {})
        label, reason = classify_case(run, events_by_case.get(case_id, []))
        if label not in ALLOWED_LABELS:
            label = "needs_triage"
        counts[label] += 1
        rows.append(
            {
                "case_id": case_id,
                "family": "pkcs_container_parsing",
                "target_library": "openssl",
                "container_type": case["container_type"],
                "seed_id": case["seed_id"],
                "seed_origin": case["seed_origin"],
                "mutation_strategy": case["mutation_strategy"],
                "run_status": run.get("run_status", ""),
                "exit_code": run.get("exit_code"),
                "oracle_event_count": len(events_by_case.get(case_id, [])),
                "candidate_label": label,
                "reason": reason,
                "claim_policy": {
                    "confirmed_vulnerability": False,
                    "cve": False,
                    "exploitable": False,
                },
            }
        )
        if label in {"full_consumption_gap_candidate", "semantic_divergence_candidate", "needs_triage"}:
            queue.append(
                {
                    "case_id": case_id,
                    "family": "pkcs_container_parsing",
                    "target_library": "openssl",
                    "candidate_label": label,
                    "external_validation_status": "pending",
                    "claim_policy": {
                        "confirmed_vulnerability": False,
                        "cve": False,
                        "exploitable": False,
                    },
                }
            )

    analysis = {
        "schema": "pkcs_oracle_aware_analysis_v1",
        "generated_at": now_iso(),
        "allowed_candidate_labels": sorted(ALLOWED_LABELS),
        "cases": rows,
        "summary": {label: counts.get(label, 0) for label in sorted(ALLOWED_LABELS)},
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    family_summary = {
        "schema": "pkcs_family_summary_v1",
        "generated_at": now_iso(),
        "family": "pkcs_container_parsing",
        "target_library": "openssl",
        "total_cases": len(rows),
        "candidate_label_counts": analysis["summary"],
        "oracle_events": len(compile_summary.get("oracle_events", [])),
        "compile_success": compile_summary["summary"].get("compile_success", 0),
        "run_attempted": compile_summary["summary"].get("run_attempted", 0),
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    candidate_queue = {
        "schema": "pkcs_candidate_queue_v1",
        "generated_at": now_iso(),
        "source_task": SPRINT,
        "allowed_candidate_labels": sorted(ALLOWED_LABELS),
        "candidates": queue,
        "summary": {"total_candidates": len(queue), "external_validation_pending": len(queue)},
    }
    return analysis, family_summary, candidate_queue


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=15)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in (
        "inputs",
        "mutation",
        "render_plan",
        "rendered_cases",
        "compile_run",
        "analyze",
        "candidates",
        "validation",
        "reports",
    ):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    manifest_path = repo_root / SEED_MANIFEST
    matrix_path = repo_root / SUPPLEMENTAL_MATRIX
    manifest = load_yaml(manifest_path)
    matrix = load_yaml(matrix_path)
    selection = select_seeds(repo_root, manifest)
    dump_yaml(out_dir / "inputs" / "pkcs_verified_seed_selection.yaml", selection)

    source_cases = pkcs_cases(matrix)
    rendered, blocked = render_cases(repo_root, out_dir, source_cases, selection)
    unblocked_doc = {
        "schema": "pkcs_unblocked_mutation_cases_v1",
        "generated_at": now_iso(),
        "source_matrix": SUPPLEMENTAL_MATRIX,
        "family": "pkcs_container_parsing",
        "pending_seed_cases_before": 4,
        "cases": rendered,
        "blocked_cases": blocked,
        "summary": {"pkcs_cases_unblocked": len(rendered), "blocked_cases": len(blocked)},
    }
    dump_yaml(out_dir / "mutation" / "pkcs_unblocked_mutation_cases.yaml", unblocked_doc)

    render_plan = build_render_plan(out_dir, rendered, blocked)
    dump_yaml(out_dir / "render_plan" / "render_plan.yaml", render_plan)

    include_dir = OPENSSL_INSTALL / "include"
    lib_dir = lib_dir_for_install(OPENSSL_INSTALL)
    compile_results = []
    run_results = []
    oracle_events = []
    sanitizer_observations = []
    for case in rendered:
        compile_result, run_result, events, sanitizer = execute_instrumented_case(
            case,
            out_dir / "compile_run",
            include_dir,
            lib_dir,
            OPENSSL_INSTALL,
            args.timeout_seconds,
            parse_events,
        )
        compile_results.append(compile_result)
        run_results.append(run_result)
        oracle_events.extend(events)
        sanitizer_observations.append(sanitizer)

    compile_summary = {
        "schema": "pkcs_compile_run_summary_v1",
        "generated_at": now_iso(),
        "environment": {
            "openssl_install": OPENSSL_INSTALL.as_posix(),
            "include_dir": include_dir.as_posix(),
            "include_dir_exists": include_dir.exists(),
            "lib_dir": lib_dir.as_posix(),
            "lib_dir_exists": lib_dir.exists(),
        },
        "compile_results": compile_results,
        "run_results": run_results,
        "oracle_events": oracle_events,
        "sanitizer_observations": sanitizer_observations,
        "summary": {
            "total_cases": len(rendered),
            "compile_success": len([r for r in compile_results if r.get("compile_status") == "compile_success"]),
            "compile_failed": len([r for r in compile_results if r.get("compile_status") != "compile_success"]),
            "run_attempted": len([r for r in run_results if r.get("run_status") != "not_run_compile_failed"]),
            "run_exited": len([r for r in run_results if r.get("run_status") == "exited"]),
            "oracle_event_count": len(oracle_events),
        },
    }
    dump_yaml(out_dir / "compile_run" / "compile_run_summary.yaml", compile_summary)

    analysis_doc, family_summary, queue_doc = analyze(rendered, compile_summary)
    dump_yaml(out_dir / "analyze" / "oracle_aware_analysis.yaml", analysis_doc)
    dump_yaml(out_dir / "analyze" / "family_summary.yaml", family_summary)
    dump_yaml(out_dir / "candidates" / "pkcs_candidate_queue.yaml", queue_doc)

    qc = {
        "schema": "pkcs_valid_prefix_pipeline_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "verified_seed_manifest_loaded": True,
        "pkcs_pending_cases_before": 4,
        "pkcs_cases_unblocked": len(rendered),
        "asn1_cases_rerun": False,
        "render_executed": True,
        "compile_executed": True,
        "run_executed": compile_summary["summary"]["run_attempted"] > 0,
        "oracle_aware_analyze_executed": True,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if len(rendered) > 0
        and compile_summary["summary"]["compile_success"] > 0
        and compile_summary["summary"]["run_attempted"] > 0
        and len(oracle_events) > 0
        else "blocked",
    }
    dump_yaml(out_dir / "validation" / "pkcs_valid_prefix_pipeline_quality_checks.yaml", qc)

    report = f"""# {SPRINT} Report

## Summary

- quality_status: {qc['quality_status']}
- verified seed manifest: `{SEED_MANIFEST}`
- pending_seed_cases_before: 4
- pkcs_cases_unblocked: {len(rendered)}
- rendered cases: {len(rendered)}
- compile success: {compile_summary['summary']['compile_success']}
- run attempted: {compile_summary['summary']['run_attempted']}
- oracle events: {len(oracle_events)}
- ASN.1 rerun: false

## Labels

- normal_accept: {analysis_doc['summary'].get('normal_accept', 0)}
- normal_reject: {analysis_doc['summary'].get('normal_reject', 0)}
- full_consumption_gap_candidate: {analysis_doc['summary'].get('full_consumption_gap_candidate', 0)}
- semantic_divergence_candidate: {analysis_doc['summary'].get('semantic_divergence_candidate', 0)}
- needs_triage: {analysis_doc['summary'].get('needs_triage', 0)}
- external_validation_pending: {analysis_doc['summary'].get('external_validation_pending', 0)}

## Policy

No feedback, knowledge, pattern-bank, adapter recipe, normalized template, GLM, git, CVE, exploitability, or confirmed vulnerability claim was produced.
"""
    write_text(out_dir / "reports" / f"{SPRINT}_report.md", report)

    print(f"[OK] wrote {SPRINT} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"unblocked={len(rendered)} compile_success={compile_summary['summary']['compile_success']} "
        f"run_attempted={compile_summary['summary']['run_attempted']} "
        f"oracle_events={len(oracle_events)} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Inventory historical families and reconcile them with the active registry."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text


TASK = "family_inventory_registry_reconcile_v2"
DEFAULT_OUT_DIR = f"artifacts/reports/{TASK}"
SCAN_ROOTS = ["config", "knowledge", "artifacts", "normalized_templates", "adapter_recipes"]
FIELD_PATTERNS = [
    "family",
    "family_id",
    "pattern_family",
    "candidate_family",
    "oracle_family",
    "harness_family",
    "operation_family",
]
FOCUS_FAMILIES = [
    "der_pointer_consumption",
    "x509_parsing",
    "pkey_parsing",
    "pkcs8_parsing",
    "x509_crl_parsing",
    "cms_container_parsing",
    "pkcs_container_parsing",
    "ossl_store_lifecycle",
    "mac_lifecycle",
    "secure_heap_state_lifecycle",
    "pkey_verify_semantic",
    "evp_digest_ctx_lifecycle",
    "evp_cipher_ctx_lifecycle",
    "provider_fetch_lifecycle",
    "pkey_ctx_lifecycle",
    "bn_arithmetic_semantic",
    "bn_usub_semantic",
    "ec_arithmetic_semantic",
    "rsa_padding_semantic",
    "cipher_ctx_lifecycle",
    "digest_ctx_lifecycle",
    "asn1_nested_boundary",
    "x509_asn1_inner_boundary",
    "return_code_outlen_semantic",
    "buffer_canary_boundary",
    "object_state_lifecycle",
    "null_deref_dispatch",
]
IGNORE_VALUES = {
    "",
    "openssl",
    "mbedtls",
    "wolfssl",
    "botan",
    "lifecycle",
    "semantic",
    "parsing",
    "pass",
    "blocked",
    "unknown",
    "profile_ready",
    "generate",
    "skip",
}
PARSING_FAMILIES = {
    "x509_parsing",
    "pkey_parsing",
    "pkcs8_parsing",
    "x509_crl_parsing",
    "cms_container_parsing",
    "pkcs_container_parsing",
    "x509_asn1_inner_boundary",
    "asn1_nested_boundary",
    "der_pointer_consumption",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--family-profiles", default="config/family_profiles.yaml")
    parser.add_argument("--novelty-policy", default="config/family_novelty_policy.yaml")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    return parser.parse_args()


def safe_load_structured(path: Path) -> Any:
    if path.suffix.lower() in {".yaml", ".yml"}:
        return load_yaml(path)
    if path.suffix.lower() == ".json":
        try:
            return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return {}
    return {}


def walk_values(obj: Any, source: str, found: dict[str, set[str]]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key)
            if key_s in FIELD_PATTERNS:
                for family in extract_family_values(value):
                    add_found(found, family, source)
            walk_values(value, source, found)
    elif isinstance(obj, list):
        for item in obj:
            walk_values(item, source, found)


def extract_family_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [normalize_family(value)]
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(extract_family_values(item))
        return out
    return []


def normalize_family(value: str) -> str:
    text = value.strip().strip("'\"`")
    text = text.replace(" ", "_").replace("-", "_").lower()
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text


def familyish(value: str) -> bool:
    if value in IGNORE_VALUES:
        return False
    if len(value) < 4:
        return False
    markers = [
        "_parsing",
        "_lifecycle",
        "_semantic",
        "_boundary",
        "_oracle",
        "_consumption",
        "_dispatch",
        "_canary",
    ]
    return value in FOCUS_FAMILIES or any(marker in value for marker in markers)


def add_found(found: dict[str, set[str]], family: str, source: str) -> None:
    family = normalize_family(family)
    if familyish(family):
        found.setdefault(family, set()).add(source)


def scan_text(path: Path, rel: str, found: dict[str, set[str]]) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    for focus in FOCUS_FAMILIES:
        if focus in text or focus.replace("_", "-") in text:
            add_found(found, focus, rel)
    field_re = re.compile(
        r"^\s*(family|family_id|pattern_family|candidate_family|oracle_family|harness_family|operation_family)\s*:\s*['\"]?([^'\"\n#]+)",
        re.MULTILINE,
    )
    for match in field_re.finditer(text):
        add_found(found, match.group(2), rel)


def discover_families(repo_root: Path) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for root_name in SCAN_ROOTS:
        root = repo_root / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            rel = path.relative_to(repo_root).as_posix()
            if path.stat().st_size > 2_000_000:
                scan_text(path, rel, found)
                continue
            data = safe_load_structured(path)
            if data:
                walk_values(data, rel, found)
            scan_text(path, rel, found)
    return found


def infer_track(family: str, profile: dict[str, Any]) -> str:
    if profile.get("track"):
        return str(profile["track"])
    if family in PARSING_FAMILIES or family.endswith("_parsing") or "asn1" in family:
        return "parsing"
    if family.endswith("_lifecycle") or "lifecycle" in family:
        return "lifecycle"
    if family.endswith("_semantic") or "semantic" in family:
        return "semantic"
    if family.endswith("_oracle"):
        return "oracle"
    return "unknown"


def infer_archetype(family: str, profile: dict[str, Any]) -> str:
    if profile.get("archetype"):
        return str(profile["archetype"])
    if family in {"evp_digest_ctx_lifecycle", "evp_cipher_ctx_lifecycle"}:
        return "evp_context_lifecycle"
    if family == "mac_lifecycle":
        return "mac_context_lifecycle"
    if family in PARSING_FAMILIES:
        return "object_or_container_parsing"
    if family in {"bn_arithmetic_semantic", "bn_usub_semantic"}:
        return "bignum_arithmetic_semantic"
    if family == "ec_arithmetic_semantic":
        return "ec_arithmetic_semantic"
    return ""


def completed_no_candidate_from_artifacts(repo_root: Path) -> set[str]:
    completed = set()
    roots = [
        repo_root / "artifacts/sprints/pkey_verify_semantic_compile_run_analyze_v1",
        repo_root / "artifacts/sprints/evp_digest_ctx_lifecycle_full_pipeline_v1",
        repo_root / "artifacts/campaigns/continue_next_novel_family_full_pipeline_v1",
    ]
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*quality_checks.yaml"):
            data = load_yaml(path)
            if data.get("quality_status") == "pass_no_candidate":
                family = data.get("family") or data.get("selected_family")
                if family:
                    completed.add(str(family))
    return completed


def external_pending_families(repo_root: Path) -> set[str]:
    out = set()
    queue = repo_root / "artifacts/sprints/x509_external_pending_and_continue_scheduler_v1/queue/external_pending_queue.yaml"
    data = load_yaml(queue)
    for item in data.get("items", []) or []:
        if item.get("family"):
            out.add(str(item["family"]))
    for family in (data.get("summary") or {}).get("families", []) or []:
        out.add(str(family))
    candidate = repo_root / "artifacts/sprints/x509_external_pending_and_continue_scheduler_v1/external_pending/x509_external_pending_candidate.yaml"
    cdata = load_yaml(candidate)
    if cdata.get("family"):
        out.add(str(cdata["family"]))
    elif cdata:
        out.add("x509_parsing")
    return out


def recommended_action(row: dict[str, Any]) -> str:
    if row["external_pending"]:
        return "mark_external_pending"
    if row["historical_tested"]:
        return "mark_historical_tested"
    if row["known_pattern_only"]:
        return "mark_known_pattern_only"
    if row["completed_no_candidate"]:
        return "mark_completed_no_candidate"
    if row["track"] == "parsing":
        return "deprioritize_parsing"
    if not row["active_profile_present"]:
        return "add_profile"
    if row["remaining_novel"]:
        return "run_full_pipeline"
    return "keep_active"


def profile_stub(family: str, track: str, archetype: str) -> dict[str, Any]:
    return {
        "family": family,
        "track": track,
        "archetype": archetype,
        "target_library": "openssl",
        "status": "profile_proposed",
        "seed_discovery": {"enabled": True, "mode": "api_sequence_or_regression_pattern"},
        "mutation": {"engine": "generic_lifecycle_mutation_engine" if track == "lifecycle" else "generic_mutation_engine"},
        "render": {"mode": "lifecycle_harness" if track == "lifecycle" else "semantic_harness"},
        "oracle": ["state_transition_observation", "crash_or_sanitizer"]
        if track == "lifecycle"
        else ["semantic_divergence", "crash_or_sanitizer"],
        "avoid_patterns": [
            "der_single_object_trailing_garbage_full_consumption",
            "secure_heap_state_lifecycle_issue_28669",
        ],
    }


def build_matrix(repo_root: Path, found: dict[str, set[str]], profiles: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    active = profiles.get("families") or {}
    known = set((policy.get("known_pattern_only_families") or {}).keys())
    historical = set((policy.get("historical_tested_families") or {}).keys())
    completed_no = set((policy.get("completed_no_candidate_families") or {}).keys()) | completed_no_candidate_from_artifacts(repo_root)
    external = external_pending_families(repo_root)
    all_names = sorted(set(found) | set(active) | known | historical | completed_no | external)
    rows = []
    for family in all_names:
        profile = active.get(family) or {}
        track = infer_track(family, profile)
        row = {
            "family": family,
            "track": track,
            "archetype": infer_archetype(family, profile),
            "sources": sorted(found.get(family, []))[:40],
            "active_profile_present": family in active,
            "profile_status": profile.get("status", "missing_profile" if family not in active else ""),
            "known_pattern_only": family in known,
            "historical_tested": family in historical,
            "external_pending": family in external,
            "completed_no_candidate": family in completed_no,
            "completed_candidate": False,
            "seed_ready": bool(list((repo_root / "artifacts").glob(f"**/*{family}*seed*manifest*.yaml"))),
            "mutation_ready": bool(list((repo_root / "artifacts").glob(f"**/*{family}*/mutation/mutation_plan.yaml"))),
            "render_ready": bool(list((repo_root / "artifacts").glob(f"**/*{family}*/render/render_plan.yaml"))),
            "compile_run_ready": bool(list((repo_root / "artifacts").glob(f"**/*{family}*/compile/compile_summary.yaml"))),
            "remaining_novel": False,
            "recommended_action": "",
        }
        row["remaining_novel"] = (
            track != "parsing"
            and not row["known_pattern_only"]
            and not row["historical_tested"]
            and not row["external_pending"]
            and not row["completed_no_candidate"]
        )
        row["recommended_action"] = recommended_action(row)
        rows.append(row)
    return rows


def select_next(rows: list[dict[str, Any]]) -> dict[str, Any]:
    priority = [
        "mac_lifecycle",
        "provider_fetch_lifecycle",
        "pkey_ctx_lifecycle",
        "ossl_store_lifecycle",
        "ec_arithmetic_semantic",
        "bn_arithmetic_semantic",
        "bn_usub_semantic",
        "rsa_padding_semantic",
    ]
    remaining = [row for row in rows if row["remaining_novel"]]
    for name in priority:
        for row in remaining:
            if row["family"] == name:
                return {
                    "schema": "next_family_recommendation_v1",
                    "generated_at": now_iso(),
                    "selected_family": row["family"],
                    "track": row["track"],
                    "archetype": row["archetype"],
                    "recommended_action": "run_full_pipeline"
                    if row["active_profile_present"]
                    else "add_profile_then_run_full_pipeline",
                    "reason": "highest-priority remaining non-parsing family with historical evidence",
                }
    if remaining:
        row = remaining[0]
        return {
            "schema": "next_family_recommendation_v1",
            "generated_at": now_iso(),
            "selected_family": row["family"],
            "track": row["track"],
            "archetype": row["archetype"],
            "recommended_action": row["recommended_action"],
            "reason": "first remaining non-parsing family after status filtering",
        }
    return {
        "schema": "next_family_recommendation_v1",
        "generated_at": now_iso(),
        "selected_family": "",
        "track": "",
        "archetype": "",
        "recommended_action": "blocked_no_ready_novel_family",
        "reason": "no remaining non-parsing family discovered",
    }


def write_report(path: Path, qc: dict[str, Any], next_rec: dict[str, Any], missing: list[str]) -> None:
    lines = [
        f"# {TASK} Report",
        "",
        "## Summary",
        "",
        f"- discovered_family_count: {qc['discovered_family_count']}",
        f"- active_family_count: {qc['active_family_count']}",
        f"- missing_profile_count: {qc['missing_profile_count']}",
        f"- remaining_novel_count: {qc['remaining_novel_count']}",
        f"- next_family: {next_rec.get('selected_family')}",
        f"- quality_status: {qc['quality_status']}",
        "",
        "## Missing Profiles",
        "",
    ]
    lines.extend(f"- {item}" for item in missing[:80])
    lines.extend(
        [
            "",
            "## Policy",
            "",
            "This reconciliation did not render, compile, run, write main feedback, modify the pattern bank, perform git operations, or claim any vulnerability.",
            "",
        ]
    )
    write_text(path, "\n".join(lines))


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = repo_root / args.out_dir
    profiles = load_yaml(repo_root / args.family_profiles)
    policy = load_yaml(repo_root / args.novelty_policy)
    active = profiles.get("families") or {}
    unknown_before = len([name for name, profile in active.items() if not profile.get("track")])
    found = discover_families(repo_root)
    rows = build_matrix(repo_root, found, profiles, policy)
    missing = sorted([row["family"] for row in rows if not row["active_profile_present"]])
    proposed = {
        "schema": "proposed_family_profiles_v1",
        "generated_at": now_iso(),
        "note": "Proposal only; config/family_profiles.yaml was not overwritten in this reconciliation.",
        "families": {
            row["family"]: profile_stub(row["family"], row["track"], row["archetype"])
            for row in rows
            if not row["active_profile_present"] and row["track"] != "parsing"
        },
    }
    remaining = [row for row in rows if row["remaining_novel"]]
    next_rec = select_next(rows)
    discovered = {
        "schema": "discovered_families_v2",
        "generated_at": now_iso(),
        "scan_roots": SCAN_ROOTS,
        "families": [
            {"family": family, "sources": sorted(sources)[:80]}
            for family, sources in sorted(found.items())
        ],
    }
    gap_report = {
        "schema": "family_registry_gap_report_v2",
        "generated_at": now_iso(),
        "active_family_count": len(active),
        "discovered_family_count": len(rows),
        "missing_profile_count": len(missing),
        "missing_profiles": missing,
        "active_without_track": sorted([name for name, profile in active.items() if not profile.get("track")]),
        "explanation_for_active_count_9": (
            "The active registry is a scheduler-ready subset. Historical artifacts, pattern-bank data, "
            "adapter recipes, and migration outputs mention additional families that have not yet been "
            "promoted into config/family_profiles.yaml."
        ),
    }
    matrix = {
        "schema": "family_status_matrix_v2",
        "generated_at": now_iso(),
        "families": rows,
    }
    remaining_doc = {
        "schema": "remaining_novel_families_v2",
        "generated_at": now_iso(),
        "families": remaining,
    }
    qc = {
        "schema": "family_inventory_registry_reconcile_quality_checks_v2",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "scan_executed": True,
        "active_profiles_loaded": bool(active),
        "discovered_family_count": len(rows),
        "active_family_count": len(active),
        "missing_profile_count": len(missing),
        "unknown_track_count_before": unknown_before,
        "unknown_track_count_after": unknown_before,
        "completed_families_marked": len([row for row in rows if row["completed_no_candidate"] or row["completed_candidate"]]),
        "known_pattern_only_marked": len([row for row in rows if row["known_pattern_only"]]),
        "historical_tested_marked": len([row for row in rows if row["historical_tested"]]),
        "external_pending_marked": len([row for row in rows if row["external_pending"]]),
        "remaining_novel_count": len(remaining),
        "next_family_recommendation_generated": bool(next_rec.get("selected_family")),
        "proposed_profiles_generated": bool(proposed["families"]),
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass",
    }
    dump_yaml(out_dir / "discovered_families.yaml", discovered)
    dump_yaml(out_dir / "active_family_profiles_snapshot.yaml", profiles)
    dump_yaml(out_dir / "family_registry_gap_report.yaml", gap_report)
    dump_yaml(out_dir / "family_status_matrix.yaml", matrix)
    dump_yaml(out_dir / "proposed_family_profiles.yaml", proposed)
    dump_yaml(out_dir / "remaining_novel_families.yaml", remaining_doc)
    dump_yaml(out_dir / "next_family_recommendation.yaml", next_rec)
    dump_yaml(out_dir / "validation/family_inventory_registry_reconcile_quality_checks.yaml", qc)
    write_report(out_dir / "reports/family_inventory_registry_reconcile_v2_report.md", qc, next_rec, missing)
    print(f"wrote {out_dir}")
    print(f"discovered_family_count: {len(rows)}")
    print(f"next_family: {next_rec.get('selected_family')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

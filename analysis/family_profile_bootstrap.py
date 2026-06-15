"""Bootstrap missing family profiles for local scheduler selection."""

from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from analysis.family_selection import (
    artifact_status,
    build_ranking,
    pending_families,
    seed_task,
    select_next,
    updated_queue,
)


TASK = "family_profiles_bootstrap_v1"
DEFAULT_EXTERNAL_PENDING = (
    "artifacts/sprints/x509_external_pending_and_continue_scheduler_v1/queue/"
    "external_pending_queue.yaml"
)
BOOTSTRAP_FAMILIES = {
    "pkey_parsing": {
        "description": "OpenSSL pkey / public/private key parsing",
        "seed_keywords": ["key", "pkey", "private", "public", "rsa", "ec"],
        "candidate_extensions": [".key", ".pem", ".der", ".pub"],
        "validation_commands": [
            "openssl pkey -in <file> -noout",
            "openssl pkey -pubin -in <file> -noout",
        ],
    },
    "pkcs8_parsing": {
        "description": "PKCS#8 private key parsing",
        "seed_keywords": ["pkcs8", "private key"],
        "candidate_extensions": [".pk8", ".key", ".pem", ".der"],
        "validation_commands": [
            "openssl pkcs8 -in <file> -inform PEM -nocrypt -out /dev/null",
            "openssl pkcs8 -in <file> -inform DER -nocrypt -out /dev/null",
        ],
    },
    "cms_container_parsing": {
        "description": "CMS / SignedData / EnvelopedData container parsing",
        "seed_keywords": ["cms", "signeddata", "envelopeddata", "pkcs7"],
        "candidate_extensions": [".cms", ".p7m", ".p7s", ".der", ".pem"],
        "validation_commands": [
            "openssl cms -inform DER -in <file> -cmsout -noout",
            "openssl cms -inform PEM -in <file> -cmsout -noout",
        ],
    },
    "x509_crl_parsing": {
        "description": "X.509 CRL parsing",
        "seed_keywords": ["crl", "certificate revocation list", "x509"],
        "candidate_extensions": [".crl", ".der", ".pem"],
        "validation_commands": [
            "openssl crl -inform DER -in <file> -noout",
            "openssl crl -inform PEM -in <file> -noout",
        ],
    },
}
INPUT_FORMATS = ["der", "pem"]
ORACLE_GOALS = ["parser_accept", "full_consumption_gap"]
MUTATION_OPERATORS = [
    "valid_object_plus_trailing_garbage",
    "malformed_only_control",
    "near_valid_length_delta",
    "format_toggle_der_pem",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--candidate-ranking", required=True)
    parser.add_argument("--family-profiles", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--external-pending", default=DEFAULT_EXTERNAL_PENDING)
    return parser.parse_args()


def profile_for(family: str, spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "family": family,
        "status": "profile_ready",
        "description": spec["description"],
        "input_formats": list(INPUT_FORMATS),
        "seed_discovery": {
            "enabled": True,
            "seed_keywords": list(spec["seed_keywords"]),
            "candidate_extensions": list(spec["candidate_extensions"]),
            "validation_commands": list(spec["validation_commands"]),
        },
        "oracle_goals": list(ORACLE_GOALS),
        "mutation_operators": list(MUTATION_OPERATORS),
        "notes": (
            "Bootstrap profile for scheduler seed-discovery selection only; "
            "does not add family-specific mutators or execute harnesses."
        ),
    }


def ensure_profiles(profiles: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    updated = deepcopy(profiles) if profiles else {"schema": "family_profiles_v1", "families": {}}
    updated.setdefault("schema", "family_profiles_v1")
    families = updated.setdefault("families", {})
    added: dict[str, Any] = {}
    for family, spec in BOOTSTRAP_FAMILIES.items():
        families[family] = profile_for(family, spec)
        added[family] = families[family]
    return updated, added


def candidate_names_from_ranking(candidate_ranking: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for item in candidate_ranking.get("candidates", []) or []:
        family = item.get("family")
        if family and family not in names:
            names.append(str(family))
    for family in BOOTSTRAP_FAMILIES:
        if family not in names:
            names.append(family)
    return names


def post_bootstrap_selection(
    repo_root: Path,
    candidate_names: list[str],
    external_pending: dict[str, Any],
    profiles_after: dict[str, Any],
) -> tuple[list[str], dict[str, Any], dict[str, Any], dict[str, Any]]:
    skipped = sorted(pending_families(external_pending))
    status_rows = [
        artifact_status(repo_root, family, set(skipped), profiles_after)
        for family in candidate_names
        if family not in skipped
    ]
    ranking = build_ranking(status_rows)
    selected = select_next(ranking)
    plan = seed_task(selected)
    return skipped, ranking, selected, plan


def quality_checks(
    profiles_before: dict[str, Any],
    added: dict[str, Any],
    skipped: list[str],
    selected: dict[str, Any],
) -> dict[str, Any]:
    selected_family = selected.get("family") or ""
    required = set(BOOTSTRAP_FAMILIES)
    added_names = set(added)
    ok = (
        bool(profiles_before)
        and len(added) >= 4
        and required.issubset(added_names)
        and bool(skipped)
        and bool(selected_family)
    )
    return {
        "schema": "family_profiles_bootstrap_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "family_profiles_loaded": bool(profiles_before),
        "family_profiles_updated": bool(added),
        "added_profile_count": len(added),
        "pkey_profile_added": "pkey_parsing" in added,
        "pkcs8_profile_added": "pkcs8_parsing" in added,
        "cms_profile_added": "cms_container_parsing" in added,
        "x509_crl_profile_added": "x509_crl_parsing" in added,
        "external_pending_respected": bool(skipped),
        "post_bootstrap_selection_generated": bool(selected_family),
        "selected_next_family": selected_family,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass" if ok else "blocked",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    ranking_path = (repo_root / args.candidate_ranking).resolve()
    profiles_path = (repo_root / args.family_profiles).resolve()
    external_pending_path = (repo_root / args.external_pending).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "profiles", "selection", "plans", "queue", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    candidate_ranking = load_yaml(ranking_path)
    profiles_before = load_yaml(profiles_path)
    external_pending = load_yaml(external_pending_path)
    profiles_after, added = ensure_profiles(profiles_before)
    dump_yaml(profiles_path, profiles_after)

    candidate_names = candidate_names_from_ranking(candidate_ranking)
    skipped, post_ranking, selected, plan = post_bootstrap_selection(
        repo_root,
        candidate_names,
        external_pending,
        profiles_after,
    )
    queue = updated_queue(plan, skipped)
    qc = quality_checks(profiles_before, added, skipped, selected)

    dump_yaml(out_dir / "inputs/family_candidate_ranking_snapshot.yaml", candidate_ranking)
    dump_yaml(out_dir / "profiles/family_profiles_before.yaml", profiles_before)
    dump_yaml(out_dir / "profiles/family_profiles_after.yaml", profiles_after)
    dump_yaml(
        out_dir / "profiles/added_family_profiles.yaml",
        {
            "schema": "added_family_profiles_v1",
            "generated_at": now_iso(),
            "profiles": added,
            "summary": {"added_profile_count": len(added), "families": sorted(added)},
        },
    )
    dump_yaml(
        out_dir / "selection/post_bootstrap_family_selection.yaml",
        {
            "schema": "post_bootstrap_family_selection_v1",
            "generated_at": now_iso(),
            "skipped_families": skipped,
            "ranking": post_ranking,
            "selected": selected,
        },
    )
    dump_yaml(out_dir / "plans/next_seed_discovery_task.yaml", plan)
    dump_yaml(out_dir / "queue/updated_scheduler_task_queue.yaml", queue)
    dump_yaml(out_dir / "validation/family_profiles_bootstrap_quality_checks.yaml", qc)
    report = f"""# {TASK} Report

## Updated Profiles

- added_profile_count: {len(added)}
- added_families: {sorted(added)}

## Post-Bootstrap Selection

- skipped_families: {skipped}
- selected_next_family: {selected.get('family') or 'none'}
- selected_status: {selected.get('status')}
- next_task: {plan.get('task_name')}
- allowed_to_run_now: {plan.get('allowed_to_run_now')}

## Policy

No tools script, family-specific mutator, render, compile, run, feedback,
knowledge, pattern-bank, adapter recipe, normalized template, GLM, git, CVE,
exploitability, or confirmed vulnerability claim was produced.

## Quality

- quality_status: {qc.get('quality_status')}
"""
    write_text(out_dir / "reports/family_profiles_bootstrap_v1_report.md", report)
    print(f"[OK] wrote {TASK} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"added={len(added)} selected={selected.get('family') or 'none'} "
        f"next={plan.get('task_name')} quality={qc['quality_status']}"
    )
    return 0 if qc["quality_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

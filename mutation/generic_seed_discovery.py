"""Generic seed discovery and validation driven by family profiles."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text


TASK = "pkey_parsing_seed_discovery_v1"
ASAN_OPENSSL = Path("/home/wen/work/install-openssl-3.5.5-asan/bin/openssl")
FALLBACK_OPENSSL = Path("/usr/bin/openssl")
SEARCH_ROOTS = [
    "artifacts",
    "datasets",
    "data",
    "tests",
    "testdata",
    "corpus",
    "seeds",
]
DEFAULT_KEYWORDS = ["key", "pkey", "private", "public", "rsa", "ec", "ed25519", "pem", "der"]
MAX_CANDIDATES = 200
MAX_SEED_BYTES = 2 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--family", required=True)
    parser.add_argument("--family-profiles", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def run_command(argv: list[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return {
            "argv": argv,
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": argv,
            "return_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "validation command timed out",
            "timeout": True,
        }


def choose_openssl() -> dict[str, Any]:
    asan_available = False
    fallback_reason = ""
    if ASAN_OPENSSL.exists() and ASAN_OPENSSL.is_file():
        probe = run_command([str(ASAN_OPENSSL), "version"])
        if probe["return_code"] == 0:
            version = (probe.get("stdout") or "").strip()
            return {
                "openssl_path": str(ASAN_OPENSSL),
                "openssl_version": version,
                "asan_openssl_available": True,
                "fallback_reason": "",
                "probe": probe,
            }
        fallback_reason = (probe.get("stderr") or probe.get("stdout") or "ASAN OpenSSL probe failed").strip()
    else:
        fallback_reason = f"{ASAN_OPENSSL} is not executable"

    probe = run_command([str(FALLBACK_OPENSSL), "version"])
    version = (probe.get("stdout") or "").strip() if probe["return_code"] == 0 else ""
    return {
        "openssl_path": str(FALLBACK_OPENSSL),
        "openssl_version": version,
        "asan_openssl_available": asan_available,
        "fallback_reason": fallback_reason,
        "probe": probe,
    }


def family_profile(profiles: dict[str, Any], family: str) -> dict[str, Any]:
    return (profiles.get("families") or {}).get(family, {}) or {}


def candidate_extensions(profile: dict[str, Any]) -> list[str]:
    seed_discovery = profile.get("seed_discovery") or {}
    exts = seed_discovery.get("candidate_extensions") or []
    return [str(ext).lower() for ext in exts]


def seed_keywords(profile: dict[str, Any]) -> list[str]:
    seed_discovery = profile.get("seed_discovery") or {}
    keywords = list(seed_discovery.get("seed_keywords") or []) + DEFAULT_KEYWORDS
    seen: list[str] = []
    for item in keywords:
        lowered = str(item).lower()
        if lowered not in seen:
            seen.append(lowered)
    return seen


def infer_format(path: Path) -> str:
    try:
        prefix = path.read_bytes()[:128]
    except OSError:
        return "unknown"
    if b"-----BEGIN" in prefix:
        return "pem"
    if path.suffix.lower() == ".pem":
        return "pem"
    return "der"


def score_candidate(path: Path, repo_root: Path, keywords: list[str]) -> int:
    rel = path.relative_to(repo_root).as_posix().lower()
    score = 0
    for keyword in keywords:
        if keyword in rel:
            score += 3
    if "baseline_valid" in rel:
        score += 8
    if "valid" in rel:
        score += 4
    if "malformed" in rel or "trailing" in rel or "mutated" in rel:
        score -= 6
    if "pubkey" in rel or "pkcs8" in rel or "pkey" in rel:
        score += 8
    return score


def discover_candidates(repo_root: Path, profile: dict[str, Any]) -> list[dict[str, Any]]:
    exts = set(candidate_extensions(profile))
    keywords = seed_keywords(profile)
    candidates: list[dict[str, Any]] = []
    for root_name in SEARCH_ROOTS:
        root = repo_root / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix not in exts:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= 0 or size > MAX_SEED_BYTES:
                continue
            rel = path.relative_to(repo_root).as_posix()
            score = score_candidate(path, repo_root, keywords)
            if score <= 0:
                continue
            candidates.append(
                {
                    "source_path": rel,
                    "suffix": suffix,
                    "size_bytes": size,
                    "format": infer_format(path),
                    "score": score,
                    "matched_keywords": [k for k in keywords if k in rel.lower()],
                }
            )
    candidates.sort(key=lambda item: (-int(item["score"]), item["source_path"]))
    return candidates[:MAX_CANDIDATES]


def validation_commands(openssl_path: str, candidate_path: Path, fmt: str) -> list[list[str]]:
    file_arg = str(candidate_path)
    if fmt == "pem":
        return [
            [openssl_path, "pkey", "-in", file_arg, "-noout"],
            [openssl_path, "pkey", "-pubin", "-in", file_arg, "-noout"],
            [openssl_path, "pkey", "-inform", "DER", "-in", file_arg, "-noout"],
            [openssl_path, "pkey", "-pubin", "-inform", "DER", "-in", file_arg, "-noout"],
        ]
    return [
        [openssl_path, "pkey", "-inform", "DER", "-in", file_arg, "-noout"],
        [openssl_path, "pkey", "-pubin", "-inform", "DER", "-in", file_arg, "-noout"],
        [openssl_path, "pkey", "-in", file_arg, "-noout"],
        [openssl_path, "pkey", "-pubin", "-in", file_arg, "-noout"],
    ]


def validate_candidates(
    repo_root: Path,
    out_dir: Path,
    candidates: list[dict[str, Any]],
    openssl_info: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    seeds_dir = out_dir / "verified_seeds"
    seeds_dir.mkdir(parents=True, exist_ok=True)
    openssl_path = str(openssl_info["openssl_path"])
    for index, candidate in enumerate(candidates, start=1):
        source = repo_root / candidate["source_path"]
        attempts = []
        first_success: dict[str, Any] | None = None
        for argv in validation_commands(openssl_path, source, str(candidate["format"])):
            result = run_command(argv)
            attempts.append(result)
            if result["return_code"] == 0 and first_success is None:
                first_success = result
        validation = {
            **candidate,
            "validation_attempts": attempts,
            "verified": first_success is not None,
        }
        results.append(validation)
        if first_success is None:
            continue
        seed_id = f"pkey_seed_{len(verified) + 1:04d}"
        copied_path = seeds_dir / f"{seed_id}{source.suffix.lower() or '.seed'}"
        shutil.copy2(source, copied_path)
        verified.append(
            {
                "seed_id": seed_id,
                "source_path": candidate["source_path"],
                "copied_path": copied_path.relative_to(repo_root).as_posix(),
                "format": candidate["format"],
                "validation_command": " ".join(first_success["argv"]),
                "validation_return_code": first_success["return_code"],
                "openssl_path": openssl_info["openssl_path"],
                "openssl_version": openssl_info["openssl_version"],
            }
        )
    return results, verified


def manifest(family: str, verified: list[dict[str, Any]]) -> dict[str, Any]:
    if verified:
        return {
            "schema": "verified_seed_manifest_v1",
            "family": family,
            "seed_ready": True,
            "verified_seed_count": len(verified),
            "verified_seeds": verified,
            "next_stage": "mutation_planner",
        }
    return {
        "schema": "verified_seed_manifest_v1",
        "family": family,
        "seed_ready": False,
        "verified_seed_count": 0,
        "verified_seeds": [],
        "blocked_by": "missing_valid_seed",
        "next_stage": "seed_discovery_retry",
    }


def next_plan(family: str, seed_manifest: dict[str, Any]) -> dict[str, Any]:
    if seed_manifest.get("seed_ready"):
        return {
            "schema": "next_execution_plan_v1",
            "generated_at": now_iso(),
            "family": family,
            "next_stage": "mutation_planner",
            "task_name": f"{family}_generic_mutation_plan_v1",
            "allowed_to_run_now": True,
            "required_inputs": ["manifests/verified_pkey_seed_manifest.yaml", "config/family_profiles.yaml"],
            "blocked_by": [],
        }
    return {
        "schema": "next_execution_plan_v1",
        "generated_at": now_iso(),
        "family": family,
        "next_stage": "seed_discovery_retry",
        "task_name": f"{family}_seed_discovery_retry_v1",
        "allowed_to_run_now": False,
        "required_inputs": ["config/family_profiles.yaml"],
        "blocked_by": ["missing_valid_seed"],
    }


def quality_checks(
    family: str,
    profile: dict[str, Any],
    candidates: list[dict[str, Any]],
    verified: list[dict[str, Any]],
    seed_manifest: dict[str, Any],
) -> dict[str, Any]:
    seed_ready = bool(seed_manifest.get("seed_ready"))
    return {
        "schema": "pkey_seed_discovery_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "generic_seed_discovery_used": True,
        "family_specific_seed_discovery_created": False,
        "family_profile_loaded": bool(profile),
        "pkey_selected": family == "pkey_parsing",
        "candidate_seeds_found": len(candidates),
        "verified_seed_count": len(verified),
        "seed_manifest_generated": True,
        "seed_ready": seed_ready,
        "next_stage_mutation_planner_ready": seed_ready,
        "render_executed": False,
        "compile_fuzz_harness_executed": False,
        "run_fuzz_harness_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass" if seed_ready else "blocked_missing_seed",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "discovery", "validation", "manifests", "plans", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    profiles = load_yaml((repo_root / args.family_profiles).resolve())
    profile = family_profile(profiles, args.family)
    openssl_info = choose_openssl()
    candidates = discover_candidates(repo_root, profile) if profile else []
    validation_results, verified = validate_candidates(repo_root, out_dir, candidates, openssl_info)
    seed_manifest = manifest(args.family, verified)
    plan = next_plan(args.family, seed_manifest)
    qc = quality_checks(args.family, profile, candidates, verified, seed_manifest)

    dump_yaml(
        out_dir / "inputs/family_profile_snapshot.yaml",
        {
            "schema": "family_profile_snapshot_v1",
            "generated_at": now_iso(),
            "family": args.family,
            "profile": profile,
        },
    )
    dump_yaml(
        out_dir / "discovery/candidate_seed_index.yaml",
        {
            "schema": "candidate_seed_index_v1",
            "generated_at": now_iso(),
            "family": args.family,
            "candidate_count": len(candidates),
            "candidates": candidates,
        },
    )
    dump_yaml(
        out_dir / "validation/seed_validation_results.yaml",
        {
            "schema": "seed_validation_results_v1",
            "generated_at": now_iso(),
            "family": args.family,
            "openssl": openssl_info,
            "candidate_count": len(candidates),
            "verified_seed_count": len(verified),
            "results": validation_results,
        },
    )
    dump_yaml(out_dir / "manifests/verified_pkey_seed_manifest.yaml", seed_manifest)
    dump_yaml(out_dir / "plans/next_execution_plan.yaml", plan)
    dump_yaml(out_dir / "validation/pkey_seed_discovery_quality_checks.yaml", qc)
    seed_formats = sorted({seed.get("format", "unknown") for seed in verified})
    report = f"""# {TASK} Report

## Seed Discovery

- family: {args.family}
- candidate_seeds_found: {len(candidates)}
- verified_seed_count: {len(verified)}
- seed_ready: {seed_manifest.get('seed_ready')}
- seed_formats: {seed_formats}

## OpenSSL

- openssl_path: {openssl_info.get('openssl_path')}
- openssl_version: {openssl_info.get('openssl_version')}
- asan_openssl_available: {openssl_info.get('asan_openssl_available')}
- fallback_reason: {openssl_info.get('fallback_reason')}

## Next Stage

- next_stage: {plan.get('next_stage')}
- task_name: {plan.get('task_name')}
- allowed_to_run_now: {plan.get('allowed_to_run_now')}
- blocked_by: {plan.get('blocked_by')}

## Policy

No tools script, family-specific seed discovery script, family-specific mutator,
fuzz harness render, fuzz harness compile, fuzz harness run, feedback, knowledge,
pattern-bank, adapter recipe, normalized template, GLM, git, CVE, exploitability,
or confirmed vulnerability claim was produced.

## Quality

- quality_status: {qc.get('quality_status')}
"""
    write_text(out_dir / "reports/pkey_parsing_seed_discovery_v1_report.md", report)
    print(f"[OK] wrote generic seed discovery artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"family={args.family} candidates={len(candidates)} verified={len(verified)} "
        f"seed_ready={seed_manifest.get('seed_ready')} quality={qc['quality_status']}"
    )
    return 0 if qc["quality_status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())

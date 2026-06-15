"""Discover verified X.509 seeds for valid-prefix mutation planning.

This is a seed/readiness step only. It validates existing corpus candidates
with the OpenSSL CLI and generates a synthetic self-signed certificate only
when DER/PEM coverage is insufficient. It does not render, compile, run fuzz
harnesses, write feedback, mutate knowledge, or claim vulnerabilities.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


TASK = "x509_family_template_seed_discovery_v1"
PREFERRED_OPENSSL = Path("/home/wen/work/install-openssl-3.5.5-asan/bin/openssl")
SCAN_ROOTS = ["data", "datasets", "pocs", "artifacts/sprints"]
SUFFIXES = {".der", ".pem", ".crt", ".cer", ".cert"}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: list[str], timeout: int = 30) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout,
        )
        return {
            "command": cmd,
            "return_code": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": cmd,
            "return_code": 124,
            "stdout": exc.stdout[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr": exc.stderr[-4000:] if isinstance(exc.stderr, str) else "",
            "timeout": True,
        }


def resolve_openssl() -> dict[str, Any]:
    attempts = []
    if PREFERRED_OPENSSL.exists():
        result = run_cmd([str(PREFERRED_OPENSSL), "version"], timeout=10)
        attempts.append({"path": str(PREFERRED_OPENSSL), **result})
        if result["return_code"] == 0:
            return {"available": True, "path": str(PREFERRED_OPENSSL), "version": result["stdout"].strip(), "attempts": attempts}
    fallback = shutil.which("openssl") or "/usr/bin/openssl"
    if Path(fallback).exists():
        result = run_cmd([fallback, "version"], timeout=10)
        attempts.append({"path": fallback, **result})
        if result["return_code"] == 0:
            return {"available": True, "path": fallback, "version": result["stdout"].strip(), "attempts": attempts}
    return {"available": False, "path": "", "version": "", "attempts": attempts}


def scheduler_decision(repo_root: Path, scheduler_queue: Path) -> dict[str, Any]:
    queue = load_yaml(scheduler_queue)
    selected = None
    for task in queue.get("tasks", []) or []:
        if task.get("task_name") == TASK:
            selected = task
            break
    return {
        "schema": "x509_seed_scheduler_decision_trace_v1",
        "generated_at": now_iso(),
        "scheduler_queue": scheduler_queue.relative_to(repo_root).as_posix()
        if scheduler_queue.is_absolute() and scheduler_queue.is_relative_to(repo_root)
        else scheduler_queue.as_posix(),
        "scheduler_queue_loaded": bool(queue),
        "scheduler_selected_task": TASK,
        "task_record": selected,
        "allowed_to_run_now": bool(selected and selected.get("status") == "ready" and selected.get("allowed_to_run_now") is True),
        "selection_reason": (selected or {}).get("reason", ""),
    }


def candidate_reason(path: Path) -> str:
    text = path.as_posix().lower()
    if any(token in text for token in ("x509", "cert", "certificate", "crt")):
        return "x509_cert_path_hint"
    if path.suffix.lower() in {".crt", ".cer", ".cert"}:
        return "certificate_suffix"
    return "generic_der_or_pem"


def discover_candidates(repo_root: Path) -> list[dict[str, Any]]:
    candidates = []
    seen: set[Path] = set()
    for root_name in SCAN_ROOTS:
        root = repo_root / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in SUFFIXES:
                continue
            if path in seen:
                continue
            seen.add(path)
            candidates.append(
                {
                    "path": path.relative_to(repo_root).as_posix(),
                    "suffix": path.suffix.lower(),
                    "candidate_reason": candidate_reason(path),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return candidates


def validate_x509(openssl: str, path: Path, fmt: str) -> dict[str, Any]:
    return run_cmd([openssl, "x509", "-inform", fmt.upper(), "-in", str(path), "-noout"], timeout=30)


def make_seed_record(
    seed_id: str,
    path: Path,
    repo_root: Path,
    fmt: str,
    origin: str,
    validation: dict[str, Any],
    notes: list[str],
) -> dict[str, Any]:
    return {
        "seed_id": seed_id,
        "family": "x509_parsing",
        "path": path.relative_to(repo_root).as_posix(),
        "format": fmt,
        "origin": origin,
        "openssl_command": " ".join(str(x) for x in validation.get("command", [])),
        "return_code": validation.get("return_code"),
        "parser_valid": validation.get("return_code") == 0,
        "usable_for_valid_prefix_mutation": validation.get("return_code") == 0,
        "usable_for_trailing_garbage_oracle": validation.get("return_code") == 0,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "notes": notes,
    }


def validate_candidate(openssl: str, repo_root: Path, candidate: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    path = repo_root / candidate["path"]
    suffix = path.suffix.lower()
    formats = ["PEM"] if suffix in {".pem", ".crt", ".cert"} else ["DER", "PEM"]
    attempts = []
    for fmt in formats:
        result = validate_x509(openssl, path, fmt)
        attempts.append({"format": fmt.lower(), **result})
        if result["return_code"] == 0:
            seed = make_seed_record(
                f"existing_x509_{fmt.lower()}_{candidate['sha256'][:8]}",
                path,
                repo_root,
                fmt.lower(),
                "existing_corpus",
                result,
                [f"validated with openssl x509 -inform {fmt.upper()} -noout"],
            )
            return {**candidate, "validated": True, "attempts": attempts, "verified_seed_id": seed["seed_id"]}, seed
    return {**candidate, "validated": False, "attempts": attempts, "verified_seed_id": ""}, None


def generate_synthetic(openssl: str, out_dir: Path, repo_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    seeds_dir = out_dir / "verified_seeds"
    materials = seeds_dir / "_generated_materials"
    materials.mkdir(parents=True, exist_ok=True)
    key = materials / "x509_seed_key.pem"
    pem = seeds_dir / "x509_valid_selfsigned.pem"
    der = seeds_dir / "x509_valid_selfsigned.der"
    commands = []
    seeds = []

    req = run_cmd(
        [
            openssl,
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-x509",
            "-days",
            "1",
            "-subj",
            "/CN=crypto-pattern-fuzz-x509-seed",
            "-out",
            str(pem),
        ],
        timeout=60,
    )
    commands.append({"purpose": "generate_self_signed_pem", **req})
    if req["return_code"] == 0:
        pem_validation = validate_x509(openssl, pem, "PEM")
        commands.append({"purpose": "validate_synthetic_pem", **pem_validation})
        if pem_validation["return_code"] == 0:
            seeds.append(
                make_seed_record(
                    "synthetic_x509_valid_selfsigned_pem",
                    pem,
                    repo_root,
                    "pem",
                    "synthetic_openssl_generated",
                    pem_validation,
                    ["generated locally with OpenSSL self-signed certificate"],
                )
            )
        convert = run_cmd(
            [openssl, "x509", "-in", str(pem), "-outform", "DER", "-out", str(der)],
            timeout=30,
        )
        commands.append({"purpose": "convert_pem_to_der", **convert})
        if convert["return_code"] == 0:
            der_validation = validate_x509(openssl, der, "DER")
            commands.append({"purpose": "validate_synthetic_der", **der_validation})
            if der_validation["return_code"] == 0:
                seeds.append(
                    make_seed_record(
                        "synthetic_x509_valid_selfsigned_der",
                        der,
                        repo_root,
                        "der",
                        "synthetic_openssl_generated",
                        der_validation,
                        ["generated locally with OpenSSL self-signed certificate and converted to DER"],
                    )
                )
    return seeds, commands


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--scheduler-queue", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--max-validate", type=int, default=500)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    scheduler_queue = (repo_root / args.scheduler_queue).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("scheduler", "inventory", "validation", "verified_seeds", "manifests", "plans", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    decision = scheduler_decision(repo_root, scheduler_queue)
    dump_yaml(out_dir / "scheduler" / "scheduler_decision_trace.yaml", decision)
    openssl_info = resolve_openssl()
    candidates = discover_candidates(repo_root)
    high_signal = [c for c in candidates if c["candidate_reason"] != "generic_der_or_pem"]
    generic = [c for c in candidates if c["candidate_reason"] == "generic_der_or_pem"]
    selected = (high_signal + generic)[: max(0, args.max_validate)]

    validations = []
    verified = []
    synthetic_commands = []
    if decision["allowed_to_run_now"] and openssl_info["available"]:
        for candidate in selected:
            validation, seed = validate_candidate(openssl_info["path"], repo_root, candidate)
            validations.append(validation)
            if seed:
                if seed["format"] not in {s["format"] for s in verified}:
                    verified.append(seed)
            if {s["format"] for s in verified} >= {"der", "pem"}:
                break
        if not ({s["format"] for s in verified} >= {"der", "pem"}):
            synthetic, synthetic_commands = generate_synthetic(openssl_info["path"], out_dir, repo_root)
            existing_formats = {s["format"] for s in verified}
            for seed in synthetic:
                if seed["format"] not in existing_formats:
                    verified.append(seed)
                    existing_formats.add(seed["format"])

    inventory = {
        "schema": "x509_seed_candidate_inventory_v1",
        "generated_at": now_iso(),
        "scan_roots": SCAN_ROOTS,
        "candidate_count": len(candidates),
        "selected_for_validation": len(selected),
        "openssl": openssl_info,
        "candidates": candidates,
        "selection_policy": {"high_signal_first": True, "stop_after_der_and_pem_verified": True},
    }
    dump_yaml(out_dir / "inventory" / "x509_seed_candidate_inventory.yaml", inventory)

    validation_report = {
        "schema": "x509_seed_validation_report_v1",
        "generated_at": now_iso(),
        "openssl": openssl_info,
        "scheduler_allowed_to_run_now": decision["allowed_to_run_now"],
        "candidate_validations": validations,
        "synthetic_generation": {
            "attempted": bool(synthetic_commands),
            "commands": synthetic_commands,
        },
        "summary": {
            "candidate_count": len(candidates),
            "validated_candidate_count": len(validations),
            "verified_seed_count": len(verified),
            "der_seed_verified": any(s["format"] == "der" for s in verified),
            "pem_seed_verified": any(s["format"] == "pem" for s in verified),
            "synthetic_seed_generated": any(s["origin"] == "synthetic_openssl_generated" for s in verified),
        },
    }
    dump_yaml(out_dir / "validation" / "x509_seed_validation_report.yaml", validation_report)

    manifest = {
        "schema": "verified_x509_seed_manifest_v1",
        "generated_at": now_iso(),
        "seeds": verified,
        "summary": validation_report["summary"],
    }
    dump_yaml(out_dir / "manifests" / "verified_x509_seed_manifest.yaml", manifest)

    der_ready = any(s["format"] == "der" and s["parser_valid"] for s in verified)
    pem_ready = any(s["format"] == "pem" and s["parser_valid"] for s in verified)
    can_start = bool(der_ready or pem_ready)
    plan = {
        "schema": "x509_template_seed_readiness_plan_v1",
        "generated_at": now_iso(),
        "family": "x509_parsing",
        "verified_der_seed_ready": der_ready,
        "verified_pem_seed_ready": pem_ready,
        "malformed_only_control_seed_available": bool(candidates and not can_start),
        "can_start_valid_prefix_mutation": can_start,
        "recommended_next_task": "x509_valid_prefix_mutation_plan_v1" if can_start else "x509_seed_discovery_fixup_v1",
        "blocked_by": [] if can_start else ["missing_verified_x509_seed"],
    }
    dump_yaml(out_dir / "plans" / "x509_template_seed_readiness_plan.yaml", plan)

    qc = {
        "schema": "x509_seed_discovery_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "scheduler_queue_loaded": decision["scheduler_queue_loaded"],
        "scheduler_selected_task": TASK,
        "allowed_to_run_now": decision["allowed_to_run_now"],
        "candidate_inventory_generated": True,
        "verified_seed_manifest_generated": True,
        "verified_seed_count": len(verified),
        "der_seed_verified": der_ready,
        "pem_seed_verified": pem_ready,
        "synthetic_seed_generated": any(s["origin"] == "synthetic_openssl_generated" for s in verified),
        "readiness_plan_generated": True,
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
        "quality_status": "pass"
        if decision["allowed_to_run_now"]
        and len(verified) > 0
        and (der_ready or pem_ready)
        else "blocked",
    }
    dump_yaml(out_dir / "validation" / "x509_seed_discovery_quality_checks.yaml", qc)

    report = f"""# {TASK} Report

## Summary

- quality_status: {qc['quality_status']}
- scheduler_selected_task: {TASK}
- allowed_to_run_now: {decision['allowed_to_run_now']}
- openssl_path: `{openssl_info.get('path', '')}`
- openssl_version: `{openssl_info.get('version', '')}`
- candidate seeds found: {len(candidates)}
- verified seeds: {len(verified)}
- DER seed verified: {der_ready}
- PEM seed verified: {pem_ready}
- synthetic seed generated: {qc['synthetic_seed_generated']}

## Readiness

- can_start_valid_prefix_mutation: {plan['can_start_valid_prefix_mutation']}
- recommended_next_task: `{plan['recommended_next_task']}`
- blocked_by: {plan['blocked_by']}

## Policy

No render, compile, run, feedback, knowledge, pattern-bank, adapter recipe,
normalized template, GLM, git, CVE, exploitability, or confirmed vulnerability
claim was produced.
"""
    (out_dir / "reports" / f"{TASK}_report.md").write_text(report, encoding="utf-8")

    print(f"[OK] wrote {TASK} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"candidates={len(candidates)} verified={len(verified)} der={der_ready} pem={pem_ready} "
        f"synthetic={qc['synthetic_seed_generated']} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

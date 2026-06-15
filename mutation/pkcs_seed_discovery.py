"""Discover or generate verified PKCS seeds for valid-prefix mutation.

This module scans local corpora for PKCS12/PKCS7/CMS-like inputs, validates
them with OpenSSL CLI parsers, and generates synthetic OpenSSL-backed seeds
when no usable corpus seed is available. It does not render harnesses, compile
harnesses, run fuzz targets, write feedback, or update knowledge/pattern-bank
state.
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


PREFERRED_OPENSSL = Path("/home/wen/work/install-openssl-3.5.5-asan/bin/openssl")
SCAN_ROOTS = ["data", "datasets", "pocs", "artifacts"]
PKCS12_SUFFIXES = {".p12", ".pfx"}
PKCS7_SUFFIXES = {".p7b", ".p7c", ".pkcs7"}
GENERAL_SUFFIXES = {".der", ".pem"}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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
            timeout=timeout,
            check=False,
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
            "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
            "timeout": True,
        }


def resolve_openssl() -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    if PREFERRED_OPENSSL.exists() and PREFERRED_OPENSSL.is_file():
        result = run_cmd([str(PREFERRED_OPENSSL), "version"], timeout=10)
        attempts.append({"path": str(PREFERRED_OPENSSL), **result})
        if result["return_code"] == 0:
            return {"available": True, "path": str(PREFERRED_OPENSSL), "attempts": attempts}

    fallback = shutil.which("openssl")
    if fallback:
        result = run_cmd([fallback, "version"], timeout=10)
        attempts.append({"path": fallback, **result})
        if result["return_code"] == 0:
            return {"available": True, "path": fallback, "attempts": attempts}

    return {"available": False, "path": "", "attempts": attempts}


def candidate_type(path: Path) -> tuple[str, str]:
    suffix = path.suffix.lower()
    lower = path.as_posix().lower()
    if suffix in PKCS12_SUFFIXES:
        return "pkcs12", "pkcs12_suffix"
    if suffix in PKCS7_SUFFIXES:
        return "pkcs7", "pkcs7_suffix"
    if suffix in GENERAL_SUFFIXES and any(token in lower for token in ("pkcs", "p7", "cms", "certbag")):
        return "pkcs7_or_cms", "pkcs_related_path_hint"
    if suffix in GENERAL_SUFFIXES:
        return "generic_der_or_pem", "generic_der_or_pem_suffix"
    return "unknown", "unknown"


def discover_candidates(repo_root: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[Path] = set()
    suffixes = PKCS12_SUFFIXES | PKCS7_SUFFIXES | GENERAL_SUFFIXES
    for root_name in SCAN_ROOTS:
        root = repo_root / root_name
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            if path in seen:
                continue
            seen.add(path)
            ctype, reason = candidate_type(path)
            candidates.append(
                {
                    "path": path.relative_to(repo_root).as_posix(),
                    "suffix": path.suffix.lower(),
                    "candidate_type": ctype,
                    "candidate_reason": reason,
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return candidates


def validate_pkcs12(openssl: str, path: Path) -> dict[str, Any]:
    return run_cmd([openssl, "pkcs12", "-in", str(path), "-noout", "-passin", "pass:"], timeout=30)


def validate_pkcs7(openssl: str, path: Path, inform: str) -> dict[str, Any]:
    return run_cmd([openssl, "pkcs7", "-inform", inform, "-in", str(path), "-noout"], timeout=30)


def validate_cms(openssl: str, path: Path, inform: str) -> dict[str, Any]:
    return run_cmd([openssl, "cms", "-cmsout", "-inform", inform, "-in", str(path), "-noout"], timeout=30)


def make_seed_record(
    seed_id: str,
    container_type: str,
    path: Path,
    repo_root: Path,
    origin: str,
    validation: dict[str, Any],
    notes: list[str],
) -> dict[str, Any]:
    command = " ".join(str(x) for x in validation.get("command", []))
    return {
        "seed_id": seed_id,
        "family": "pkcs_container_parsing",
        "container_type": container_type,
        "path": path.relative_to(repo_root).as_posix(),
        "origin": origin,
        "openssl_command": command,
        "return_code": validation.get("return_code"),
        "parser_valid": validation.get("return_code") == 0,
        "full_consumption_relevant": True,
        "usable_for_valid_prefix_mutation": validation.get("return_code") == 0,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "notes": notes,
    }


def validate_candidate(openssl: str, repo_root: Path, candidate: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    path = repo_root / candidate["path"]
    suffix = path.suffix.lower()
    attempts: list[dict[str, Any]] = []
    verified: dict[str, Any] | None = None

    if suffix in PKCS12_SUFFIXES:
        result = validate_pkcs12(openssl, path)
        attempts.append({"parser": "pkcs12", **result})
        if result["return_code"] == 0:
            verified = make_seed_record(
                f"existing_pkcs12_{len(candidate['sha256'][:8])}_{candidate['sha256'][:8]}",
                "pkcs12",
                path,
                repo_root,
                "existing_corpus",
                result,
                ["validated with openssl pkcs12 -noout"],
            )
    else:
        formats = ["PEM"] if suffix == ".pem" else ["DER", "PEM"]
        for inform in formats:
            result = validate_pkcs7(openssl, path, inform)
            attempts.append({"parser": "pkcs7", "inform": inform, **result})
            if result["return_code"] == 0:
                verified = make_seed_record(
                    f"existing_pkcs7_{candidate['sha256'][:8]}",
                    "pkcs7",
                    path,
                    repo_root,
                    "existing_corpus",
                    result,
                    [f"validated with openssl pkcs7 -inform {inform} -noout"],
                )
                break
            cms_result = validate_cms(openssl, path, inform)
            attempts.append({"parser": "cms", "inform": inform, **cms_result})
            if cms_result["return_code"] == 0:
                verified = make_seed_record(
                    f"existing_cms_{candidate['sha256'][:8]}",
                    "cms",
                    path,
                    repo_root,
                    "existing_corpus",
                    cms_result,
                    [f"validated with openssl cms -cmsout -inform {inform} -noout"],
                )
                break

    validation = {
        **candidate,
        "validated": verified is not None,
        "attempts": attempts,
        "verified_seed_id": verified.get("seed_id") if verified else "",
    }
    return validation, verified


def generate_synthetic(openssl: str, out_dir: Path, repo_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    seeds_dir = out_dir / "verified_seeds"
    materials = seeds_dir / "_generated_materials"
    materials.mkdir(parents=True, exist_ok=True)
    seeds: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []

    key = materials / "pkcs_seed_key.pem"
    cert = materials / "pkcs_seed_cert.pem"
    pkcs12 = seeds_dir / "pkcs12_valid_minimal.p12"
    pkcs7 = seeds_dir / "pkcs7_valid_certbag.der"

    cmd = [
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
        "/CN=crypto-pattern-fuzz-pkcs-seed",
        "-out",
        str(cert),
    ]
    req_result = run_cmd(cmd, timeout=60)
    commands.append({"purpose": "generate_self_signed_cert", **req_result})
    if req_result["return_code"] != 0:
        return seeds, commands

    pkcs12_result = run_cmd(
        [
            openssl,
            "pkcs12",
            "-export",
            "-inkey",
            str(key),
            "-in",
            str(cert),
            "-out",
            str(pkcs12),
            "-passout",
            "pass:",
        ],
        timeout=60,
    )
    commands.append({"purpose": "generate_pkcs12", **pkcs12_result})
    if pkcs12_result["return_code"] == 0:
        validation = validate_pkcs12(openssl, pkcs12)
        commands.append({"purpose": "validate_synthetic_pkcs12", **validation})
        if validation["return_code"] == 0:
            seeds.append(
                make_seed_record(
                    "synthetic_pkcs12_valid_minimal",
                    "pkcs12",
                    pkcs12,
                    repo_root,
                    "synthetic_openssl_generated",
                    validation,
                    ["generated locally with OpenSSL from a self-signed certificate"],
                )
            )

    pkcs7_result = run_cmd(
        [
            openssl,
            "crl2pkcs7",
            "-nocrl",
            "-certfile",
            str(cert),
            "-outform",
            "DER",
            "-out",
            str(pkcs7),
        ],
        timeout=60,
    )
    commands.append({"purpose": "generate_pkcs7", **pkcs7_result})
    if pkcs7_result["return_code"] == 0:
        validation = validate_pkcs7(openssl, pkcs7, "DER")
        commands.append({"purpose": "validate_synthetic_pkcs7", **validation})
        if validation["return_code"] == 0:
            seeds.append(
                make_seed_record(
                    "synthetic_pkcs7_valid_certbag",
                    "pkcs7",
                    pkcs7,
                    repo_root,
                    "synthetic_openssl_generated",
                    validation,
                    ["generated locally with OpenSSL crl2pkcs7 from a self-signed certificate"],
                )
            )

    return seeds, commands


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--max-validate", type=int, default=400)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "inventory").mkdir(exist_ok=True)
    (out_dir / "validation").mkdir(exist_ok=True)
    (out_dir / "verified_seeds").mkdir(exist_ok=True)
    (out_dir / "manifests").mkdir(exist_ok=True)
    (out_dir / "plans").mkdir(exist_ok=True)
    (out_dir / "reports").mkdir(exist_ok=True)

    openssl_info = resolve_openssl()
    candidates = discover_candidates(repo_root)
    high_signal = [
        c
        for c in candidates
        if c["candidate_type"] in {"pkcs12", "pkcs7", "pkcs7_or_cms"}
        or any(token in c["path"].lower() for token in ("pkcs", "p7", "cms"))
    ]
    generic = [c for c in candidates if c not in high_signal]
    selected = (high_signal + generic)[: max(0, args.max_validate)]

    validations: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    synthetic_commands: list[dict[str, Any]] = []
    blocked_reason = ""

    if openssl_info["available"]:
        openssl = openssl_info["path"]
        for candidate in selected:
            validation, seed = validate_candidate(openssl, repo_root, candidate)
            validations.append(validation)
            if seed:
                verified.append(seed)
        if not any(s["container_type"] == "pkcs12" for s in verified) or not any(
            s["container_type"] in {"pkcs7", "cms"} for s in verified
        ):
            synthetic, synthetic_commands = generate_synthetic(openssl, out_dir, repo_root)
            existing_ids = {s["seed_id"] for s in verified}
            for seed in synthetic:
                if seed["seed_id"] not in existing_ids:
                    verified.append(seed)
    else:
        blocked_reason = "openssl unavailable"

    inventory = {
        "schema": "pkcs_seed_candidate_inventory_v1",
        "generated_at": now_iso(),
        "scan_roots": SCAN_ROOTS,
        "candidate_count": len(candidates),
        "validated_candidate_count": len(validations),
        "max_validate": args.max_validate,
        "openssl": openssl_info,
        "candidates": candidates,
        "selection_policy": {
            "high_signal_first": True,
            "generic_der_or_pem_included_until_max_validate": True,
        },
    }
    dump_yaml(out_dir / "inventory" / "pkcs_seed_candidate_inventory.yaml", inventory)

    validation_report = {
        "schema": "pkcs_seed_validation_report_v1",
        "generated_at": now_iso(),
        "openssl": openssl_info,
        "blocked_reason": blocked_reason,
        "candidate_validations": validations,
        "synthetic_generation": {
            "attempted": bool(openssl_info["available"]),
            "commands": synthetic_commands,
        },
        "summary": {
            "candidate_count": len(candidates),
            "validated_candidate_count": len(validations),
            "verified_seed_count": len(verified),
            "existing_verified_seed_count": len([s for s in verified if s["origin"] == "existing_corpus"]),
            "synthetic_verified_seed_count": len(
                [s for s in verified if s["origin"] == "synthetic_openssl_generated"]
            ),
        },
    }
    dump_yaml(out_dir / "validation" / "pkcs_seed_validation_report.yaml", validation_report)

    manifest = {
        "schema": "verified_pkcs_seed_manifest_v1",
        "generated_at": now_iso(),
        "seeds": verified,
        "summary": {
            "verified_seed_count": len(verified),
            "pkcs12_seed_verified": any(s["container_type"] == "pkcs12" for s in verified),
            "pkcs7_or_cms_seed_verified": any(s["container_type"] in {"pkcs7", "cms"} for s in verified),
            "origins": sorted({s["origin"] for s in verified}),
        },
    }
    dump_yaml(out_dir / "manifests" / "verified_pkcs_seed_manifest.yaml", manifest)

    can_unblock = (
        manifest["summary"]["pkcs12_seed_verified"] or manifest["summary"]["pkcs7_or_cms_seed_verified"]
    )
    unblock_plan = {
        "schema": "pkcs_pending_seed_unblock_plan_v1",
        "generated_at": now_iso(),
        "pending_seed_cases_before": 4,
        "verified_pkcs_seeds": [
            {
                "seed_id": s["seed_id"],
                "container_type": s["container_type"],
                "path": s["path"],
                "origin": s["origin"],
            }
            for s in verified
        ],
        "can_unblock_pending_cases": bool(can_unblock),
        "recommended_next_task": "pkcs_valid_prefix_pipeline_to_analyze_v1"
        if can_unblock
        else "valid_seed_discovery_pkcs_fixup_v1",
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
        "notes": [
            "Use verified seeds only; do not mark unvalidated corpus files as valid.",
            "Next step should exercise PKCS valid-prefix mutation, not claim a bug.",
        ],
    }
    dump_yaml(out_dir / "plans" / "pkcs_pending_seed_unblock_plan.yaml", unblock_plan)

    qc = {
        "schema": "valid_seed_discovery_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "openssl_available": bool(openssl_info["available"]),
        "candidate_inventory_generated": True,
        "verified_seed_manifest_generated": True,
        "verified_seed_count": len(verified),
        "pkcs12_seed_verified": manifest["summary"]["pkcs12_seed_verified"],
        "pkcs7_or_cms_seed_verified": manifest["summary"]["pkcs7_or_cms_seed_verified"],
        "pending_seed_unblock_plan_generated": True,
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
        if openssl_info["available"]
        and len(verified) > 0
        and manifest["summary"]["pkcs12_seed_verified"]
        and manifest["summary"]["pkcs7_or_cms_seed_verified"]
        else "blocked",
    }
    dump_yaml(out_dir / "validation" / "valid_seed_discovery_quality_checks.yaml", qc)

    report = f"""# valid_seed_discovery_pkcs_v1 Report

## Summary

- quality_status: {qc['quality_status']}
- openssl_available: {qc['openssl_available']}
- openssl_path: `{openssl_info.get('path', '')}`
- candidate seeds found: {len(candidates)}
- verified seeds: {len(verified)}
- PKCS12 verified: {qc['pkcs12_seed_verified']}
- PKCS7/CMS verified: {qc['pkcs7_or_cms_seed_verified']}
- synthetic seed generated: {bool([s for s in verified if s['origin'] == 'synthetic_openssl_generated'])}

## Unblock Plan

- pending_seed_cases_before: 4
- can_unblock: {unblock_plan['can_unblock_pending_cases']}
- recommended_next_task: `{unblock_plan['recommended_next_task']}`

## Safety

- core_logic_in_tools: false
- new_tools_script_created: false
- render_executed: false
- compile_executed: false
- run_executed: false
- feedback_written: false
- knowledge_modified: false
- pattern_bank_modified: false
- adapter_recipes_modified: false
- normalized_templates_modified: false
- glm_called: false
- git_add_commit_push: false
- confirmed_vulnerability_claim: false

This sprint only discovers and validates PKCS seed material. It does not claim a vulnerability.
"""
    (out_dir / "reports" / "valid_seed_discovery_pkcs_v1_report.md").write_text(
        report,
        encoding="utf-8",
    )

    print(f"[OK] wrote PKCS seed discovery artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"candidates={len(candidates)} verified={len(verified)} "
        f"pkcs12={qc['pkcs12_seed_verified']} pkcs7_or_cms={qc['pkcs7_or_cms_seed_verified']} "
        f"quality={qc['quality_status']}"
    )
    print(f"[NEXT] {unblock_plan['recommended_next_task']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

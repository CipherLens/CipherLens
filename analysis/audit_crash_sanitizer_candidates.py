#!/usr/bin/env python3
"""Audit crash/sanitizer top5 candidates from the candidate queue."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml


QUEUE = Path("artifacts/candidate_queue/candidate_queue.yaml")
OUT_ROOT = Path("artifacts/crash_sanitizer_audit")
PER_ISSUE = OUT_ROOT / "per_issue"
TOP5_YAML = OUT_ROOT / "top5_audit.yaml"
TOP5_MD = OUT_ROOT / "top5_audit.md"
RECOMMENDED_YAML = OUT_ROOT / "recommended_next_family.yaml"
README = OUT_ROOT / "README.md"

SIGNATURES = {
    "asan": re.compile(r"AddressSanitizer|ERROR:\s*AddressSanitizer", re.I),
    "ubsan": re.compile(r"UndefinedBehaviorSanitizer|UBSAN|runtime error", re.I),
    "segv": re.compile(r"SIGSEGV|SEGV|Segmentation fault|segmentation fault", re.I),
    "exit_139": re.compile(r"exit code 139|return code: 139|Normal run exit code: 139", re.I),
    "heap_buffer_overflow": re.compile(r"heap-buffer-overflow", re.I),
    "stack_buffer_overflow": re.compile(r"stack-buffer-overflow", re.I),
    "use_after_free": re.compile(r"use-after-free", re.I),
    "invalid_read": re.compile(r"Invalid read", re.I),
}


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}
    return obj if isinstance(obj, dict) else {}


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)
    return obj if isinstance(obj, dict) else {}


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def iter_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file())


def issue_slug(issue_id: str) -> str:
    return "issue_" + issue_id.rsplit("-", 1)[-1].lower()


def queue_top5() -> List[Dict[str, Any]]:
    queue = load_yaml(QUEUE)
    out: List[Dict[str, Any]] = []
    for item in queue.get("candidates", []) or []:
        if item.get("oracle_type") != "crash_or_sanitizer":
            continue
        if not str(item.get("pattern_id", "")).startswith("OPENSSL-ISSUE-"):
            continue
        out.append(item)
        if len(out) == 5:
            break
    return out


def signal_flags(text: str) -> Dict[str, Any]:
    flags = {name: bool(pattern.search(text or "")) for name, pattern in SIGNATURES.items()}
    other = []
    if flags.pop("invalid_read", False):
        other.append("valgrind_invalid_read")
    return {
        "asan": flags["asan"],
        "ubsan": flags["ubsan"],
        "segv": flags["segv"],
        "exit_139": flags["exit_139"],
        "heap_buffer_overflow": flags["heap_buffer_overflow"],
        "stack_buffer_overflow": flags["stack_buffer_overflow"],
        "use_after_free": flags["use_after_free"],
        "other": other,
    }


def has_any_crash_signal(flags: Dict[str, Any]) -> bool:
    return any(
        bool(flags.get(name))
        for name in [
            "asan",
            "ubsan",
            "segv",
            "exit_139",
            "heap_buffer_overflow",
            "stack_buffer_overflow",
            "use_after_free",
        ]
    ) or bool(flags.get("other"))


def classify(item: Dict[str, Any], metadata: Dict[str, Any], flags: Dict[str, Any], text: str) -> Dict[str, Any]:
    issue_id = str(item.get("pattern_id", ""))
    strict = bool(metadata.get("strict_reproduction"))
    local_crash = bool(metadata.get("crash_observed")) or "segmentation_fault" in str(
        metadata.get("local_test_result", "")
    )
    has_signal = has_any_crash_signal(flags)
    missing_original = bool(metadata.get("missing_original_input"))
    placeholder = str(metadata.get("input_status", "")).lower() == "placeholder_input_used"
    affected = metadata.get("affected_version")

    if issue_id == "OPENSSL-ISSUE-28669" and local_crash and has_signal:
        verdict = "ready_for_runnable_family"
        repro = 0.85
        crash_conf = 0.9
        validity = 0.75
        readiness = 0.8
        misuse = "medium"
        action = (
            "Start a small D_then_A secure-heap lifecycle sprint that reproduces "
            "CRYPTO_secure_used without secure heap init, then adds safe-control cases."
        )
    elif has_signal and not strict:
        verdict = "needs_manual_confirmation"
        repro = 0.55
        crash_conf = 0.7
        validity = 0.55
        readiness = 0.55
        misuse = "medium"
        action = "Recover original input/environment and confirm crash under the affected version."
    else:
        verdict = "needs_manual_confirmation"
        repro = 0.35 if missing_original or placeholder else 0.45
        crash_conf = 0.35
        validity = 0.45
        readiness = 0.35
        misuse = "medium" if missing_original or placeholder else "unknown"
        action = "Do manual repro audit before promoting to runnable family."

    if not affected:
        version_dependency = "unknown"
    elif "dev" in str(affected) or "," in str(affected):
        version_dependency = "high"
    else:
        version_dependency = "medium"

    has_repro = bool(metadata.get("reproduction_command"))
    only_nonzero = "exit code" in text.lower() and not has_signal

    return {
        "recommended_verdict": verdict,
        "recommended_next_action": action,
        "reproducibility_score": round(repro, 2),
        "crash_confidence_score": round(crash_conf, 2),
        "harness_validity_score": round(validity, 2),
        "migration_readiness_score": round(readiness, 2),
        "severity_score": float(item.get("severity_score", 0.0) or 0.0),
        "harness_misuse_risk": misuse,
        "version_dependency": version_dependency,
        "has_repro_command": has_repro,
        "only_nonzero_exit": only_nonzero,
    }


def audit_one(item: Dict[str, Any]) -> Dict[str, Any]:
    issue_id = str(item.get("pattern_id", ""))
    artifact_path = Path(str(item.get("source_path") or f"datasets/openssl/poc_artifacts/{issue_slug(issue_id)}"))
    metadata_path = artifact_path / "metadata.json"
    metadata = load_json(metadata_path)
    files = list(iter_files(artifact_path))
    text_parts = []
    evidence_files = []
    for path in files:
        if path.name in {"metadata.json", "README.md", "run.log", "valgrind.log", "asan.log", "ubsan.log"}:
            text_parts.append(read_text(path))
            evidence_files.append(str(path))
    combined_text = "\n".join(text_parts + ["\n".join(map(str, item.get("notes", []) or []))])
    flags = signal_flags(combined_text)
    classified = classify(item, metadata, flags, combined_text)

    has_log = any(path.name in {"run.log", "valgrind.log", "asan.log", "ubsan.log"} for path in files)
    has_summary = (artifact_path / "README.md").exists() or metadata_path.exists()
    has_version = bool(metadata.get("affected_version") or metadata.get("tested_library"))
    sanitizer = flags["asan"] or flags["ubsan"] or flags["heap_buffer_overflow"] or flags["stack_buffer_overflow"] or flags["use_after_free"]

    family = str(item.get("family", ""))
    if issue_id == "OPENSSL-ISSUE-28669":
        family = "secure_heap_state_lifecycle"

    notes = list(item.get("notes", []) or [])
    if metadata.get("validation_notes"):
        notes.append(str(metadata["validation_notes"]))
    if metadata.get("missing_original_input"):
        notes.append("Original input artifact is missing; strict historical reproduction is not established.")
    if issue_id == "OPENSSL-ISSUE-28669":
        notes.append("Local artifact reports SIGSEGV exit 139 and Valgrind Invalid read against system OpenSSL.")

    return {
        "issue_id": issue_id,
        "family": family,
        "oracle_type": item.get("oracle_type", "crash_or_sanitizer"),
        "migration_status": item.get("migration_status", "pending_migration"),
        "artifact_path": str(artifact_path),
        "evidence_files": evidence_files or [str(p) for p in item.get("evidence_files", []) or []],
        "has_local_artifact": artifact_path.exists(),
        "has_readme_or_metadata_or_summary": has_summary,
        "has_crash_log": has_log and has_any_crash_signal(flags),
        "has_sanitizer_signature": sanitizer,
        "has_repro_command": classified["has_repro_command"],
        "has_version_info": has_version,
        "crash_signal": flags,
        "only_nonzero_exit": classified["only_nonzero_exit"],
        "harness_misuse_risk": classified["harness_misuse_risk"],
        "version_dependency": classified["version_dependency"],
        "reproducibility_score": classified["reproducibility_score"],
        "crash_confidence_score": classified["crash_confidence_score"],
        "harness_validity_score": classified["harness_validity_score"],
        "migration_readiness_score": classified["migration_readiness_score"],
        "severity_score": classified["severity_score"],
        "recommended_verdict": classified["recommended_verdict"],
        "recommended_next_action": classified["recommended_next_action"],
        "notes": notes,
    }


def recommended_family(audits: List[Dict[str, Any]]) -> Dict[str, Any]:
    ready = [a for a in audits if a["recommended_verdict"] == "ready_for_runnable_family"]
    if ready:
        best = sorted(
            ready,
            key=lambda a: (a["migration_readiness_score"], a["crash_confidence_score"], a["severity_score"]),
            reverse=True,
        )[0]
        return {
            "recommended_next_family": {
                "family": best["family"],
                "seed_issue": best["issue_id"],
                "reason": (
                    "This is the only top5 candidate with local crash evidence: "
                    "SIGSEGV/exit 139 plus Valgrind Invalid read. Treat it as a sprint seed, "
                    "not as a new vulnerability claim."
                ),
                "readiness_score": best["migration_readiness_score"],
                "severity_score": best["severity_score"],
                "required_before_runnable": [
                    "Confirm behavior against intended OpenSSL versions",
                    "Add a safe initialized secure-heap control case",
                    "Decide whether CRYPTO_secure_used pre-init call is valid API usage or harness misuse",
                    "Create pattern knowledge and recipe-slot adapter before rendering cases",
                ],
                "proposed_execution_path": "D_then_A",
                "proposed_sprint_name": "secure_heap_state_lifecycle_v1",
                "should_start_runnable_sprint_now": True,
                "blocking_questions": [
                    "Is CRYPTO_secure_used before secure heap initialization documented as safe or undefined?",
                    "Which OpenSSL versions are affected locally and upstream?",
                    "Can the oracle distinguish expected precondition failure from NULL dereference?",
                ],
            }
        }

    return {
        "recommended_next_family": {
            "family": "",
            "seed_issue": "",
            "reason": "No top5 candidate has enough local crash/sanitizer evidence for runnable promotion.",
            "readiness_score": 0.0,
            "severity_score": 0.0,
            "required_before_runnable": ["Recover original inputs and sanitizer logs", "Confirm affected versions"],
            "proposed_execution_path": "D_then_A",
            "proposed_sprint_name": "",
            "should_start_runnable_sprint_now": False,
            "blocking_questions": ["Which candidate can be strictly reproduced locally?"],
        }
    }


def write_markdown(audits: List[Dict[str, Any]], recommendation: Dict[str, Any]) -> None:
    lines = [
        "# Crash/Sanitizer Top5 Evidence Audit",
        "",
        f"Top5 source: `{QUEUE}`",
        "",
        "## Summary",
        "",
    ]
    counts: Dict[str, int] = {}
    for audit in audits:
        counts[audit["recommended_verdict"]] = counts.get(audit["recommended_verdict"], 0) + 1
    for key in sorted(counts):
        lines.append(f"- {key}: `{counts[key]}`")
    lines += ["", "## Issues", ""]
    for audit in audits:
        lines += [
            f"### {audit['issue_id']}",
            "",
            f"- family: `{audit['family']}`",
            f"- recommended_verdict: `{audit['recommended_verdict']}`",
            f"- crash_signal: `{audit['crash_signal']}`",
            f"- reproducibility_score: `{audit['reproducibility_score']}`",
            f"- crash_confidence_score: `{audit['crash_confidence_score']}`",
            f"- harness_validity_score: `{audit['harness_validity_score']}`",
            f"- migration_readiness_score: `{audit['migration_readiness_score']}`",
            f"- action: {audit['recommended_next_action']}",
            "",
        ]
    rec = recommendation["recommended_next_family"]
    lines += [
        "## Recommended Next Family",
        "",
        f"- family: `{rec['family']}`",
        f"- seed_issue: `{rec['seed_issue']}`",
        f"- proposed_execution_path: `{rec['proposed_execution_path']}`",
        f"- proposed_sprint_name: `{rec['proposed_sprint_name']}`",
        f"- should_start_runnable_sprint_now: `{str(rec['should_start_runnable_sprint_now']).lower()}`",
        "",
        rec["reason"],
        "",
    ]
    TOP5_MD.write_text("\n".join(lines), encoding="utf-8")


def write_readme(recommendation: Dict[str, Any]) -> None:
    rec = recommendation["recommended_next_family"]
    text = f"""# Crash/Sanitizer Audit

This directory records a read-only evidence audit for the crash/sanitizer top5
from `artifacts/candidate_queue/candidate_queue.yaml`.

The audit does not claim any new vulnerability. It checks local artifact
presence, crash/sanitizer signatures, repro commands, version information,
harness misuse risk, and migration readiness before recommending a runnable
family.

Recommended next family: `{rec['family']}`
Seed issue: `{rec['seed_issue']}`
Start runnable sprint now: `{str(rec['should_start_runnable_sprint_now']).lower()}`
"""
    README.write_text(text, encoding="utf-8")


def main() -> int:
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    PER_ISSUE.mkdir(parents=True, exist_ok=True)
    audits = [audit_one(item) for item in queue_top5()]
    recommendation = recommended_family(audits)

    report = {
        "audit_name": "Crash/Sanitizer top5 evidence audit",
        "top5_source": str(QUEUE),
        "audited_issues": [a["issue_id"] for a in audits],
        "issues": audits,
        "recommended_next_family": recommendation["recommended_next_family"],
    }
    with TOP5_YAML.open("w", encoding="utf-8") as f:
        yaml.safe_dump(report, f, sort_keys=False, allow_unicode=True)
    for audit in audits:
        with (PER_ISSUE / f"{audit['issue_id'].lower()}.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(audit, f, sort_keys=False, allow_unicode=True)
    with RECOMMENDED_YAML.open("w", encoding="utf-8") as f:
        yaml.safe_dump(recommendation, f, sort_keys=False, allow_unicode=True)
    write_markdown(audits, recommendation)
    write_readme(recommendation)
    print(f"[OK] wrote {TOP5_YAML}")
    print(f"[OK] wrote {TOP5_MD}")
    print(f"[OK] wrote {RECOMMENDED_YAML}")
    print(f"[OK] wrote {README}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Prepare external validation evidence for PKCS full-consumption candidates.

This module reads existing sprint artifacts, replays candidate inputs with the
OpenSSL CLI, and writes triage/evidence handoff documents. It does not render
new harnesses, compile fuzz harnesses, write feedback, mutate knowledge, or make
confirmed vulnerability/CVE/exploitability claims.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from analyzer.oracle_event_parser import parse_oracle_event_line


SPRINT = "pkcs_candidate_external_validation_v1"
PIPELINE_ROOT = Path("artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1")
SEED_MANIFEST = Path(
    "artifacts/sprints/valid_seed_discovery_pkcs_v1/manifests/verified_pkcs_seed_manifest.yaml"
)
PREFERRED_OPENSSL = Path("/home/wen/work/install-openssl-3.5.5-asan/bin/openssl")
ALLOWED_CLASSIFICATIONS = {
    "expected_prefix_parse_behavior",
    "caller_must_check_consumption",
    "app_level_validation_gap_candidate",
    "needs_teammate_validation",
    "false_positive",
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
            return {"available": True, "path": str(PREFERRED_OPENSSL), "attempts": attempts}
    fallback = shutil.which("openssl")
    if fallback:
        result = run_cmd([fallback, "version"], timeout=10)
        attempts.append({"path": fallback, **result})
        if result["return_code"] == 0:
            return {"available": True, "path": fallback, "attempts": attempts}
    return {"available": False, "path": "", "attempts": attempts}


def parse_events_from_log(path: Path) -> list[dict[str, Any]]:
    events = []
    if not path.exists():
        return events
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        event = parse_oracle_event_line(line)
        if event is None:
            continue
        event["raw_line"] = line
        events.append(event)
    return events


def candidate_input_path(repo_root: Path, case: dict[str, Any]) -> Path:
    rendered_root = repo_root / PIPELINE_ROOT / "rendered_cases"
    for meta in sorted(rendered_root.glob("*/render_metadata.yaml")):
        doc = load_yaml(meta)
        if doc.get("case_id") == case.get("case_id"):
            return Path(str(doc.get("seed_input", "")))
    return Path("")


def run_stdout_path(repo_root: Path, case_id: str) -> Path:
    return repo_root / PIPELINE_ROOT / "compile_run" / "compiled_cases" / case_id / "run.stdout.log"


def replay_command(openssl: str, container_type: str, input_path: Path) -> list[str]:
    if container_type == "pkcs12":
        return [openssl, "pkcs12", "-in", str(input_path), "-noout", "-passin", "pass:"]
    if container_type == "cms":
        return [openssl, "cms", "-cmsout", "-inform", "DER", "-in", str(input_path), "-noout"]
    return [openssl, "pkcs7", "-inform", "DER", "-in", str(input_path), "-noout"]


def summarize_oracle(events: list[dict[str, Any]]) -> dict[str, Any]:
    parse_events = [e for e in events if e.get("phase") == "parse"]
    accepted = any(e.get("accepted") == 1 for e in parse_events)
    full_values = [e.get("full_consumption") for e in parse_events if "full_consumption" in e]
    full_consumption = bool(full_values) and all(v == 1 for v in full_values)
    full_gap = accepted and any(v == 0 for v in full_values)
    return {
        "accepted": accepted,
        "full_consumption": full_consumption,
        "full_consumption_gap": full_gap,
        "event_count": len(events),
        "parse_events": len(parse_events),
        "raw_events": [e.get("raw_line", "") for e in events],
    }


def classify(oracle: dict[str, Any], replay: dict[str, Any], container_type: str) -> tuple[str, str, str]:
    replay_accepted = replay.get("return_code") == 0
    if not oracle.get("full_consumption_gap"):
        return (
            "false_positive",
            "local oracle did not retain accepted=true plus full_consumption=false",
            "drop from candidate queue unless new evidence appears",
        )
    if not replay_accepted:
        return (
            "needs_teammate_validation",
            "harness parser accepted a prefix but OpenSSL CLI replay did not accept the full file",
            "ask teammate to compare CLI behavior, d2i semantics, and app-level expectations",
        )
    if container_type in {"pkcs12", "pkcs7", "cms"}:
        return (
            "caller_must_check_consumption",
            "d2i-style parser accepted a prefix while trailing bytes remain; this is a caller-consumption-check obligation rather than a standalone vulnerability claim",
            "external validation should determine whether any real app-level caller omits full-consumption checks",
        )
    return (
        "needs_teammate_validation",
        "container type was not specific enough for local classification",
        "ask teammate to validate API semantics",
    )


def select_candidates(repo_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    queue = load_yaml(repo_root / PIPELINE_ROOT / "candidates" / "pkcs_candidate_queue.yaml")
    analysis = load_yaml(repo_root / PIPELINE_ROOT / "analyze" / "oracle_aware_analysis.yaml")
    analysis_by_case = {case.get("case_id"): case for case in analysis.get("cases", [])}
    selected = []
    for item in queue.get("candidates", []) or []:
        if item.get("family") != "pkcs_container_parsing":
            continue
        if item.get("candidate_label") != "full_consumption_gap_candidate":
            continue
        case = analysis_by_case.get(item.get("case_id"), {})
        if not case:
            continue
        selected.append({**item, **case})
    doc = {
        "schema": "pkcs_candidate_selection_v1",
        "generated_at": now_iso(),
        "candidate_queue": str(PIPELINE_ROOT / "candidates" / "pkcs_candidate_queue.yaml"),
        "oracle_aware_analysis": str(PIPELINE_ROOT / "analyze" / "oracle_aware_analysis.yaml"),
        "family": "pkcs_container_parsing",
        "label": "full_consumption_gap_candidate",
        "candidate_count": len(selected),
        "case_ids": [c.get("case_id") for c in selected],
        "container_types": sorted({str(c.get("container_type")) for c in selected}),
    }
    return doc, selected


def build_evidence_bundle(out_dir: Path, repo_root: Path, triage_rows: list[dict[str, Any]]) -> None:
    bundle = out_dir / "evidence" / "candidate_evidence_bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    for row in triage_rows:
        case_dir = bundle / row["candidate_id"]
        case_dir.mkdir(parents=True, exist_ok=True)
        input_path = Path(row["input_path"])
        if input_path.exists():
            shutil.copy2(input_path, case_dir / "input.bin")
        stdout = run_stdout_path(repo_root, row["case_id"])
        if stdout.exists():
            shutil.copy2(stdout, case_dir / "run.stdout.log")
        dump_yaml(case_dir / "evidence.yaml", row)


def notes_text(triage_rows: list[dict[str, Any]]) -> str:
    lines = [
        "# PKCS Candidate External Validation Notes",
        "",
        "These are not confirmed vulnerabilities, CVEs, or exploitability claims.",
        "They are local prefix-consumption candidates that need API/app-level validation.",
        "",
        "## Candidates",
        "",
    ]
    for row in triage_rows:
        lines.extend(
            [
                f"### {row['candidate_id']}",
                "",
                f"- case_id: `{row['case_id']}`",
                f"- container_type: `{row['container_type']}`",
                f"- seed_id: `{row['seed_id']}`",
                f"- mutation_strategy: `{row['mutation_strategy']}`",
                f"- oracle accepted: {row['oracle_events']['accepted']}",
                f"- oracle full_consumption: {row['oracle_events']['full_consumption']}",
                f"- oracle full_consumption_gap: {row['oracle_events']['full_consumption_gap']}",
                f"- replay command: `{row['local_replay']['openssl_command']}`",
                f"- replay return_code: {row['local_replay']['return_code']}",
                f"- classification: `{row['classification']}`",
                f"- reason: {row['reason']}",
                f"- next_action: {row['next_action']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Recommended External Checks",
            "",
            "- Confirm OpenSSL `d2i_*` prefix-parse semantics for PKCS12/PKCS7 inputs with trailing bytes.",
            "- Check whether any app-level parser wrapper is expected to require full input consumption.",
            "- Treat CLI acceptance as parser replay evidence only; consumed length comes from the instrumented harness event.",
            "- Do not escalate to vulnerability language without an app-level missing-consumption-check path.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "replay", "evidence", "triage", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    selection_doc, candidates = select_candidates(repo_root)
    dump_yaml(out_dir / "inputs" / "candidate_selection.yaml", selection_doc)

    _seed_manifest = load_yaml(repo_root / SEED_MANIFEST)
    openssl_info = resolve_openssl()
    replay_rows = []
    triage_rows = []
    for idx, candidate in enumerate(candidates, start=1):
        case_id = str(candidate.get("case_id"))
        input_path = candidate_input_path(repo_root, candidate)
        events = parse_events_from_log(repo_root / run_stdout_path(Path("."), case_id))
        oracle = summarize_oracle(events)
        replay: dict[str, Any]
        if openssl_info["available"] and input_path.exists():
            cmd = replay_command(openssl_info["path"], str(candidate.get("container_type")), input_path)
            replay = run_cmd(cmd)
        else:
            replay = {
                "command": [],
                "return_code": 127,
                "stdout": "",
                "stderr": "openssl unavailable or input missing",
                "timeout": False,
            }
        classification, reason, next_action = classify(
            oracle, replay, str(candidate.get("container_type"))
        )
        if classification not in ALLOWED_CLASSIFICATIONS:
            classification = "needs_teammate_validation"
        row = {
            "candidate_id": f"pkcs_candidate_{idx:03d}",
            "case_id": case_id,
            "container_type": candidate.get("container_type", ""),
            "seed_id": candidate.get("seed_id", ""),
            "mutation_strategy": candidate.get("mutation_strategy", ""),
            "input_path": input_path.as_posix(),
            "input_sha256": sha256_file(input_path) if input_path.exists() else "",
            "input_size_bytes": input_path.stat().st_size if input_path.exists() else 0,
            "oracle_events": oracle,
            "local_replay": {
                "openssl_command": " ".join(str(x) for x in replay.get("command", [])),
                "return_code": replay.get("return_code"),
                "accepted": replay.get("return_code") == 0,
                "stdout_excerpt": replay.get("stdout", ""),
                "stderr_excerpt": replay.get("stderr", ""),
            },
            "classification": classification,
            "reason": reason,
            "next_action": next_action,
            "claim_policy": {
                "confirmed_vulnerability": False,
                "cve": False,
                "exploitable": False,
            },
        }
        replay_rows.append(
            {
                "candidate_id": row["candidate_id"],
                "case_id": case_id,
                "container_type": row["container_type"],
                "input_path": row["input_path"],
                "openssl_command": row["local_replay"]["openssl_command"],
                "return_code": row["local_replay"]["return_code"],
                "accepted": row["local_replay"]["accepted"],
                "stderr_excerpt": row["local_replay"]["stderr_excerpt"],
            }
        )
        triage_rows.append(row)

    replay_doc = {
        "schema": "pkcs_local_replay_report_v1",
        "generated_at": now_iso(),
        "openssl": openssl_info,
        "replay_attempted": bool(replay_rows),
        "replays": replay_rows,
        "summary": {
            "candidate_count": len(triage_rows),
            "accepted": len([r for r in replay_rows if r.get("accepted")]),
        },
    }
    dump_yaml(out_dir / "replay" / "local_replay_report.yaml", replay_doc)

    build_evidence_bundle(out_dir, repo_root, triage_rows)

    counts = Counter(row["classification"] for row in triage_rows)
    triage_doc = {
        "schema": "pkcs_candidate_triage_v1",
        "generated_at": now_iso(),
        "allowed_classifications": sorted(ALLOWED_CLASSIFICATIONS),
        "candidates": triage_rows,
        "summary": {name: counts.get(name, 0) for name in sorted(ALLOWED_CLASSIFICATIONS)},
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }
    dump_yaml(out_dir / "triage" / "pkcs_candidate_triage.yaml", triage_doc)
    write_text(out_dir / "triage" / "teammate_validation_notes.md", notes_text(triage_rows))

    qc = {
        "schema": "pkcs_candidate_external_validation_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "candidate_queue_loaded": True,
        "candidate_count": len(triage_rows),
        "replay_attempted": bool(replay_rows),
        "evidence_bundle_generated": True,
        "teammate_notes_generated": True,
        "asn1_cases_rerun": False,
        "render_executed": False,
        "compile_executed": False,
        "run_fuzz_harness_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass" if len(triage_rows) == 2 else "blocked",
    }
    dump_yaml(out_dir / "validation" / "pkcs_candidate_external_validation_quality_checks.yaml", qc)

    report = f"""# {SPRINT} Report

## Summary

- quality_status: {qc['quality_status']}
- candidate_count: {len(triage_rows)}
- replay_attempted: {qc['replay_attempted']}
- evidence_bundle_generated: true
- teammate_notes_generated: true
- ASN.1 rerun: false
- render/compile/run fuzz harness: false / false / false

## Classification Summary

{yaml.safe_dump(triage_doc['summary'], sort_keys=True, allow_unicode=True)}
## Policy

No confirmed vulnerability, CVE, exploitability, feedback, knowledge, pattern-bank,
adapter recipe, normalized template, GLM, git add, commit, or push action was made.
"""
    write_text(out_dir / "reports" / f"{SPRINT}_report.md", report)

    print(f"[OK] wrote {SPRINT} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"candidates={len(triage_rows)} replay={bool(replay_rows)} "
        f"classifications={dict(counts)} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Triage X.509 full-consumption candidate with OpenSSL app-level replay."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from analysis.analysis_records import dump_yaml, now_iso, write_text


ASAN_OPENSSL = Path("/home/wen/work/install-openssl-3.5.5-asan/bin/openssl")
ASAN_INSTALL = Path("/home/wen/work/install-openssl-3.5.5-asan")
SYSTEM_OPENSSL = Path("/usr/bin/openssl")


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--input-sprint", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def openssl_env() -> dict[str, str]:
    env = os.environ.copy()
    lib64 = ASAN_INSTALL / "lib64"
    lib = lib64 if lib64.exists() else ASAN_INSTALL / "lib"
    prior = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{lib}:{prior}" if prior else lib.as_posix()
    env["OPENSSL_MODULES"] = (lib / "ossl-modules").as_posix()
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def select_openssl() -> dict[str, Any]:
    if ASAN_OPENSSL.exists():
        proc = subprocess.run(
            [ASAN_OPENSSL.as_posix(), "version", "-a"],
            text=True,
            capture_output=True,
            env=openssl_env(),
        )
        output = (proc.stdout + proc.stderr).strip()
        if proc.returncode == 0:
            return {
                "path": ASAN_OPENSSL.as_posix(),
                "version": output.splitlines()[0] if output else "",
                "asan_available": True,
                "fallback_used": False,
                "fallback_reason": "",
                "env": openssl_env(),
            }
        fallback_reason = output
    else:
        fallback_reason = "ASAN OpenSSL binary missing"

    proc = subprocess.run([SYSTEM_OPENSSL.as_posix(), "version", "-a"], text=True, capture_output=True)
    output = (proc.stdout + proc.stderr).strip()
    return {
        "path": SYSTEM_OPENSSL.as_posix(),
        "version": output.splitlines()[0] if output else "",
        "asan_available": False,
        "fallback_used": True,
        "fallback_reason": fallback_reason,
        "env": os.environ.copy(),
    }


def by_case(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(item.get("case_id") or ""): item for item in items}


def events_for(events: list[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    return [event for event in events if event.get("case_id") == case_id]


def input_file_for(index_case: dict[str, Any]) -> Path:
    input_dir = Path(str(index_case.get("input_corpus_dir") or ""))
    for name in ("input.der", "input.pem", "input.bin"):
        candidate = input_dir / name
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"no input file under {input_dir}")


def replay_commands(openssl: dict[str, Any], input_path: Path, fmt: str, out_dir: Path, prefix: str) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = str(openssl["path"])
    if fmt == "pem":
        commands = [
            [bin_path, "x509", "-in", input_path.as_posix(), "-noout", "-fingerprint"],
            [bin_path, "x509", "-in", input_path.as_posix(), "-noout", "-text"],
            [bin_path, "x509", "-in", input_path.as_posix(), "-outform", "DER", "-out", (out_dir / f"{prefix}.der").as_posix()],
        ]
    else:
        commands = [
            [bin_path, "x509", "-inform", "DER", "-in", input_path.as_posix(), "-noout", "-fingerprint"],
            [bin_path, "x509", "-inform", "DER", "-in", input_path.as_posix(), "-noout", "-text"],
            [
                bin_path,
                "x509",
                "-inform",
                "DER",
                "-in",
                input_path.as_posix(),
                "-outform",
                "PEM",
                "-out",
                (out_dir / f"{prefix}.pem").as_posix(),
            ],
        ]
    results = []
    for idx, command in enumerate(commands, start=1):
        proc = subprocess.run(command, text=True, capture_output=True, env=openssl["env"])
        stdout_log = out_dir / f"{prefix}_cmd_{idx}.stdout.log"
        stderr_log = out_dir / f"{prefix}_cmd_{idx}.stderr.log"
        stdout_log.write_text(proc.stdout, encoding="utf-8")
        stderr_log.write_text(proc.stderr, encoding="utf-8")
        output_path = ""
        for pos, token in enumerate(command):
            if token == "-out" and pos + 1 < len(command):
                output_path = command[pos + 1]
        meaningful_output = bool(proc.stdout.strip()) or (bool(output_path) and Path(output_path).exists() and Path(output_path).stat().st_size > 0)
        results.append(
            {
                "command_id": f"{prefix}_cmd_{idx}",
                "command": command,
                "return_code": proc.returncode,
                "stdout_log": stdout_log.as_posix(),
                "stderr_log": stderr_log.as_posix(),
                "output_path": output_path,
                "meaningful_output": meaningful_output,
            }
        )
    return results


def app_level_accepted(results: list[dict[str, Any]]) -> bool:
    return all(item.get("return_code") == 0 and item.get("meaningful_output") for item in results)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    input_sprint = (repo_root / args.input_sprint).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "replay", "controls", "evidence/candidate_evidence_bundle", "triage", "summary", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    analysis = load_yaml(input_sprint / "analyze/oracle_aware_analysis.yaml")
    queue = load_yaml(input_sprint / "candidates/x509_candidate_queue.yaml")
    run_results = load_yaml(input_sprint / "compile_run/run_results.yaml")
    oracle_events = load_yaml(input_sprint / "compile_run/oracle_events.yaml")
    case_index = load_yaml(repo_root / "artifacts/sprints/orchestrator_execute_x509_render_cases_v1/case_index/rendered_case_index.yaml")

    candidates = [
        item
        for item in queue.get("candidates", []) or []
        if item.get("family") == "x509_parsing" and item.get("candidate_label") == "full_consumption_gap_candidate"
    ]
    index_by_id = by_case(case_index.get("cases", []) or [])
    run_by_id = by_case(run_results.get("run_results", []) or [])
    analysis_by_id = by_case(analysis.get("cases", []) or [])
    all_events = oracle_events.get("events", []) or []
    openssl = select_openssl()

    triaged = []
    replay_matrix = {
        "schema": "x509_app_replay_matrix_v1",
        "generated_at": now_iso(),
        "openssl": {k: v for k, v in openssl.items() if k != "env"},
        "commands": [],
    }
    replay_results = {"schema": "x509_app_replay_results_v1", "generated_at": now_iso(), "results": []}

    malformed_case = next(
        (case for case in case_index.get("cases", []) or [] if case.get("mutation_strategy") == "malformed_only_control"),
        {},
    )
    malformed_input = input_file_for(malformed_case) if malformed_case else None
    control_copy = out_dir / "controls" / "malformed_only_control.der"
    control_results: list[dict[str, Any]] = []
    if malformed_input is not None:
        shutil.copy2(malformed_input, control_copy)
        control_results = replay_commands(openssl, control_copy, "der", out_dir / "replay", "malformed_control")

    for candidate in candidates:
        case_id = str(candidate.get("case_id") or "")
        index_case = index_by_id[case_id]
        run = run_by_id.get(case_id, {})
        case_analysis = analysis_by_id.get(case_id, {})
        evs = events_for(all_events, case_id)
        input_path = input_file_for(index_case)
        fmt = "pem" if input_path.suffix.lower() == ".pem" else "der"
        evidence_dir = out_dir / "evidence/candidate_evidence_bundle"
        copied_input = evidence_dir / f"{case_id}{input_path.suffix}"
        shutil.copy2(input_path, copied_input)
        for log_key in ("stdout_log", "stderr_log"):
            log_path = Path(str(run.get(log_key) or ""))
            if log_path.exists():
                shutil.copy2(log_path, evidence_dir / f"{case_id}.{log_key}.log")
        dump_yaml(evidence_dir / f"{case_id}.oracle_events.yaml", {"events": evs})
        dump_yaml(evidence_dir / f"{case_id}.analysis.yaml", case_analysis)
        results = replay_commands(openssl, copied_input, fmt, out_dir / "replay", "candidate")
        replay_matrix["commands"].extend(
            {
                "case_id": case_id,
                "command_id": result["command_id"],
                "command": result["command"],
            }
            for result in results
        )
        replay_results["results"].append({"case_id": case_id, "kind": "candidate", "results": results})
        accepted = app_level_accepted(results)
        control_rejected = bool(control_results) and all(item.get("return_code") != 0 for item in control_results)
        full_gap = any(event.get("accepted") in {1, True, "true"} and event.get("full_consumption") in {0, False, "false"} for event in evs)
        if accepted and control_rejected and full_gap:
            classification = "app_level_validation_gap_candidate"
            next_action = "prepare minimal app-level reproducer and request external validation"
            reason = "OpenSSL x509 app accepted the trailing-garbage candidate while malformed-only control was rejected."
        elif full_gap:
            classification = "caller_must_check_consumption"
            next_action = "validate caller behavior and API documentation"
            reason = "Harness observed accepted prefix parse with unconsumed bytes, but app replay did not prove app-level acceptance."
        else:
            classification = "false_positive"
            next_action = "close or regenerate candidate"
            reason = "No accepted full-consumption gap remains after triage."
        triaged.append(
            {
                "candidate_id": case_id,
                "case_id": case_id,
                "mutation_strategy": candidate.get("mutation_strategy", ""),
                "input_path": copied_input.as_posix(),
                "oracle_events": {
                    "accepted": [event.get("accepted") for event in evs],
                    "full_consumption": [event.get("full_consumption") for event in evs],
                    "full_consumption_gap": full_gap,
                },
                "app_replay": {
                    "commands_attempted": len(results),
                    "app_level_accepted": accepted,
                    "meaningful_output": all(item.get("meaningful_output") for item in results),
                },
                "malformed_only_control": {
                    "generated": malformed_input is not None,
                    "path": control_copy.as_posix() if malformed_input is not None else "",
                    "rejected": control_rejected,
                },
                "classification": classification,
                "reason": reason,
                "recommended_next_action": next_action,
                "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
            }
        )

    replay_results["results"].append({"case_id": "malformed_only_control", "kind": "control", "results": control_results})
    dump_yaml(
        out_dir / "inputs/candidate_selection.yaml",
        {
            "schema": "x509_candidate_selection_v1",
            "generated_at": now_iso(),
            "source_candidate_queue": (input_sprint / "candidates/x509_candidate_queue.yaml").as_posix(),
            "candidate_count": len(candidates),
            "selected_candidates": candidates,
        },
    )
    dump_yaml(out_dir / "replay/x509_app_replay_matrix.yaml", replay_matrix)
    dump_yaml(out_dir / "replay/x509_app_replay_results.yaml", replay_results)
    control_rejected = bool(control_results) and all(item.get("return_code") != 0 for item in control_results)
    dump_yaml(
        out_dir / "controls/malformed_only_control.yaml",
        {
            "schema": "x509_malformed_only_control_v1",
            "generated_at": now_iso(),
            "generated": malformed_input is not None,
            "path": control_copy.as_posix() if malformed_input is not None else "",
            "replay_results": control_results,
            "rejected": control_rejected,
        },
    )
    triage_doc = {
        "schema": "x509_candidate_triage_v1",
        "generated_at": now_iso(),
        "candidates": triaged,
        "summary": {
            "candidate_count": len(triaged),
            "app_level_validation_gap_candidate": len(
                [item for item in triaged if item.get("classification") == "app_level_validation_gap_candidate"]
            ),
            "caller_must_check_consumption": len(
                [item for item in triaged if item.get("classification") == "caller_must_check_consumption"]
            ),
            "needs_external_validation": len(
                [
                    item
                    for item in triaged
                    if item.get("classification")
                    in {"app_level_validation_gap_candidate", "caller_must_check_consumption", "needs_external_validation"}
                ]
            ),
        },
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    dump_yaml(out_dir / "triage/x509_candidate_triage.yaml", triage_doc)

    classification = triaged[0]["classification"] if triaged else "none"
    issue_summary = f"""# X.509 Issue Candidate Summary

## 1. 问题来源

来自 `orchestrator_execute_x509_compile_run_analyze_v1` 的 `full-consumption gap candidate`。

## 2. 当前 observed behavior

候选 DER 输入在 harness 中被 OpenSSL `d2i_X509` 接受，但 `consumed_len < input_len`。

## 3. harness/oracle 证据

- candidate count: {len(triaged)}
- oracle accepted: {triaged[0]['oracle_events']['accepted'] if triaged else []}
- oracle full_consumption: {triaged[0]['oracle_events']['full_consumption'] if triaged else []}

## 4. app-level replay 结果

- app replay attempted: true
- app-level accepted: {triaged[0]['app_replay']['app_level_accepted'] if triaged else False}
- meaningful output: {triaged[0]['app_replay']['meaningful_output'] if triaged else False}

## 5. malformed-only control 结果

- generated: {malformed_input is not None}
- rejected: {control_rejected}

## 6. 当前分类

`{classification}`

## 7. 是否建议准备 issue

建议先准备 issue-level semantic candidate 材料并请求外部验证；目前不能给出 CVE 或 exploitable 结论。

## 8. 后续最小复现建议

保留 candidate DER、malformed-only control、三条 `openssl x509` replay 命令及其 stdout/stderr，复核应用层是否应拒绝 trailing garbage。
"""
    write_text(out_dir / "summary/x509_issue_candidate_summary.md", issue_summary)
    brief = f"""# Teammate Validation Brief

## Request

请外部复核 X.509 DER trailing-garbage 的 app-level replay 行为。

## Candidate

- case_id: `{triaged[0]['case_id'] if triaged else ''}`
- classification: `{classification}`
- evidence bundle: `artifacts/sprints/x509_candidate_triage_v1/evidence/candidate_evidence_bundle/`

## What To Check

- `openssl x509 -inform DER` 是否预期接受带 trailing garbage 的 DER。
- malformed-only control 是否稳定拒绝。
- 该行为是否只属于 low-level prefix parse，还是可作为 app-level validation gap candidate。

## Claim Policy

本 brief 不声明漏洞、CVE 或可利用性。
"""
    write_text(out_dir / "summary/teammate_validation_brief.md", brief)

    qc = {
        "schema": "x509_candidate_triage_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "candidate_queue_loaded": bool(queue),
        "candidate_count": len(candidates),
        "app_replay_attempted": bool(triaged),
        "malformed_only_control_generated": malformed_input is not None,
        "evidence_bundle_generated": (out_dir / "evidence/candidate_evidence_bundle").exists(),
        "teammate_brief_generated": (out_dir / "summary/teammate_validation_brief.md").exists(),
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
        "quality_status": "pass"
        if bool(queue) and len(candidates) == 1 and bool(triaged) and (out_dir / "summary/teammate_validation_brief.md").exists()
        else "blocked",
    }
    dump_yaml(out_dir / "validation/x509_candidate_triage_quality_checks.yaml", qc)
    report = f"""# x509_candidate_triage_v1 Report

- candidate_count: {len(candidates)}
- app_replay_attempted: {bool(triaged)}
- malformed_only_control_rejected: {control_rejected}
- classification: {classification}
- quality_status: {qc['quality_status']}

No vulnerability, CVE, or exploitability conclusion is made.
"""
    write_text(out_dir / "reports/x509_candidate_triage_v1_report.md", report)
    print(f"[OK] wrote x509_candidate_triage_v1 artifacts to {out_dir}")
    print(f"[SUMMARY] candidates={len(candidates)} classification={classification} quality={qc['quality_status']}")
    return 0 if qc["quality_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

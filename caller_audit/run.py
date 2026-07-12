from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from .command_runner import run_commands
from .dynamic_parser import parse_dynamic_evidence
from .io_utils import (
    expand_tree,
    load_yaml,
    write_jsonl,
    write_yaml,
)
from .report import render_report
from .repository import snapshot_repository
from .scanner import evaluate_static_checks, scan_call_sites
from .verdict import classify


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run CipherLens caller-aware audit v0.1."
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--skip-commands", action="store_true")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    raw = load_yaml(config_path)
    project_raw = raw.get("project") or {}
    repo_path_raw = os.path.expandvars(
        str(project_raw.get("repo_path", ""))
    )
    repo_root = Path(repo_path_raw).expanduser().resolve()
    if not repo_root.is_dir():
        raise SystemExit(
            f"project.repo_path does not exist: {repo_root}"
        )

    out_root = Path(args.out_root).expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    context = {
        "repo": str(repo_root),
        "out": str(out_root),
        "config_dir": str(config_path.parent),
    }
    config = expand_tree(raw, context)
    project = config.get("project") or {}
    candidate = config.get("candidate") or {}
    scan = config.get("scan") or {}
    dynamic_cfg = config.get("dynamic") or {}
    reachability = config.get("reachability") or {}

    snapshot = snapshot_repository(repo_root)
    expected_commit = str(project.get("expected_commit") or "")
    if expected_commit and snapshot["commit"] != expected_commit:
        raise SystemExit(
            "repository commit mismatch: "
            f"expected {expected_commit}, got {snapshot['commit']}"
        )

    call_sites = scan_call_sites(
        repo_root,
        api_patterns=list(scan.get("api_patterns") or []),
        include_globs=list(scan.get("include_globs") or []),
        exclude_globs=list(scan.get("exclude_globs") or []),
        test_markers=list(scan.get("test_markers") or []),
        context_lines=int(scan.get("context_lines", 8)),
    )
    static_checks = evaluate_static_checks(
        call_sites,
        list(scan.get("full_consumption_patterns") or []),
    )

    write_yaml(out_root / "repository_snapshot.yaml", snapshot)
    write_jsonl(out_root / "call_sites.jsonl", call_sites)
    write_yaml(out_root / "static_checks.yaml", static_checks)

    command_results: list[dict[str, Any]] = []
    if not args.skip_commands:
        command_results = run_commands(
            list(config.get("commands") or []),
            default_cwd=repo_root,
            log_dir=out_root / "logs",
            base_env={
                str(k): str(v)
                for k, v in (
                    config.get("environment") or {}
                ).items()
            },
        )
    write_yaml(out_root / "command_results.yaml", command_results)

    dynamic_evidence = parse_dynamic_evidence(
        command_results, dynamic_cfg
    )
    write_yaml(
        out_root / "dynamic_evidence.yaml",
        dynamic_evidence,
    )

    verdict = classify(
        static_checks, dynamic_evidence, reachability
    )
    result = {
        "schema": "cipherlens_caller_audit_v0_1",
        "project": project,
        "candidate": candidate,
        "repository": snapshot,
        "static_checks": static_checks,
        "dynamic_evidence": dynamic_evidence,
        "reachability": reachability,
        "verdict": verdict,
    }
    write_yaml(out_root / "caller_triage.yaml", result)
    (out_root / "REPORT.md").write_text(
        render_report(result), encoding="utf-8"
    )

    print(f"[OK] caller audit output: {out_root}")
    print(f"[VERDICT] {verdict['status']}")
    print(verdict["reason"])


if __name__ == "__main__":
    main()

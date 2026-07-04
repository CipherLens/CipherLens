#!/usr/bin/env python3
"""Thin CLI wrapper for the one-click GLM/oracle mainline campaign."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


DEFAULT_TARGETS = "mbedtls-3.6.4-asan,mbedtls-4.1.0-asan,botan-3.10.0-asan"
DEFAULT_FAMILIES = "pkey_sign_verify,mac_digest_lifecycle,aead_lifecycle,roundtrip,parser_full_consumption"
DEFAULT_OUT_DIR = "artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--targets", default=DEFAULT_TARGETS)
    parser.add_argument("--families", default=DEFAULT_FAMILIES)
    parser.add_argument("--orchestrator-mode", choices=["stage_contract", "legacy_smoke"], default="stage_contract")
    parser.add_argument("--seed-source", default="mixed")
    parser.add_argument("--execution-mode", default="syntax_only")
    parser.add_argument("--oracle-mode", default="dispatch")
    parser.add_argument("--probe-mode", choices=["live", "existing"], default="existing")
    parser.add_argument("--max-families", type=int, default=5)
    parser.add_argument("--max-cases", type=int, default=60)
    parser.add_argument("--max-compile-jobs", type=int, default=80)
    args = parser.parse_args()

    repo = Path(args.repo_root)
    cmd = [
        sys.executable,
        "analysis/full_mainline_glm_oracle_campaign.py",
        "--repo-root",
        args.repo_root,
        "--out-dir",
        args.out_dir,
        "--targets",
        args.targets,
        "--families",
        args.families,
        "--orchestrator-mode",
        args.orchestrator_mode,
        "--seed-source",
        args.seed_source,
        "--execution-mode",
        args.execution_mode,
        "--oracle-mode",
        args.oracle_mode,
        "--max-families",
        str(args.max_families),
        "--max-cases",
        str(args.max_cases),
        "--max-compile-jobs",
        str(args.max_compile_jobs),
        "--probe-mode",
        args.probe_mode,
    ]
    raise SystemExit(subprocess.run(cmd, cwd=repo, check=False).returncode)


if __name__ == "__main__":
    main()

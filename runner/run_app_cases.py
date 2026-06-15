from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run_case(case_dir: Path, timeout: int) -> dict[str, Any]:
    manifest_path = case_dir / "case_manifest.yaml"
    manifest = load_yaml(manifest_path)
    result_path = case_dir / "run_result.json"
    if result_path.exists():
        result_path.unlink()
    proc = subprocess.run(
        [sys.executable, "case.py"],
        cwd=case_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    result: dict[str, Any] = {}
    if result_path.exists():
        result = json.loads(result_path.read_text(encoding="utf-8"))
        status = "run_ok"
    else:
        status = "harness_error"
    return {
        "source": str(case_dir / "case.py"),
        "case_dir": str(case_dir),
        "case_id": manifest.get("case_id", case_dir.name),
        "library": "openssl",
        "status": status,
        "runner_exit_code": proc.returncode,
        "runner_stdout": proc.stdout,
        "runner_stderr": proc.stderr,
        "manifest": manifest,
        "run": result,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--keep-going", action="store_true")
    args = parser.parse_args()

    case_dirs = sorted(path for path in args.input_root.iterdir() if (path / "case.py").exists())
    args.result.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    with args.result.open("w", encoding="utf-8") as f:
        for case_dir in case_dirs:
            try:
                row = run_case(case_dir, args.timeout)
            except subprocess.TimeoutExpired as exc:
                row = {
                    "source": str(case_dir / "case.py"),
                    "case_dir": str(case_dir),
                    "case_id": case_dir.name,
                    "library": "openssl",
                    "status": "timeout",
                    "runner_stdout": exc.stdout or "",
                    "runner_stderr": exc.stderr or "",
                    "manifest": load_yaml(case_dir / "case_manifest.yaml"),
                    "run": {},
                }
            counts[row["status"]] = counts.get(row["status"], 0) + 1
            f.write(json.dumps(row, sort_keys=True) + "\n")
            if row["status"] not in {"run_ok"} and not args.keep_going:
                break
    print(f"[SUMMARY] total_cases: {sum(counts.values())}")
    print(f"[SUMMARY] status_counts: {counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

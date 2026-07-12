from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any


def run_commands(
    commands: list[dict[str, Any]],
    default_cwd: Path,
    log_dir: Path,
    base_env: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    log_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []

    for index, spec in enumerate(commands):
        name = str(spec.get("name") or f"command_{index:02d}")
        command = str(spec["command"])
        cwd = Path(spec.get("cwd") or default_cwd)
        timeout = int(spec.get("timeout_seconds", 1800))
        allow_failure = bool(spec.get("allow_failure", False))

        env = dict(os.environ)
        if base_env:
            env.update({str(k): str(v) for k, v in base_env.items()})
        env.update({
            str(k): str(v)
            for k, v in (spec.get("env") or {}).items()
        })

        start = time.time()
        result = subprocess.run(
            ["bash", "-lc", command],
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        elapsed = round(time.time() - start, 3)

        stdout_path = log_dir / f"{index:02d}_{name}.stdout.log"
        stderr_path = log_dir / f"{index:02d}_{name}.stderr.log"
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")

        rows.append({
            "name": name,
            "command": command,
            "cwd": str(cwd),
            "returncode": result.returncode,
            "duration_seconds": elapsed,
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
            "allow_failure": allow_failure,
        })
        if result.returncode != 0 and not allow_failure:
            break

    return rows

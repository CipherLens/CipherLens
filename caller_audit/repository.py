from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


def git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed in {repo}:\n{result.stderr.strip()}"
        )
    return result.stdout.strip()


def snapshot_repository(repo: Path) -> dict[str, Any]:
    if not (repo / ".git").exists():
        raise ValueError(f"not a Git repository: {repo}")
    return {
        "repository_root": str(repo.resolve()),
        "remote_origin": git(repo, "remote", "get-url", "origin", check=False),
        "branch": git(repo, "branch", "--show-current", check=False),
        "commit": git(repo, "rev-parse", "HEAD"),
        "commit_date": git(repo, "show", "-s", "--format=%cI", "HEAD"),
        "status_short": git(repo, "status", "--short", check=False),
        "submodules": git(
            repo, "submodule", "status", "--recursive", check=False
        ).splitlines(),
    }

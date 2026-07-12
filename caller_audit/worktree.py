from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


def run(command: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"command failed: {' '.join(command)}\n"
            f"{result.stdout}\n{result.stderr}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare a detached fix-control worktree."
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--patch", required=True)
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    worktree = Path(args.worktree).resolve()
    patch = Path(args.patch).resolve()

    subprocess.run(
        ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if worktree.exists():
        shutil.rmtree(worktree)

    run([
        "git", "-C", str(repo), "worktree", "add",
        "--detach", str(worktree), args.commit,
    ])
    run(["git", "-C", str(worktree), "apply", "--check", str(patch)])
    run(["git", "-C", str(worktree), "apply", str(patch)])
    run([
        "git", "-C", str(worktree),
        "submodule", "update", "--init", "--recursive",
    ])
    print(f"[OK] prepared fix-control worktree: {worktree}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List


ROOT = Path("artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage")
RANKED_FILE = ROOT / "lua_app_search_ranked.txt"
OUT_DIR = ROOT / "lua_app_candidate_files"


def blob_to_raw(url: str) -> str:
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$", url)
    if not match:
        return url
    owner, repo, ref, path = match.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


def safe_filename(index: int, repo: str, path: str) -> str:
    owner_repo = repo.replace("/", "__")
    clean_path = path.strip("/").replace("/", "__")
    clean_path = re.sub(r"[^A-Za-z0-9_.-]+", "_", clean_path)
    if not clean_path.lower().endswith(".lua"):
        clean_path += ".lua"
    return f"{index:02d}_{owner_repo}__{clean_path}"


def read_top_candidates(limit: int = 20) -> List[Dict[str, str]]:
    if not RANKED_FILE.exists():
        return []
    rows: List[Dict[str, str]] = []
    lines = RANKED_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        rows.append(
            {
                "rank": parts[0],
                "score": parts[1],
                "repo": parts[2],
                "path": parts[3],
                "url": parts[4],
            }
        )
        if len(rows) >= limit:
            break
    return rows


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = read_top_candidates()
    if not rows:
        print(f"[WARN] no candidates in {RANKED_FILE}")
        return 0

    ok = 0
    for idx, row in enumerate(rows, 1):
        raw_url = blob_to_raw(row["url"])
        out_path = OUT_DIR / safe_filename(idx, row["repo"], row["path"])
        try:
            with urllib.request.urlopen(raw_url, timeout=30) as resp:
                data = resp.read()
            out_path.write_bytes(data)
            ok += 1
            print(f"[OK] {idx} {row['repo']} {row['path']} -> {out_path}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"[FAIL] {idx} {row['repo']} {row['path']} {raw_url}: {exc}")

    print(f"[SUMMARY] downloaded={ok} requested={len(rows)} out_dir={OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

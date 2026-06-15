#!/usr/bin/env python3
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


ROOT = Path("artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage")
SEARCH_DIR = ROOT / "lua_app_search"
OUT_FILE = ROOT / "lua_app_search_ranked.txt"

HIGH_KEYWORDS = [
    "auth",
    "token",
    "session",
    "verify",
    "sign",
    "signature",
    "cookie",
    "request",
    "server",
    "client",
    "jwt",
    "login",
    "role",
    "permission",
]
MEDIUM_KEYWORDS = [
    "mac.ctx",
    "openssl.mac",
    "update",
    "final",
    "hmac",
    "cmac",
]
LOW_KEYWORDS = [
    "example",
    "demo",
    "test",
    "doc",
]
EXCLUDE_PATH_PARTS = [
    "doc",
    "docs",
    "example",
    "examples",
    "test",
    "tests",
    "spec",
    "specs",
    "vendor",
    "vendors",
    "third_party",
    "README",
]
VENDORED_REPOS = {
    "zhaozg/lua-openssl",
    "brimworks/lua-openssl",
}


def repo_name(item: Dict[str, Any]) -> str:
    repo = item.get("repository", {})
    if isinstance(repo, dict):
        return str(repo.get("fullName") or repo.get("full_name") or repo.get("nameWithOwner") or "")
    return str(repo or "")


def load_json_file(path: Path) -> Tuple[List[Dict[str, Any]], str]:
    if not path.exists() or path.stat().st_size == 0:
        return [], "empty"
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return [], "empty"
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], f"bad_json:{exc}"

    if isinstance(obj, dict):
        if obj.get("message") or obj.get("documentation_url") or obj.get("errors"):
            return [], "github_error"
        if isinstance(obj.get("items"), list):
            obj = obj["items"]
        else:
            return [], "unexpected_dict"

    if not isinstance(obj, list):
        return [], "unexpected_json"

    rows = [x for x in obj if isinstance(x, dict)]
    return rows, "ok"


def is_excluded(repo: str, path: str) -> bool:
    if repo in VENDORED_REPOS:
        return True
    lower_path = path.lower()
    parts = re.split(r"[/_.-]+", lower_path)
    if any(part in EXCLUDE_PATH_PARTS for part in parts):
        return True
    if Path(path).name.lower().startswith("readme"):
        return True
    return False


def score_candidate(repo: str, path: str, url: str) -> Tuple[int, List[str]]:
    haystack = f"{repo} {path} {url}".lower()
    score = 0
    hits: List[str] = []
    for kw in HIGH_KEYWORDS:
        if kw in haystack:
            score += 10
            hits.append(f"high:{kw}")
    for kw in MEDIUM_KEYWORDS:
        if kw in haystack:
            score += 4
            hits.append(f"medium:{kw}")
    for kw in LOW_KEYWORDS:
        if kw in haystack:
            score -= 5
            hits.append(f"low:{kw}")
    return score, hits


def iter_candidates() -> Iterable[Tuple[str, str, str, str]]:
    for path in sorted(SEARCH_DIR.glob("*.json")):
        rows, status = load_json_file(path)
        if status != "ok":
            continue
        for item in rows:
            repo = repo_name(item)
            candidate_path = str(item.get("path") or "")
            url = str(item.get("url") or "")
            if repo and candidate_path and url:
                yield repo, candidate_path, url, path.name


def main() -> int:
    seen = set()
    ranked = []
    for repo, path, url, source_file in iter_candidates():
        key = (repo, path)
        if key in seen:
            continue
        seen.add(key)
        if is_excluded(repo, path):
            continue
        score, hits = score_candidate(repo, path, url)
        ranked.append(
            {
                "score": score,
                "repo": repo,
                "path": path,
                "url": url,
                "source_file": source_file,
                "hits": ",".join(hits),
            }
        )

    ranked.sort(key=lambda row: (-row["score"], row["repo"], row["path"]))
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUT_FILE.open("w", encoding="utf-8") as f:
        f.write("rank\tscore\trepo\tpath\turl\thits\tsource_file\n")
        for idx, row in enumerate(ranked[:50], 1):
            f.write(
                f"{idx}\t{row['score']}\t{row['repo']}\t{row['path']}\t"
                f"{row['url']}\t{row['hits']}\t{row['source_file']}\n"
            )

    print(f"[OK] ranked_candidates={min(len(ranked), 50)} total_after_filter={len(ranked)} out={OUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

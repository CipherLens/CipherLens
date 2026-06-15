#!/usr/bin/env python3
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


ROOT = Path("artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage")
SEARCH_DIR = ROOT / "lua_app_search_round2"
OUT_FILE = ROOT / "lua_app_search_round2_ranked.txt"

TARGET_TERMS = [
    "mac.ctx",
    "openssl.mac.ctx",
    "ctx:update",
    "ctx:final",
]
SECURITY_TERMS = [
    "auth",
    "token",
    "session",
    "signature",
    "verify",
    "cookie",
    "request",
    "server",
    "login",
    "role",
    "permission",
    "sign",
]
ASSOCIATED_TERMS = [
    "openssl.hmac",
    "openssl.digest",
    "hmac",
    "digest",
    "final",
]
LOW_VALUE_TERMS = [
    "test",
    "tests",
    "example",
    "examples",
    "doc",
    "docs",
    "readme",
]
VENDORED_OR_SELF_REPOS = {
    "zhaozg/lua-openssl",
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
    return [x for x in obj if isinstance(x, dict)], "ok"


def is_low_value_path(path: str) -> bool:
    lower = path.lower()
    parts = re.split(r"[/_.-]+", lower)
    return any(part in LOW_VALUE_TERMS for part in parts) or Path(path).name.lower().startswith("readme")


def is_excluded(repo: str, path: str) -> bool:
    if repo in VENDORED_OR_SELF_REPOS:
        return True
    lower_repo_path = f"{repo}/{path}".lower()
    if "lua-openssl/test" in lower_repo_path or "/3rd/lua-openssl/" in lower_repo_path:
        return True
    if is_low_value_path(path):
        return True
    return False


def score_candidate(repo: str, path: str, url: str) -> Tuple[int, List[str]]:
    haystack = f"{repo} {path} {url}".lower()
    score = 0
    hits: List[str] = []
    for term in TARGET_TERMS:
        if term in haystack:
            score += 30
            hits.append(f"target:{term}")
    for term in SECURITY_TERMS:
        if term in haystack:
            score += 12
            hits.append(f"security:{term}")
    for term in ASSOCIATED_TERMS:
        if term in haystack:
            score += 3
            hits.append(f"assoc:{term}")
    for term in LOW_VALUE_TERMS:
        if term in haystack:
            score -= 10
            hits.append(f"low:{term}")
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
                "hits": ",".join(hits),
                "source_file": source_file,
            }
        )
    ranked.sort(key=lambda row: (-row["score"], row["repo"], row["path"]))
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUT_FILE.open("w", encoding="utf-8") as f:
        f.write("rank\tscore\trepo\tpath\turl\thits\tsource_file\n")
        for idx, row in enumerate(ranked[:100], 1):
            f.write(
                f"{idx}\t{row['score']}\t{row['repo']}\t{row['path']}\t"
                f"{row['url']}\t{row['hits']}\t{row['source_file']}\n"
            )
    print(f"[OK] ranked={min(len(ranked), 100)} total_after_filter={len(ranked)} out={OUT_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import json
from pathlib import Path

ROOT = Path("artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/wide_search")

EXCLUDE_PATH_WORDS = [
    "openssl", "libressl", "boringssl",
    "doc/", "docs/", "man3", "man7", ".pod",
    "include/openssl", "test/", "tests/", "example", "examples",
    ".def", ".h", "cmac.c", "cmac.h"
]

HIGH_VALUE_WORDS = [
    "php_method", "pyobject", "python", "ruby", "node", "lua",
    "update", "digest", "final", "hash", "mac",
    "session", "auth", "verify", "token", "sign", "cookie",
    "parser", "request", "protocol", "server", "client"
]

records = {}

for jf in ROOT.glob("*.json"):
    raw = jf.read_text(errors="ignore").strip()
    if not raw:
        print(f"[skip empty] {jf}")
        continue

    try:
        data = json.loads(raw)
    except Exception as e:
        print(f"[skip bad json] {jf}: {e}")
        continue

    for item in data:
        repo = item["repository"]["nameWithOwner"]
        path = item["path"]
        url = item["url"]
        key = (repo, path)

        low_path = path.lower()
        if any(x in low_path for x in EXCLUDE_PATH_WORDS):
            continue

        score = 0
        why = []
        combined = f"{repo} {path}".lower()

        for w in HIGH_VALUE_WORDS:
            if w in combined:
                score += 1
                why.append(w)

        if any(x in combined for x in ["php", "pyobject", "python", "binding", "extension"]):
            score += 3
            why.append("language-binding")

        if any(x in combined for x in ["auth", "verify", "token", "session", "server", "client"]):
            score += 3
            why.append("security-boundary")

        if key not in records:
            records[key] = {
                "repo": repo,
                "path": path,
                "url": url,
                "score": 0,
                "sources": [],
                "why": set(),
            }

        records[key]["score"] += score
        records[key]["sources"].append(jf.name)
        records[key]["why"].update(why)

ranked = sorted(records.values(), key=lambda x: x["score"], reverse=True)

out = Path("artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/wide_search_ranked.txt")
with out.open("w") as f:
    for i, r in enumerate(ranked[:50], 1):
        f.write(f"[{i}] score={r['score']}\n")
        f.write(f"repo={r['repo']}\n")
        f.write(f"path={r['path']}\n")
        f.write(f"url={r['url']}\n")
        f.write(f"sources={','.join(r['sources'])}\n")
        f.write(f"why={','.join(sorted(r['why']))}\n\n")

print(f"ranked_candidates={len(ranked)}")
print(f"wrote {out}")
for i, r in enumerate(ranked[:20], 1):
    print(f"[{i}] score={r['score']} {r['repo']} {r['path']}")

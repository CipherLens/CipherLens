import re
import subprocess
from pathlib import Path

ranked = Path("artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/wide_search_ranked.txt")
outdir = Path("artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/wide_candidate_files")
outdir.mkdir(parents=True, exist_ok=True)

text = ranked.read_text(errors="ignore")
blocks = text.strip().split("\n\n")[:20]

def to_raw(url: str) -> str:
    # https://github.com/owner/repo/blob/commit/path
    # -> https://raw.githubusercontent.com/owner/repo/commit/path
    return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")

for idx, block in enumerate(blocks, 1):
    m_repo = re.search(r"repo=(.+)", block)
    m_path = re.search(r"path=(.+)", block)
    m_url = re.search(r"url=(.+)", block)
    if not (m_repo and m_path and m_url):
        continue

    repo = m_repo.group(1)
    path = m_path.group(1)
    url = m_url.group(1)
    raw = to_raw(url)

    safe = f"{idx:02d}_" + repo.replace("/", "__") + "__" + path.replace("/", "__")
    dest = outdir / safe

    print(f"[{idx}] downloading {repo}:{path}")
    subprocess.run(["curl", "-L", raw, "-o", str(dest)], check=False)

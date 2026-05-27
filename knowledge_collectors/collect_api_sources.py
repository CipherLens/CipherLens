import re
import yaml
from pathlib import Path
from typing import Dict, Any, List


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "libraries.yaml"
OUT_ROOT = PROJECT_ROOT / "knowledge_raw" / "api_constraints"


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def find_candidate_files(dirs: List[str]) -> List[Path]:
    exts = {".h", ".hpp", ".hh", ".c", ".cc", ".cpp", ".md", ".rst", ".pod", ".txt"}
    files = []

    for d in dirs:
        p = Path(d)
        if not p.exists():
            print(f"[!] Directory not found: {p}")
            continue

        for f in p.rglob("*"):
            if f.is_file() and f.suffix.lower() in exts:
                files.append(f)

    return files


def extract_snippets(text: str, keywords: List[str], window_before: int = 10, window_after: int = 18) -> List[str]:
    lines = text.splitlines()
    snippets = []

    for i, line in enumerate(lines):
        if not any(k in line for k in keywords):
            continue

        start = max(0, i - window_before)
        end = min(len(lines), i + window_after)

        block = "\n".join(lines[start:end]).strip()

        if block and block not in snippets:
            snippets.append(block)

    return snippets


def safe_name(path: Path) -> str:
    name = str(path)
    name = name.replace("/", "__")
    name = name.replace(":", "")
    return name[-180:]


def collect_for_library(lib_name: str, lib_cfg: Dict[str, Any]) -> None:
    out_dir = OUT_ROOT / lib_name
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_dirs = []
    scan_dirs.extend(lib_cfg.get("include_dirs", []))
    scan_dirs.extend(lib_cfg.get("source_dirs", []))

    keywords = lib_cfg.get("focus_keywords", [])
    version = lib_cfg.get("version", "")

    files = find_candidate_files(scan_dirs)
    print(f"[+] {lib_name}: found {len(files)} candidate source/header/doc files")

    written = 0
    snippet_total = 0

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"[!] Failed to read {f}: {e}")
            continue

        snippets = extract_snippets(text, keywords)

        if not snippets:
            continue

        out_path = out_dir / f"{safe_name(f)}.md"

        with out_path.open("w", encoding="utf-8") as out:
            out.write(f"# Official API knowledge snippets: {lib_name}\n\n")
            out.write(f"Library: {lib_name}\n")
            out.write(f"Version: {version}\n")
            out.write(f"Source file: {f}\n")
            out.write(f"Knowledge type: api_constraints\n\n")

            for idx, snip in enumerate(snippets, start=1):
                out.write(f"## Snippet {idx}\n\n")
                out.write("```c\n")
                out.write(snip)
                out.write("\n```\n\n")

        written += 1
        snippet_total += len(snippets)

    print(f"[+] {lib_name}: wrote {written} files, {snippet_total} snippets -> {out_dir}")


def main():
    cfg = load_config()
    libs = cfg.get("libraries", {})

    for lib_name, lib_cfg in libs.items():
        collect_for_library(lib_name, lib_cfg)


if __name__ == "__main__":
    main()

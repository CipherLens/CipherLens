import argparse
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml


PLACEHOLDER_PATTERN = re.compile(r"\[[A-Z0-9_]+\]")

IGNORED_BRACKET_TAGS = {
    "[OK]",
    "[BUG]",
    "[INFO]",
    "[WARN]",
    "[ERROR]",
    "[DIFF]",
    "[FAIL]",
    "[PASS]",
}


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def find_template_dirs(root: Path) -> List[Path]:
    return sorted(p.parent for p in root.rglob("template_meta.yaml"))


def value_to_code(value: Any) -> str:
    """
    Convert YAML default value to C/C++ source replacement text.
    Important:
    - string literals such as A_VALUE are already inside quotes in tmpl_*.c,
      so default "5" should become 5, not \"5\".
    - enum macros such as MBEDTLS_MD_SHA256 should remain raw identifiers.
    """
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def build_default_mapping(meta: Dict[str, Any]) -> Dict[str, str]:
    mapping = {}

    for mp in meta.get("mutation_points", []):
        placeholder = mp.get("placeholder")
        if not placeholder:
            continue

        if "default" not in mp:
            raise ValueError(f"mutation point missing default: {mp}")

        mapping[placeholder] = value_to_code(mp["default"])

    return mapping


def render_text(text: str, mapping: Dict[str, str]) -> str:
    rendered = text

    # Longer placeholders first, just in case.
    #
    # Important:
    #   We only replace bracketed placeholders when the "[" is not immediately
    #   preceded by an identifier character.
    #
    # Why:
    #   In C code, array declarations such as hash[HASH_LEN] are normal syntax,
    #   not mutation placeholders. A naive string replacement would turn
    #   hash[HASH_LEN] into hash32, which is invalid C.
    #
    # Example:
    #   #define HASH_LEN [HASH_LEN]  -> should become #define HASH_LEN 32
    #   unsigned char hash[HASH_LEN] -> should stay unsigned char hash[HASH_LEN]
    for ph in sorted(mapping.keys(), key=len, reverse=True):
        escaped = re.escape(ph)
        pattern = rf"(?<![A-Za-z0-9_]){escaped}"
        rendered = re.sub(pattern, mapping[ph], rendered)

    return rendered


def unresolved_placeholders(text: str) -> List[str]:
    """
    Return unresolved mutation placeholders.

    Important:
      C array syntax like hash[HASH_LEN] or sig[SIG_LEN] is not treated as a
      mutation placeholder, because the "[" is immediately preceded by an
      identifier character.
    """
    found = set()

    for m in PLACEHOLDER_PATTERN.finditer(text):
        start = m.start()
        tag = m.group(0)

        if tag in IGNORED_BRACKET_TAGS:
            continue

        if start > 0 and re.match(r"[A-Za-z0-9_]", text[start - 1]):
            continue

        found.add(tag)

    return sorted(found)


def output_name_for_template(template_file: Path, case_name: str) -> str:
    name = template_file.name

    if name.startswith("tmpl_"):
        name = name[len("tmpl_"):]

    return f"{case_name}_{name}"


def render_template_dir(template_dir: Path, root: Path, out_root: Path, case_name: str) -> List[Path]:
    meta_path = template_dir / "template_meta.yaml"
    meta = load_yaml(meta_path)
    mapping = build_default_mapping(meta)

    rel_dir = template_dir.relative_to(root)
    out_dir = out_root / rel_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    rendered_files = []

    template_files = sorted(list(template_dir.glob("tmpl_*.c")) + list(template_dir.glob("tmpl_*.cpp")))

    if not template_files:
        print(f"[WARN] no tmpl_*.c/cpp in {template_dir}")
        return rendered_files

    for tmpl in template_files:
        text = read_text(tmpl)
        rendered = render_text(text, mapping)

        unresolved = unresolved_placeholders(rendered)
        if unresolved:
            raise RuntimeError(
                f"Unresolved placeholders in {tmpl}: {unresolved}"
            )

        out_name = output_name_for_template(tmpl, case_name)
        out_path = out_dir / out_name
        write_text(out_path, rendered)
        rendered_files.append(out_path)

    # Also write a small render manifest.
    manifest = {
        "template_id": meta.get("template_id", ""),
        "template_dir": str(template_dir),
        "case_name": case_name,
        "mapping": mapping,
        "rendered_files": [str(p) for p in rendered_files],
    }

    with (out_dir / f"{case_name}_manifest.yaml").open("w", encoding="utf-8") as f:
        yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)

    print(f"[OK] rendered {template_dir} -> {out_dir}")
    return rendered_files


def main():
    parser = argparse.ArgumentParser(description="Render C/C++ template skeletons using default mutation values.")
    parser.add_argument(
        "--root",
        default="generated_templates",
        help="Template root. Default: generated_templates",
    )
    parser.add_argument(
        "--out-root",
        default="rendered_cases",
        help="Output root. Default: rendered_cases",
    )
    parser.add_argument(
        "--case-name",
        default="default",
        help="Case name prefix. Default: default",
    )

    args = parser.parse_args()

    root = Path(args.root)
    out_root = Path(args.out_root)

    if not root.exists():
        print(f"[ERROR] template root not found: {root}")
        return 1

    template_dirs = find_template_dirs(root)

    if not template_dirs:
        print(f"[ERROR] no template_meta.yaml found under {root}")
        return 1

    total_files = []

    for td in template_dirs:
        total_files.extend(render_template_dir(td, root, out_root, args.case_name))

    print()
    print("=" * 80)
    print(f"[SUMMARY] rendered template dirs: {len(template_dirs)}")
    print(f"[SUMMARY] rendered files: {len(total_files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Any

import yaml


REQUIRED_FILES = [
    "template_meta.yaml",
    "tmpl_mbedtls.c",
    "README.md",
    "poc_original.c",
]

REQUIRED_META_FIELDS = [
    "template_id",
    "backend",
    "status",
    "poc_source",
    "operation",
    "source_api",
    "mutation_points",
    "oracle",
    "verdict",
    "generation_policy",
]

PLACEHOLDER_PATTERN = re.compile(r"\[[A-Z0-9_]+\]")

# These bracketed strings are runtime log labels, not mutation placeholders.
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


class TemplateValidationError:
    def __init__(self, template_dir: Path, message: str):
        self.template_dir = template_dir
        self.message = message

    def __str__(self):
        return f"{self.template_dir}: {self.message}"


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a YAML mapping")

    return data


def find_template_dirs(root: Path) -> List[Path]:
    dirs = []

    for meta in root.rglob("template_meta.yaml"):
        dirs.append(meta.parent)

    return sorted(dirs)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def extract_placeholders_from_text(text: str) -> Set[str]:
    placeholders = set(PLACEHOLDER_PATTERN.findall(text))
    return placeholders - IGNORED_BRACKET_TAGS


def extract_placeholders_from_meta(meta: Dict[str, Any]) -> Set[str]:
    placeholders = set()

    for mp in meta.get("mutation_points", []):
        if not isinstance(mp, dict):
            continue

        ph = mp.get("placeholder")
        if isinstance(ph, str):
            placeholders.add(ph)

    return placeholders


def validate_required_files(template_dir: Path) -> List[TemplateValidationError]:
    errors = []

    for filename in REQUIRED_FILES:
        path = template_dir / filename
        if not path.exists():
            errors.append(TemplateValidationError(template_dir, f"missing required file: {filename}"))
        elif path.stat().st_size == 0:
            errors.append(TemplateValidationError(template_dir, f"empty required file: {filename}"))

    return errors


def validate_meta_fields(template_dir: Path, meta: Dict[str, Any]) -> List[TemplateValidationError]:
    errors = []

    for field in REQUIRED_META_FIELDS:
        if field not in meta:
            errors.append(TemplateValidationError(template_dir, f"missing required meta field: {field}"))

    if "mutation_points" in meta:
        if not isinstance(meta["mutation_points"], list) or not meta["mutation_points"]:
            errors.append(TemplateValidationError(template_dir, "mutation_points must be a non-empty list"))
        else:
            for idx, mp in enumerate(meta["mutation_points"]):
                if not isinstance(mp, dict):
                    errors.append(TemplateValidationError(template_dir, f"mutation_points[{idx}] must be a mapping"))
                    continue

                for key in ["name", "placeholder", "type", "default"]:
                    if key not in mp:
                        errors.append(
                            TemplateValidationError(
                                template_dir,
                                f"mutation_points[{idx}] missing field: {key}",
                            )
                        )

                ph = mp.get("placeholder")
                if isinstance(ph, str) and not PLACEHOLDER_PATTERN.fullmatch(ph):
                    errors.append(
                        TemplateValidationError(
                            template_dir,
                            f"mutation_points[{idx}] has invalid placeholder format: {ph}",
                        )
                    )

    if "poc_source" in meta:
        if not isinstance(meta["poc_source"], dict):
            errors.append(TemplateValidationError(template_dir, "poc_source must be a mapping"))
        else:
            for key in ["file", "library", "api"]:
                if key not in meta["poc_source"]:
                    errors.append(TemplateValidationError(template_dir, f"poc_source missing field: {key}"))

    if "operation" in meta:
        if not isinstance(meta["operation"], dict):
            errors.append(TemplateValidationError(template_dir, "operation must be a mapping"))
        else:
            for key in ["abstract", "api_family", "bug_class"]:
                if key not in meta["operation"]:
                    errors.append(TemplateValidationError(template_dir, f"operation missing field: {key}"))

    if "source_api" in meta:
        if not isinstance(meta["source_api"], dict):
            errors.append(TemplateValidationError(template_dir, "source_api must be a mapping"))
        else:
            for key in ["library", "function"]:
                if key not in meta["source_api"]:
                    errors.append(TemplateValidationError(template_dir, f"source_api missing field: {key}"))

    return errors


def validate_placeholders(template_dir: Path, meta: Dict[str, Any]) -> List[TemplateValidationError]:
    errors = []

    meta_placeholders = extract_placeholders_from_meta(meta)

    if not meta_placeholders:
        errors.append(TemplateValidationError(template_dir, "no placeholders declared in mutation_points"))
        return errors

    template_files = list(template_dir.glob("tmpl_*.c")) + list(template_dir.glob("tmpl_*.cpp"))

    if not template_files:
        errors.append(TemplateValidationError(template_dir, "no tmpl_*.c or tmpl_*.cpp file found"))
        return errors

    all_template_text = "\n".join(read_text(p) for p in template_files)
    code_placeholders = extract_placeholders_from_text(all_template_text)

    for ph in sorted(meta_placeholders):
        if ph not in code_placeholders:
            errors.append(
                TemplateValidationError(
                    template_dir,
                    f"placeholder declared in meta but not used in template code: {ph}",
                )
            )

    for ph in sorted(code_placeholders):
        if ph not in meta_placeholders:
            errors.append(
                TemplateValidationError(
                    template_dir,
                    f"placeholder used in template code but not declared in meta: {ph}",
                )
            )

    return errors


def validate_readme(template_dir: Path) -> List[TemplateValidationError]:
    errors = []
    path = template_dir / "README.md"

    if not path.exists():
        return errors

    text = read_text(path)

    required_keywords = [
        "Source",
        "API",
        "Vulnerability",
        "Oracle",
    ]

    for kw in required_keywords:
        if kw.lower() not in text.lower():
            errors.append(TemplateValidationError(template_dir, f"README.md missing keyword/section: {kw}"))

    return errors


def validate_template_dir(template_dir: Path) -> List[TemplateValidationError]:
    errors = []

    errors.extend(validate_required_files(template_dir))

    meta_path = template_dir / "template_meta.yaml"
    if not meta_path.exists() or meta_path.stat().st_size == 0:
        return errors

    try:
        meta = load_yaml(meta_path)
    except Exception as e:
        errors.append(TemplateValidationError(template_dir, f"failed to parse template_meta.yaml: {e}"))
        return errors

    errors.extend(validate_meta_fields(template_dir, meta))
    errors.extend(validate_placeholders(template_dir, meta))
    errors.extend(validate_readme(template_dir))

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate crypto-pattern-fuzz template directories.")
    parser.add_argument(
        "--root",
        type=str,
        default="templates",
        help="Template root directory. Default: templates",
    )
    args = parser.parse_args()

    root = Path(args.root)

    if not root.exists():
        print(f"[ERROR] template root not found: {root}")
        return 1

    template_dirs = find_template_dirs(root)

    if not template_dirs:
        print(f"[ERROR] no template_meta.yaml found under {root}")
        return 1

    print(f"[INFO] found {len(template_dirs)} template directories")

    all_errors: List[TemplateValidationError] = []
    template_ids = {}

    for td in template_dirs:
        meta_path = td / "template_meta.yaml"

        try:
            meta = load_yaml(meta_path)
            tid = meta.get("template_id")
            if tid:
                if tid in template_ids:
                    all_errors.append(
                        TemplateValidationError(td, f"duplicate template_id: {tid}, first seen at {template_ids[tid]}")
                    )
                else:
                    template_ids[tid] = td
        except Exception:
            pass

        errors = validate_template_dir(td)
        if errors:
            print(f"[FAIL] {td}")
            for e in errors:
                print(f"  - {e.message}")
            all_errors.extend(errors)
        else:
            print(f"[OK]   {td}")

    print()
    print("=" * 80)

    if all_errors:
        print(f"[SUMMARY] validation failed: {len(all_errors)} error(s)")
        return 1

    print("[SUMMARY] all templates passed validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())

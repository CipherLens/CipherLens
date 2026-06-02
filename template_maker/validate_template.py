import argparse
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Any

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


def load_optional_yaml(template_dir: Path, filename: str) -> Optional[Dict[str, Any]]:
    path = template_dir / filename
    if not path.exists():
        return None
    return load_yaml(path)


def as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def meta_source_api_function(meta: Dict[str, Any]) -> str:
    source_api = meta.get("source_api")
    if isinstance(source_api, dict):
        return str(source_api.get("function") or "")
    if isinstance(source_api, str):
        return source_api
    return str(meta.get("poc_source", {}).get("api") or "")


def meta_harness_family(meta: Dict[str, Any]) -> str:
    return str(meta.get("harness_family") or "")


def add_unique(items: List[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in items:
        items.append(text)


def meta_trigger_apis(meta: Dict[str, Any]) -> List[str]:
    apis: List[str] = []
    add_unique(apis, meta_source_api_function(meta))
    add_unique(apis, meta.get("source_api_name"))
    add_unique(apis, meta.get("poc_source", {}).get("api"))
    for api in as_list(meta.get("internal_apis")):
        add_unique(apis, api)
    return apis


def report_trigger_apis(*reports: Optional[Dict[str, Any]]) -> List[str]:
    apis: List[str] = []
    for report in reports:
        if not report:
            continue
        for api in as_list(report.get("trigger_apis")):
            add_unique(apis, api)
        add_unique(apis, report.get("source_api"))
    return apis


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


def validate_report_identity(
    template_dir: Path,
    filename: str,
    report: Dict[str, Any],
    meta: Dict[str, Any],
) -> List[TemplateValidationError]:
    errors: List[TemplateValidationError] = []
    template_id = meta.get("template_id", "")
    source_api = meta_source_api_function(meta)
    harness_family = meta_harness_family(meta)

    source_template_id = str(meta.get("source_template_id") or "")
    allowed_template_ids = {str(template_id)}
    if source_template_id:
        allowed_template_ids.add(source_template_id)

    if report.get("template_id") and str(report.get("template_id")) not in allowed_template_ids:
        errors.append(
            TemplateValidationError(
                template_dir,
                f"{filename} template_id mismatch: {report.get('template_id')} not in {sorted(allowed_template_ids)}",
            )
        )

    if report.get("source_api") and source_api and report.get("source_api") != source_api:
        errors.append(
            TemplateValidationError(
                template_dir,
                f"{filename} source_api mismatch: {report.get('source_api')} != {source_api}",
            )
        )

    report_family = str(report.get("harness_family") or "")
    if report_family and harness_family and report_family != harness_family:
        errors.append(
            TemplateValidationError(
                template_dir,
                f"{filename} harness_family mismatch: {report_family} != {harness_family}",
            )
        )

    return errors


def validate_trigger_api_consistency(
    template_dir: Path,
    meta: Dict[str, Any],
    reports: Iterable[Dict[str, Any]],
) -> List[TemplateValidationError]:
    errors: List[TemplateValidationError] = []
    expected = meta_trigger_apis(meta)
    observed = report_trigger_apis(*reports)

    # Keep legacy templates compatible: only enforce this when the new field exists
    # or the template has opted into a harness family.
    should_enforce = bool(meta_harness_family(meta) or any("trigger_apis" in r for r in reports if r))
    if not should_enforce:
        return errors

    if not observed:
        errors.append(TemplateValidationError(template_dir, "mask artifacts must expose non-empty trigger_apis"))
        return errors

    source_api = meta_source_api_function(meta)
    if source_api and source_api not in observed:
        errors.append(
            TemplateValidationError(
                template_dir,
                f"trigger_apis must include source_api: {source_api}",
            )
        )

    for api in expected:
        if api not in observed:
            errors.append(
                TemplateValidationError(
                    template_dir,
                    f"trigger_apis missing expected API from template_meta.yaml: {api}",
                )
            )

    return errors


def validate_mask_report(
    template_dir: Path,
    meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> List[TemplateValidationError]:
    errors: List[TemplateValidationError] = []
    errors.extend(validate_report_identity(template_dir, "mask_report.yaml", mask_report, meta))

    roles = mask_report.get("roles")
    if not isinstance(roles, dict):
        errors.append(TemplateValidationError(template_dir, "mask_report.yaml roles must be a mapping"))
        return errors

    for role in ["init", "input_construction", "trigger_call", "oracle", "cleanup", "other_context"]:
        if role not in roles:
            errors.append(TemplateValidationError(template_dir, f"mask_report.yaml roles missing key: {role}"))
        elif not isinstance(roles.get(role), list):
            errors.append(TemplateValidationError(template_dir, f"mask_report.yaml roles.{role} must be a list"))

    if isinstance(roles.get("trigger_call"), list) and not roles["trigger_call"]:
        errors.append(TemplateValidationError(template_dir, "mask_report.yaml roles.trigger_call must be non-empty"))

    if isinstance(roles.get("oracle"), list) and not roles["oracle"]:
        errors.append(TemplateValidationError(template_dir, "mask_report.yaml roles.oracle must be non-empty"))

    for role, items in roles.items():
        if not isinstance(items, list):
            continue
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                errors.append(TemplateValidationError(template_dir, f"mask_report.yaml roles.{role}[{idx}] must be a mapping"))
                continue
            if not item.get("code"):
                errors.append(TemplateValidationError(template_dir, f"mask_report.yaml roles.{role}[{idx}] missing code"))
            if "line_start" in item and "line_end" in item:
                try:
                    if int(item["line_start"]) > int(item["line_end"]):
                        errors.append(TemplateValidationError(template_dir, f"mask_report.yaml roles.{role}[{idx}] has invalid line range"))
                except Exception:
                    errors.append(TemplateValidationError(template_dir, f"mask_report.yaml roles.{role}[{idx}] line range must be numeric"))

    masking_levels = mask_report.get("masking_levels")
    if masking_levels is not None and not isinstance(masking_levels, dict):
        errors.append(TemplateValidationError(template_dir, "mask_report.yaml masking_levels must be a mapping"))

    return errors


def validate_ast_mask_report(
    template_dir: Path,
    meta: Dict[str, Any],
    ast_report: Dict[str, Any],
) -> List[TemplateValidationError]:
    errors: List[TemplateValidationError] = []
    errors.extend(validate_report_identity(template_dir, "ast_mask_report.yaml", ast_report, meta))

    units = ast_report.get("ast_mask_units")
    if not isinstance(units, list) or not units:
        errors.append(TemplateValidationError(template_dir, "ast_mask_report.yaml ast_mask_units must be a non-empty list"))
        return errors

    strict_ast_metadata = bool(ast_report.get("trigger_apis") or ast_report.get("harness_family"))
    roles = {str(unit.get("role", "")) for unit in units if isinstance(unit, dict)}
    for role in ["mutation_point", "trigger_call", "oracle"]:
        if role not in roles:
            errors.append(TemplateValidationError(template_dir, f"ast_mask_report.yaml missing role in ast_mask_units: {role}"))

    seen_ids: Set[str] = set()
    for idx, unit in enumerate(units):
        if not isinstance(unit, dict):
            errors.append(TemplateValidationError(template_dir, f"ast_mask_report.yaml ast_mask_units[{idx}] must be a mapping"))
            continue

        for key in ["unit_id", "mask_level", "role", "code", "source"]:
            if key not in unit or unit.get(key) in (None, ""):
                errors.append(TemplateValidationError(template_dir, f"ast_mask_report.yaml ast_mask_units[{idx}] missing field: {key}"))

        unit_id = str(unit.get("unit_id") or "")
        if unit_id:
            if unit_id in seen_ids:
                errors.append(TemplateValidationError(template_dir, f"ast_mask_report.yaml duplicate unit_id: {unit_id}"))
            seen_ids.add(unit_id)

        source = str(unit.get("source") or "")
        if strict_ast_metadata and source.startswith("tmpl_mbedtls.c"):
            for key in ["line_start", "line_end", "node_type"]:
                if key not in unit:
                    errors.append(TemplateValidationError(template_dir, f"ast_mask_report.yaml {unit_id or idx} missing {key}"))
        if "line_start" in unit and "line_end" in unit:
            try:
                if int(unit["line_start"]) > int(unit["line_end"]):
                    errors.append(TemplateValidationError(template_dir, f"ast_mask_report.yaml {unit_id or idx} has invalid line range"))
            except Exception:
                errors.append(TemplateValidationError(template_dir, f"ast_mask_report.yaml {unit_id or idx} line range must be numeric"))

    return errors


def validate_selected_mask_units(
    template_dir: Path,
    meta: Dict[str, Any],
    selected_report: Dict[str, Any],
    ast_report: Optional[Dict[str, Any]],
) -> List[TemplateValidationError]:
    errors: List[TemplateValidationError] = []
    errors.extend(validate_report_identity(template_dir, "selected_mask_units.yaml", selected_report, meta))

    selected = selected_report.get("selected_units")
    if not isinstance(selected, list) or not selected:
        errors.append(TemplateValidationError(template_dir, "selected_mask_units.yaml selected_units must be a non-empty list"))
        return errors

    policy = selected_report.get("selection_policy")
    if not isinstance(policy, dict):
        errors.append(TemplateValidationError(template_dir, "selected_mask_units.yaml selection_policy must be a mapping"))

    ast_ids = set()
    if ast_report and isinstance(ast_report.get("ast_mask_units"), list):
        ast_ids = {str(unit.get("unit_id")) for unit in ast_report["ast_mask_units"] if isinstance(unit, dict) and unit.get("unit_id")}

    suggested_uses = {str(unit.get("suggested_use", "")) for unit in selected if isinstance(unit, dict)}
    roles = {str(unit.get("role", "")) for unit in selected if isinstance(unit, dict)}

    if "migrate_api_call" not in suggested_uses:
        errors.append(TemplateValidationError(template_dir, "selected_mask_units.yaml must include suggested_use=migrate_api_call"))

    if "preserve_oracle" not in suggested_uses and "oracle" not in roles:
        errors.append(TemplateValidationError(template_dir, "selected_mask_units.yaml must include oracle/preserve_oracle context"))

    for idx, unit in enumerate(selected):
        if not isinstance(unit, dict):
            errors.append(TemplateValidationError(template_dir, f"selected_mask_units.yaml selected_units[{idx}] must be a mapping"))
            continue
        for key in ["unit_id", "mask_level", "role", "code", "source", "selection_reason", "suggested_use"]:
            if key not in unit or unit.get(key) in (None, ""):
                errors.append(TemplateValidationError(template_dir, f"selected_mask_units.yaml selected_units[{idx}] missing field: {key}"))
        unit_id = str(unit.get("unit_id") or "")
        if ast_ids and unit_id and unit_id not in ast_ids:
            errors.append(TemplateValidationError(template_dir, f"selected_mask_units.yaml references unknown ast unit_id: {unit_id}"))

    summary = selected_report.get("selection_summary")
    if isinstance(summary, dict) and summary.get("selected_count") not in (None, len(selected)):
        errors.append(
            TemplateValidationError(
                template_dir,
                f"selected_mask_units.yaml selection_summary.selected_count mismatch: {summary.get('selected_count')} != {len(selected)}",
            )
        )

    return errors


def validate_mask_artifacts(template_dir: Path, meta: Dict[str, Any]) -> List[TemplateValidationError]:
    errors: List[TemplateValidationError] = []
    loaded: Dict[str, Optional[Dict[str, Any]]] = {}

    for filename in ["mask_report.yaml", "ast_mask_report.yaml", "selected_mask_units.yaml"]:
        try:
            loaded[filename] = load_optional_yaml(template_dir, filename)
        except Exception as e:
            errors.append(TemplateValidationError(template_dir, f"failed to parse {filename}: {e}"))
            loaded[filename] = None

    mask_report = loaded.get("mask_report.yaml")
    ast_report = loaded.get("ast_mask_report.yaml")
    selected_report = loaded.get("selected_mask_units.yaml")

    if ast_report is not None and mask_report is None:
        errors.append(TemplateValidationError(template_dir, "ast_mask_report.yaml exists but mask_report.yaml is missing"))
    if selected_report is not None and ast_report is None:
        errors.append(TemplateValidationError(template_dir, "selected_mask_units.yaml exists but ast_mask_report.yaml is missing"))

    reports = [r for r in [mask_report, ast_report, selected_report] if r]
    if reports:
        errors.extend(validate_trigger_api_consistency(template_dir, meta, reports))

    if mask_report is not None:
        errors.extend(validate_mask_report(template_dir, meta, mask_report))
    if ast_report is not None:
        errors.extend(validate_ast_mask_report(template_dir, meta, ast_report))
    if selected_report is not None:
        errors.extend(validate_selected_mask_units(template_dir, meta, selected_report, ast_report))

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
    errors.extend(validate_mask_artifacts(template_dir, meta))

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

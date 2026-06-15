import argparse
import copy
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import yaml

from template_maker.mac_lifecycle_sequences import build_mac_lifecycle_plan


PLACEHOLDER_RE = re.compile(r"\[([A-Z0-9_]+)\]")
IGNORED_BRACKET_TAGS = {
    "[OK]",
    "[BUG]",
    "[INFO]",
    "[WARN]",
    "[ERROR]",
    "[TRIAGE]",
    "[SAFE]",
}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def discover_placeholders(template_root: Path) -> Set[str]:
    placeholders: Set[str] = set()
    for path in sorted(template_root.glob("tmpl_*")):
        if path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
            continue
        text = read_text(path)
        for match in PLACEHOLDER_RE.finditer(text):
            tag = f"[{match.group(1)}]"
            if tag in IGNORED_BRACKET_TAGS:
                continue
            if match.start() > 0 and re.match(r"[A-Za-z0-9_]", text[match.start() - 1]):
                continue
            placeholders.add(tag)
    return placeholders


def expected_size_for_digest(value: str) -> Tuple[Any, str]:
    normalized = value.upper().replace("_", "-")
    sizes = {
        "SHA256": 32,
        "SHA-256": 32,
        "SHA512": 64,
        "SHA-512": 64,
    }
    if normalized in sizes:
        return sizes[normalized], ""
    return None, "digest_or_cipher has no EXPECTED_MAC_SIZE mapping in current template"


def mutation_point(name: str, placeholder: str, value: Any, value_type: str, priority: str = "medium") -> Dict[str, Any]:
    return {
        "name": name,
        "placeholder": placeholder,
        "type": value_type,
        "default": value,
        "values": [value],
        "priority": priority,
    }


def map_case_to_mutation_points(
    matrix_case: Dict[str, Any],
    base_meta: Dict[str, Any],
    placeholders: Set[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    values = matrix_case.get("values", {}) or {}
    points: List[Dict[str, Any]] = []
    unsupported: List[Dict[str, Any]] = []
    mapped_values: Dict[str, Any] = {}

    mac_algorithm = str(values.get("mac_algorithm", "")).strip()
    digest_or_cipher = str(values.get("digest_or_cipher", "")).strip()
    lifecycle_sequence = str(values.get("lifecycle_sequence", "")).strip()

    if mac_algorithm:
        if "[MAC_NAME]" in placeholders:
            points.append(mutation_point("MAC_NAME", "[MAC_NAME]", mac_algorithm, "string", "high"))
            mapped_values["MAC_NAME"] = mac_algorithm
        else:
            unsupported.append({
                "dimension": "mac_algorithm",
                "value": mac_algorithm,
                "reason": "template has no [MAC_NAME] placeholder",
                "requires_template_or_recipe_extension": True,
            })

        if mac_algorithm != "HMAC":
            unsupported.append({
                "dimension": "mac_algorithm",
                "value": mac_algorithm,
                "reason": "target template is fixed to PSA_KEY_TYPE_HMAC and PSA_ALG_HMAC(PSA_ALG_SHA_256)",
                "requires_template_or_recipe_extension": True,
            })

    if digest_or_cipher:
        if digest_or_cipher.startswith("SHA"):
            if "[DIGEST_NAME]" in placeholders:
                points.append(mutation_point("DIGEST_NAME", "[DIGEST_NAME]", digest_or_cipher, "string", "high"))
                mapped_values["DIGEST_NAME"] = digest_or_cipher
            else:
                unsupported.append({
                    "dimension": "digest_or_cipher",
                    "value": digest_or_cipher,
                    "reason": "template has no [DIGEST_NAME] placeholder",
                    "requires_template_or_recipe_extension": True,
                })

            expected_size, reason = expected_size_for_digest(digest_or_cipher)
            if expected_size is not None and "[EXPECTED_MAC_SIZE]" in placeholders:
                points.append(mutation_point("EXPECTED_MAC_SIZE", "[EXPECTED_MAC_SIZE]", expected_size, "int", "high"))
                mapped_values["EXPECTED_MAC_SIZE"] = expected_size
            else:
                unsupported.append({
                    "dimension": "digest_or_cipher",
                    "value": digest_or_cipher,
                    "reason": reason or "template has no [EXPECTED_MAC_SIZE] placeholder",
                    "requires_template_or_recipe_extension": True,
                })

            if digest_or_cipher != "SHA256":
                unsupported.append({
                    "dimension": "digest_or_cipher",
                    "value": digest_or_cipher,
                    "reason": "target template is fixed to PSA_ALG_HMAC(PSA_ALG_SHA_256) and MAC_LEN=32",
                    "requires_template_or_recipe_extension": True,
                })
        else:
            unsupported.append({
                "dimension": "digest_or_cipher",
                "value": digest_or_cipher,
                "reason": "current MAC lifecycle template has digest placeholders, not cipher placeholders",
                "requires_template_or_recipe_extension": True,
            })

    if lifecycle_sequence:
        unsupported.append({
            "dimension": "lifecycle_sequence",
            "value": lifecycle_sequence,
            "reason": "current templates have fixed STATE_A/STATE_B lifecycle code and no lifecycle_sequence placeholder",
            "requires_template_or_recipe_extension": True,
        })

    base_points = {mp.get("placeholder"): mp for mp in base_meta.get("mutation_points", []) or [] if isinstance(mp, dict)}
    existing_placeholders = {mp.get("placeholder") for mp in points}
    for placeholder in ["[MAC_NAME]", "[DIGEST_NAME]", "[KEY_BYTES]", "[KEY_LEN]", "[EXPECTED_MAC_SIZE]"]:
        if placeholder in placeholders and placeholder in base_points:
            if placeholder in existing_placeholders:
                continue
            mp = copy.deepcopy(base_points[placeholder])
            values_list = mp.get("values", [])
            value = values_list[0] if isinstance(values_list, list) and values_list else mp.get("default")
            mp["default"] = value
            mp["values"] = [value]
            points.append(mp)
            mapped_values[str(mp.get("name") or placeholder.strip("[]"))] = value
            mapped_values[f"{str(mp.get('name') or placeholder.strip('[]'))}_mapping_note"] = (
                "base_default_used_because_render_matrix_dimension_is_unsupported_or_unmapped"
            )

    return points, unsupported, mapped_values


def map_case_to_mac_slot_points(
    matrix_case: Dict[str, Any],
    placeholders: Set[str],
) -> Tuple[bool, List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], List[str]]:
    values = matrix_case.get("values", {}) or {}
    mac_algorithm = str(values.get("mac_algorithm", "")).strip()
    digest_or_cipher = str(values.get("digest_or_cipher", "")).strip()
    lifecycle_sequence = str(values.get("lifecycle_sequence", "")).strip()

    plan = build_mac_lifecycle_plan(mac_algorithm, digest_or_cipher, lifecycle_sequence)
    if not plan.supported:
        return False, [], plan.unsupported_dimensions, {}, plan.expected_candidate_types

    slot_values: Dict[str, Any] = {}
    slot_values.update(plan.common_slots)
    slot_values.update(plan.source_slots)
    slot_values.update(plan.target_slots)

    points: List[Dict[str, Any]] = []
    mapped_values: Dict[str, Any] = {
        "mac_algorithm": mac_algorithm,
        "digest_or_cipher": digest_or_cipher,
        "lifecycle_sequence": lifecycle_sequence,
        "source_render_slots": plan.source_slots,
        "target_render_slots": plan.target_slots,
        "common_render_slots": plan.common_slots,
    }

    for name, value in sorted(slot_values.items()):
        placeholder = f"[{name}]"
        if placeholder not in placeholders:
            continue
        value_type = "c_code" if name.endswith("_SEQUENCE") or name.endswith("_PARAMS") else "string"
        if isinstance(value, int):
            value_type = "int"
        if name in {"KEY_BYTES", "MESSAGE_BYTES"}:
            value_type = "c_code"
        points.append(mutation_point(name, placeholder, value, value_type, "high"))

    missing_placeholders = sorted(
        placeholder
        for placeholder in placeholders
        if placeholder.startswith((
            "[SOURCE_",
            "[TARGET_",
            "[EXPECTED_",
            "[KEY_",
            "[MESSAGE_",
            "[MAC_",
        ))
        and placeholder not in {mp["placeholder"] for mp in points}
        and placeholder not in {"[MAC_NAME]"}
    )
    unsupported = [
        {
            "dimension": "template_placeholders",
            "value": ",".join(missing_placeholders),
            "reason": "framework-owned MAC slot plan did not provide all required placeholders",
            "requires_template_extension": True,
        }
    ] if missing_placeholders else []

    return not unsupported, points, unsupported, mapped_values, plan.expected_candidate_types


def copy_template_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def write_expanded_case(
    matrix_case: Dict[str, Any],
    base_meta: Dict[str, Any],
    cross_template_root: Path,
    out_dir: Path,
    placeholders: Set[str],
) -> Dict[str, Any]:
    use_mac_slots = "[SOURCE_LIFECYCLE_SEQUENCE]" in placeholders or "[TARGET_LIFECYCLE_SEQUENCE]" in placeholders
    if use_mac_slots:
        supported, mutation_points, unsupported, mapped_values, expected_candidate_types = map_case_to_mac_slot_points(
            matrix_case,
            placeholders,
        )
    else:
        supported = True
        mutation_points, unsupported, mapped_values = map_case_to_mutation_points(matrix_case, base_meta, placeholders)
        expected_candidate_types = matrix_case.get("expected_candidate_types", []) or []

    case_id = str(matrix_case.get("case_id") or out_dir.name)
    if not supported:
        values = matrix_case.get("values", {}) or {}
        return {
            "case_id": case_id,
            "mac_algorithm": values.get("mac_algorithm"),
            "digest_or_cipher": values.get("digest_or_cipher"),
            "lifecycle_sequence": values.get("lifecycle_sequence"),
            "expected_candidate_types": expected_candidate_types,
            "source_matrix_entry": matrix_case,
            "mapped_placeholders": mapped_values,
            "unsupported_dimensions": unsupported,
            "skipped": True,
            "skip_reason": "unsupported_combo_or_sequence",
        }

    copy_template_tree(cross_template_root, out_dir)

    meta = copy.deepcopy(base_meta)
    meta["template_id"] = f"{base_meta.get('template_id', 'TEMPLATE')}__{case_id}"
    meta["mutation_points"] = mutation_points
    meta["generation_policy"] = {
        "max_cases": 1,
        "priority": [mp.get("name") for mp in mutation_points],
    }
    meta["render_matrix_case"] = {
        "case_id": case_id,
        "source_matrix_entry": matrix_case,
        "mapped_values": mapped_values,
        "unsupported_dimensions": unsupported,
        "source_render_slots": mapped_values.get("source_render_slots", {}),
        "target_render_slots": mapped_values.get("target_render_slots", {}),
        "expected_candidate_types": expected_candidate_types,
    }
    dump_yaml(out_dir / "template_meta.yaml", meta)

    manifest = {
        "case_id": case_id,
        "mac_algorithm": (matrix_case.get("values", {}) or {}).get("mac_algorithm"),
        "digest_or_cipher": (matrix_case.get("values", {}) or {}).get("digest_or_cipher"),
        "lifecycle_sequence": (matrix_case.get("values", {}) or {}).get("lifecycle_sequence"),
        "expected_candidate_types": expected_candidate_types,
        "source_matrix_entry": matrix_case,
        "mapped_placeholders": mapped_values,
        "source_render_slots": mapped_values.get("source_render_slots", {}),
        "target_render_slots": mapped_values.get("target_render_slots", {}),
        "unsupported_dimensions": unsupported,
        "skipped": False,
    }
    dump_yaml(out_dir / "render_matrix_case_manifest.yaml", manifest)
    return manifest


def build_report(
    render_matrix: Dict[str, Any],
    render_matrix_path: Path,
    cross_template_root: Path,
    validated_adapter: Path,
    out_root: Path,
    placeholders: Set[str],
    manifests: List[Dict[str, Any]],
    skipped_manifests: List[Dict[str, Any]],
) -> Dict[str, Any]:
    unsupported_count = sum(1 for m in manifests if m.get("unsupported_dimensions"))
    unsupported_dimensions = sorted({
        item.get("dimension", "")
        for manifest in manifests + skipped_manifests
        for item in manifest.get("unsupported_dimensions", []) or []
        if item.get("dimension")
    })
    return {
        "render_matrix": str(render_matrix_path),
        "source_mutation_plan": str(render_matrix.get("source_mutation_plan", "")),
        "family": render_matrix.get("family", ""),
        "cross_template_root": str(cross_template_root),
        "validated_adapter": str(validated_adapter),
        "out_root": str(out_root),
        "current_template_placeholders": sorted(placeholders),
        "input_cases": len(manifests) + len(skipped_manifests),
        "expanded_cases": len(manifests),
        "skipped_cases": len(skipped_manifests),
        "cases_with_unsupported_dimensions": unsupported_count,
        "unsupported_dimensions": unsupported_dimensions,
        "render_cases_consumable": True,
        "render_cases_consumption_method": "expanded directories with per-case template_meta.yaml and max_cases=1",
        "notes": [
            "No C harness is generated by this adapter.",
            "C files are still rendered by template_maker/render_cases.py from existing tmpl_*.c files.",
            "Unsupported dimensions are recorded in each case manifest and not silently dropped.",
            "Unsupported MAC lifecycle combinations are skipped rather than rendered as bug candidates.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply render_matrix.yaml to an existing cross-template directory.")
    parser.add_argument("--render-matrix", required=True, type=Path)
    parser.add_argument("--cross-template-root", required=True, type=Path)
    parser.add_argument("--validated-adapter", required=True, type=Path)
    parser.add_argument("--out-root", required=True, type=Path)
    parser.add_argument("--max-cases", type=int, default=64)
    args = parser.parse_args()

    if not args.cross_template_root.exists():
        print(f"[ERROR] cross template root not found: {args.cross_template_root}")
        return 1
    if not args.validated_adapter.exists():
        print(f"[ERROR] validated adapter not found: {args.validated_adapter}")
        return 1

    render_matrix = load_yaml(args.render_matrix)
    base_meta = load_yaml(args.cross_template_root / "template_meta.yaml")
    placeholders = discover_placeholders(args.cross_template_root)
    matrix_cases = render_matrix.get("case_matrix", []) or []

    if args.out_root.exists():
        shutil.rmtree(args.out_root)
    args.out_root.mkdir(parents=True, exist_ok=True)

    manifests: List[Dict[str, Any]] = []
    skipped_manifests: List[Dict[str, Any]] = []
    template_id = str(base_meta.get("template_id") or "template")
    target_api = str(render_matrix.get("target_candidate", {}).get("target_api") or "target_api")

    for matrix_case in matrix_cases[:args.max_cases]:
        case_id = str(matrix_case.get("case_id") or f"case_{len(manifests):04d}")
        out_dir = args.out_root / template_id / target_api / case_id
        manifest = write_expanded_case(matrix_case, base_meta, args.cross_template_root, out_dir, placeholders)
        if manifest.get("skipped"):
            skipped_manifests.append(manifest)
        else:
            manifests.append(manifest)

    report = build_report(
        render_matrix,
        args.render_matrix,
        args.cross_template_root,
        args.validated_adapter,
        args.out_root,
        placeholders,
        manifests,
        skipped_manifests,
    )
    dump_yaml(args.out_root / "render_matrix_application_report.yaml", report)
    dump_yaml(args.out_root / "render_matrix_skipped_cases.yaml", {"skipped_cases": skipped_manifests})

    print(f"[OK] expanded cross templates written to {args.out_root}")
    print(f"[INFO] expanded_cases: {len(manifests)}")
    print(f"[INFO] skipped_cases: {len(skipped_manifests)}")
    print(f"[INFO] unsupported_dimensions: {report.get('unsupported_dimensions')}")
    print(f"[INFO] render_cases_consumable: {report.get('render_cases_consumable')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

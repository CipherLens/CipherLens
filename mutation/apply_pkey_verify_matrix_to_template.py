import argparse
import copy
import shutil
from pathlib import Path
from typing import Any, Dict, List

import yaml

from template_maker.pkey_verify_snippets import build_case_plan


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


def mutation_point(name: str, placeholder: str, value: Any, value_type: str = "string") -> Dict[str, Any]:
    return {
        "name": name,
        "placeholder": placeholder,
        "type": value_type,
        "default": value,
        "values": [value],
        "priority": "high",
    }


def value_type_for_placeholder(placeholder: str) -> str:
    if placeholder in {"[KEY_BITS]", "[HASH_LEN]", "[SIGNATURE_LEN]"}:
        return "int"
    if placeholder in {"[HASH_BYTES]", "[SIGNATURE_BYTES]", "[VERIFY_SETUP]", "[VERIFY_CALL]", "[VERIFY_ORACLE_OBSERVATION]"}:
        return "c_code"
    return "string"


def copy_template_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def case_manifest(case_id: str, matrix_case: Dict[str, Any], plan: Any, skipped: bool) -> Dict[str, Any]:
    values = plan.values
    return {
        "case_id": case_id,
        "verify_api": values.get("verify_api", ""),
        "key_type": values.get("key_type", ""),
        "signature_mutation": values.get("signature_mutation", ""),
        "digest_mutation": values.get("digest_mutation", ""),
        "key_mutation": values.get("key_mutation", ""),
        "padding_mutation": values.get("padding_mutation", ""),
        "expected_candidate_types": plan.expected_candidate_types,
        "unsupported_dimensions": plan.unsupported_dimensions,
        "unsupported_combo": bool(plan.unsupported_dimensions),
        "source_matrix_entry": matrix_case,
        "expected_verdict_class": plan.expected_verdict_class,
        "skipped": skipped,
        "skip_reason": "projection_limitation_requires_template_extension" if skipped else "",
    }


def write_case(
    matrix_case: Dict[str, Any],
    base_meta: Dict[str, Any],
    cross_template_root: Path,
    out_dir: Path,
) -> Dict[str, Any]:
    case_id = str(matrix_case.get("case_id") or out_dir.name)
    plan = build_case_plan(matrix_case)
    manifest = case_manifest(case_id, matrix_case, plan, skipped=not plan.supported)

    if not plan.supported:
        return manifest

    copy_template_tree(cross_template_root, out_dir)
    cross_mapping = load_yaml(out_dir / "cross_mapping.yaml")
    target = cross_mapping.get("target", {}) if isinstance(cross_mapping.get("target"), dict) else {}
    target["library"] = "openssl"
    target["api"] = plan.values.get("verify_api", "")
    target["candidate_api"] = plan.values.get("verify_api", "")
    cross_mapping["target"] = target
    dump_yaml(out_dir / "cross_mapping.yaml", cross_mapping)

    points = [
        mutation_point(name.strip("[]"), name, value, value_type_for_placeholder(name))
        for name, value in plan.placeholders.items()
    ]

    meta = copy.deepcopy(base_meta)
    meta["template_id"] = f"{base_meta.get('template_id', 'PKEY_VERIFY_SEMANTIC')}__{case_id}"
    meta.setdefault("source_api", {})
    meta["source_api"]["library"] = "openssl"
    meta["source_api"]["function"] = plan.values.get("verify_api", "")
    meta["target_library"] = "openssl"
    meta["target_api"] = plan.values.get("verify_api", "")
    meta["mutation_points"] = points
    meta["generation_policy"] = {
        "max_cases": 1,
        "priority": [point["name"] for point in points],
    }
    meta["render_matrix_case"] = {
        **manifest,
        "mapped_placeholders": plan.placeholders,
    }
    dump_yaml(out_dir / "template_meta.yaml", meta)
    dump_yaml(out_dir / "render_matrix_case_manifest.yaml", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply pkey_verify render_matrix.yaml to the controlled OpenSSL verify template.")
    parser.add_argument("--render-matrix", required=True, type=Path)
    parser.add_argument("--cross-template-root", required=True, type=Path)
    parser.add_argument("--out-root", required=True, type=Path)
    parser.add_argument("--max-cases", type=int, default=80)
    args = parser.parse_args()

    if not args.cross_template_root.exists():
        print(f"[ERROR] cross template root not found: {args.cross_template_root}")
        return 1

    render_matrix = load_yaml(args.render_matrix)
    base_meta = load_yaml(args.cross_template_root / "template_meta.yaml")
    matrix_cases = render_matrix.get("case_matrix", []) or []

    if args.out_root.exists():
        shutil.rmtree(args.out_root)
    args.out_root.mkdir(parents=True, exist_ok=True)

    manifests: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for matrix_case in matrix_cases[:args.max_cases]:
        case_id = str(matrix_case.get("case_id") or f"pkey_verify_{len(manifests) + len(skipped):04d}")
        out_dir = args.out_root / case_id
        manifest = write_case(matrix_case, base_meta, args.cross_template_root, out_dir)
        if manifest.get("skipped"):
            skipped.append(manifest)
        else:
            manifests.append(manifest)

    report = {
        "render_matrix": str(args.render_matrix),
        "cross_template_root": str(args.cross_template_root),
        "out_root": str(args.out_root),
        "input_cases": min(len(matrix_cases), args.max_cases),
        "expanded_cases": len(manifests),
        "skipped_cases": len(skipped),
        "projection_cases": len(skipped),
        "high_value_cases": sum(1 for case in matrix_cases[:args.max_cases] if case.get("high_value")),
        "manifest_fields": [
            "case_id",
            "verify_api",
            "key_type",
            "signature_mutation",
            "digest_mutation",
            "key_mutation",
            "padding_mutation",
            "expected_candidate_types",
            "unsupported_dimensions",
            "unsupported_combo",
            "source_matrix_entry",
            "expected_verdict_class",
        ],
        "render_cases_consumable": True,
        "notes": [
            "No discovery harness is handwritten by this adapter.",
            "C code snippets are selected from template_maker.pkey_verify_snippets.",
            "Unsupported combinations are recorded and skipped rather than silently dropped.",
        ],
    }
    dump_yaml(args.out_root / "render_matrix_application_report.yaml", report)
    dump_yaml(args.out_root / "render_matrix_skipped_cases.yaml", {"skipped_cases": skipped})

    print(f"[OK] expanded pkey verify templates written to {args.out_root}")
    print(f"[INFO] input_cases: {report['input_cases']}")
    print(f"[INFO] expanded_cases: {report['expanded_cases']}")
    print(f"[INFO] skipped_cases: {report['skipped_cases']}")
    print(f"[INFO] high_value_cases: {report['high_value_cases']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

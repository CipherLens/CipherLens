import argparse
import copy
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


SAFE_VALUES = {
    "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER": {
        "VALUE": [-1, -2, -15, -255, 0, 1, 255],
        "RADIX": [2, 10, 16],
        "BUFLEN": [0, 1, 2, 3, 4, 8, 16, 32],
        "CANARY_SIZE": [8, 16, 32],
    },
    "BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY": {
        "A_VALUE": ["0", "1", "3", "5", "15", "255"],
        "B_VALUE": [
            "100000000",
            "123456789abcdef01",
            "ffffffffffffffff",
            "ffffffffffffffffffffffff",
            "deadbeefdeadbeef",
        ],
        "A_BASE": [10, 16],
        "B_BASE": [16, 10],
        "X_LIMB_COUNT": [1, 2, 3, 4],
        "CANARY_SIZE": [8, 16, 32],
    },
    "PK_VERIFY_EXT_OPAQUE_RSA_PSS_NULL_DEREF": {
        "KEY_BITS": [1024, 2048],
        "HASH_LEN": [20, 32, 48, 64],
        "SIG_LEN": [128, 256],
        "MD_ALG": ["MBEDTLS_MD_SHA256", "MBEDTLS_MD_SHA384", "MBEDTLS_MD_SHA512"],
        "PK_VERIFY_TYPE": ["MBEDTLS_PK_RSASSA_PSS", "MBEDTLS_PK_RSA"],
        "EXPECTED_SALT_LEN": ["MBEDTLS_RSA_SALT_LEN_ANY"],
    },
}


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def find_template_dirs(root: Path) -> List[Path]:
    return sorted(p.parent for p in root.rglob("template_meta.yaml"))


def normalize_scalar(v: Any, expected_sample: Any) -> Any:
    if isinstance(expected_sample, int):
        try:
            return int(v)
        except Exception:
            return None

    if isinstance(expected_sample, str):
        return str(v)

    return v


def normalize_values(template_id: str, mp: Dict[str, Any]) -> Dict[str, Any]:
    name = mp.get("name")
    safe_map = SAFE_VALUES.get(template_id, {})

    if name not in safe_map:
        return mp

    safe_values = safe_map[name]
    current_values = mp.get("values", [])

    if not isinstance(current_values, list):
        current_values = []

    expected_sample = safe_values[0] if safe_values else None

    normalized_current = []
    for v in current_values:
        nv = normalize_scalar(v, expected_sample)
        if nv is not None:
            normalized_current.append(nv)

    # 只保留 safe_values 白名单内的值，防止 LLM 过度生成。
    filtered = []
    for v in normalized_current:
        if v in safe_values and v not in filtered:
            filtered.append(v)

    # 如果 LLM 没给全，把安全白名单补进去，保证边界覆盖。
    for v in safe_values:
        if v not in filtered:
            filtered.append(v)

    new_mp = copy.deepcopy(mp)
    new_mp["values"] = filtered

    if "constraint" not in new_mp or not new_mp["constraint"]:
        new_mp["constraint"] = "Values are normalized by project-side safety rules."

    new_mp["normalized"] = True

    return new_mp


def normalize_template_dir(template_dir: Path, root: Path, out_root: Path) -> Path:
    meta_path = template_dir / "template_meta.yaml"
    meta = load_yaml(meta_path)

    template_id = meta.get("template_id", "")
    new_meta = copy.deepcopy(meta)

    report = {
        "template_id": template_id,
        "normalizations": [],
    }

    new_points = []
    for mp in new_meta.get("mutation_points", []):
        before = copy.deepcopy(mp)
        after = normalize_values(template_id, mp)
        new_points.append(after)

        if before.get("values") != after.get("values"):
            report["normalizations"].append({
                "name": mp.get("name"),
                "before": before.get("values"),
                "after": after.get("values"),
            })

    new_meta["mutation_points"] = new_points
    new_meta["status"] = "normalized"
    new_meta.setdefault("normalization", {})
    new_meta["normalization"]["enabled"] = True
    new_meta["normalization"]["policy"] = "template_id_specific_safe_whitelist"

    rel = template_dir.relative_to(root)
    out_dir = out_root / rel
    out_dir.mkdir(parents=True, exist_ok=True)

    for p in template_dir.iterdir():
        if p.is_file() and p.name != "template_meta.yaml":
            shutil.copy2(p, out_dir / p.name)

    dump_yaml(out_dir / "template_meta.yaml", new_meta)

    with (out_dir / "normalization_report.json").open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"[OK] normalized {template_dir} -> {out_dir}")
    return out_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize LLM-enriched template metadata.")
    parser.add_argument("--root", default="enriched_templates")
    parser.add_argument("--out-root", default="normalized_templates")
    args = parser.parse_args()

    root = Path(args.root)
    out_root = Path(args.out_root)

    if not root.exists():
        print(f"[ERROR] root not found: {root}")
        return 1

    if out_root.exists():
        shutil.rmtree(out_root)

    template_dirs = find_template_dirs(root)
    if not template_dirs:
        print(f"[ERROR] no template_meta.yaml found under {root}")
        return 1

    for td in template_dirs:
        normalize_template_dir(td, root, out_root)

    print("=" * 80)
    print(f"[SUMMARY] normalized templates: {len(template_dirs)}")
    print(f"[SUMMARY] output root: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

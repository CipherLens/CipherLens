import argparse
import ast
import itertools
import re
import shutil
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
    "[TRIAGE]",
    "[SAFE]",
    "[VERDICT]",
    "[WARNING]",
}


PRIORITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def find_template_dirs(root: Path) -> List[Path]:
    return sorted(p.parent for p in root.rglob("template_meta.yaml"))


def bytes_to_c_initializer(data: bytes) -> str:
    if not data:
        return "{ }"

    chunks = [f"0x{b:02x}" for b in data]
    lines = []
    for i in range(0, len(chunks), 12):
        lines.append("    " + ", ".join(chunks[i:i + 12]))
    return "{\n" + ",\n".join(lines) + "\n}"


def byte_array_to_code(value: Any) -> str:
    if isinstance(value, bytes):
        return bytes_to_c_initializer(value)

    text = str(value)
    stripped = text.strip()

    if stripped.startswith("{") and stripped.endswith("}") and "\x00" not in stripped:
        return stripped

    if stripped.startswith(("\"", "'")):
        try:
            decoded = ast.literal_eval(stripped)
        except (SyntaxError, ValueError):
            decoded = text
    else:
        decoded = text

    if isinstance(decoded, bytes):
        data = decoded
    else:
        data = str(decoded).encode("utf-8")

    return bytes_to_c_initializer(data)


def value_to_code(value: Any, value_type: str = "") -> str:
    if value_type == "byte_array":
        return byte_array_to_code(value)
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def render_text(text: str, mapping: Dict[str, str]) -> str:
    rendered = text

    for ph in sorted(mapping.keys(), key=len, reverse=True):
        # Allow hex-byte placeholders in C tokens such as 0x[PADDING_BYTE].
        # The generic replacement below intentionally avoids array syntax like
        # buf[LEN], so handle the explicit numeric-token form first.
        rendered = rendered.replace(f"0x{ph}", f"0x{mapping[ph]}")

        escaped = re.escape(ph)
        pattern = rf"(?<![A-Za-z0-9_]){escaped}"
        rendered = re.sub(pattern, lambda _m, value=mapping[ph]: value, rendered)

    return rendered


def unresolved_placeholders(text: str) -> List[str]:
    found = set()

    for m in PLACEHOLDER_PATTERN.finditer(text):
        start = m.start()
        tag = m.group(0)

        if tag in IGNORED_BRACKET_TAGS:
            continue

        # Do not treat C array syntax such as hash[HASH_LEN] as a mutation placeholder.
        if start > 0 and re.match(r"[A-Za-z0-9_]", text[start - 1]):
            continue

        found.add(tag)

    return sorted(found)


def get_template_files(template_dir: Path) -> List[Path]:
    return sorted(
        list(template_dir.glob("tmpl_*.c")) +
        list(template_dir.glob("tmpl_*.cpp")) +
        list(template_dir.glob("tmpl_*.cc")) +
        list(template_dir.glob("tmpl_*.cxx"))
    )


def copy_metadata_files(template_dir: Path, out_dir: Path) -> None:
    metadata_names = [
        "template_meta.yaml",
        "cross_mapping.yaml",
        "adapter_meta.yaml",
        "mask_report.yaml",
        "ast_mask_report.yaml",
        "selected_mask_units.yaml",
        "README.md",
    ]
    for name in metadata_names:
        src = template_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)


def output_name_for_template(template_file: Path, case_id: str) -> str:
    name = template_file.name
    if name.startswith("tmpl_"):
        name = name[len("tmpl_"):]
    return f"{case_id}_{name}"


def sorted_mutation_points(meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    points = list(meta.get("mutation_points", []))

    # Low priority first, high priority last.
    # itertools.product changes the last dimension fastest, so high-priority
    # mutation points get more variation in early truncated cases.
    points.sort(key=lambda mp: PRIORITY_RANK.get(str(mp.get("priority", "medium")).lower(), 1))

    return points


def build_value_lists(meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    points = sorted_mutation_points(meta)
    value_lists = []

    for mp in points:
        ph = mp.get("placeholder")
        name = mp.get("name")
        values = mp.get("values")

        if not values:
            values = [mp.get("default")]

        if not isinstance(values, list):
            values = [values]

        value_lists.append({
            "name": name,
            "placeholder": ph,
            "type": mp.get("type", ""),
            "values": values,
            "priority": mp.get("priority", "medium"),
        })

    return value_lists


def is_decimal_string(v: Any) -> bool:
    s = str(v)
    if s.startswith(("+", "-")):
        s = s[1:]
    return s.isdigit()


def is_hex_string(v: Any) -> bool:
    s = str(v).lower()
    if s.startswith("0x"):
        s = s[2:]
    return bool(s) and all(c in "0123456789abcdef" for c in s)


def parse_int_or_none(v: Any) -> int | None:
    try:
        return int(v)
    except Exception:
        return None


def hex_byte_len_or_none(v: Any) -> int | None:
    s = str(v or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = "".join(s.split())
    if not s or len(s) % 2 != 0:
        return None
    if not all(c in "0123456789abcdef" for c in s):
        return None
    return len(s) // 2


def is_valid_case(template_id: str, raw_values: Dict[str, Any]) -> bool:
    """
    Project-side constraint filtering.

    This prevents obviously invalid generated samples from reaching compile/run.
    LLM may propose broad values, but final test cases must satisfy basic API
    construction constraints.
    """
    if template_id.startswith("BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY"):
        a_base = parse_int_or_none(raw_values.get("A_BASE", 10))
        b_base = parse_int_or_none(raw_values.get("B_BASE", 16))
        a_value = raw_values.get("A_VALUE", "")
        b_value = raw_values.get("B_VALUE", "")

        if a_base == 10 and not is_decimal_string(a_value):
            return False
        if a_base == 16 and not is_hex_string(a_value):
            return False

        if b_base == 10 and not is_decimal_string(b_value):
            return False
        if b_base == 16 and not is_hex_string(b_value):
            return False

        if a_base not in (10, 16):
            return False
        if b_base not in (10, 16):
            return False

        return True

    if template_id == "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER":
        radix = parse_int_or_none(raw_values.get("RADIX", 10))
        buflen = parse_int_or_none(raw_values.get("BUFLEN", 0))
        canary_size = parse_int_or_none(raw_values.get("CANARY_SIZE", 16))

        if radix not in (2, 10, 16):
            return False
        if buflen is None or buflen < 0:
            return False
        if canary_size is None or canary_size <= 0:
            return False

        return True

    if template_id.startswith("RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE"):
        der_kind = str(raw_values.get("DER_KIND", "")).strip().lower()
        trailing_bytes = raw_values.get("TRAILING_GARBAGE_BYTES")
        trailing_len = parse_int_or_none(raw_values.get("TRAILING_GARBAGE_LEN"))
        decoded_len = hex_byte_len_or_none(trailing_bytes)

        template_id_lower = template_id.lower()
        if "d2i_rsaprivatekey" in template_id_lower and der_kind != "private":
            return False
        if "d2i_privatekey" in template_id_lower and der_kind != "private":
            return False
        if "d2i_rsa_pubkey" in template_id_lower and der_kind != "public":
            return False

        if decoded_len is None or trailing_len is None:
            return False
        if decoded_len != trailing_len:
            return False

        return True

    return True


def generate_case_mappings(meta: Dict[str, Any], max_cases: int) -> List[Dict[str, Any]]:
    value_lists = build_value_lists(meta)

    if not value_lists:
        return []

    template_id = meta.get("template_id", "")

    keys = [x["placeholder"] for x in value_lists]
    names = [x["name"] for x in value_lists]
    values_product = itertools.product(*[x["values"] for x in value_lists])

    cases = []
    seen = set()
    skipped_invalid = 0

    for vals in values_product:
        types = [x.get("type", "") for x in value_lists]
        mapping = {ph: value_to_code(v, value_type) for ph, v, value_type in zip(keys, vals, types)}
        raw_values = {name: v for name, v in zip(names, vals)}

        if not is_valid_case(template_id, raw_values):
            skipped_invalid += 1
            continue

        key = tuple(mapping.items())
        if key in seen:
            continue
        seen.add(key)

        cases.append({
            "mapping": mapping,
            "raw_values": raw_values,
        })

        if len(cases) >= max_cases:
            break

    if skipped_invalid:
        print(f"[INFO] skipped invalid cases for {template_id}: {skipped_invalid}")

    return cases


def render_template_dir(template_dir: Path, root: Path, out_root: Path, global_max_cases: int) -> int:
    meta = load_yaml(template_dir / "template_meta.yaml")
    template_id = meta.get("template_id", "")

    max_cases = int(meta.get("generation_policy", {}).get("max_cases", global_max_cases))
    max_cases = min(max_cases, global_max_cases)

    case_mappings = generate_case_mappings(meta, max_cases)
    template_files = get_template_files(template_dir)

    if not template_files:
        print(f"[WARN] no template files found: {template_dir}")
        return 0

    rel_dir = template_dir.relative_to(root)
    out_dir = out_root / rel_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    copy_metadata_files(template_dir, out_dir)

    count = 0

    for idx, case in enumerate(case_mappings):
        case_id = f"case_{idx:04d}"
        mapping = case["mapping"]

        rendered_files = []

        for tmpl in template_files:
            text = read_text(tmpl)
            rendered = render_text(text, mapping)

            unresolved = unresolved_placeholders(rendered)
            if unresolved:
                raise RuntimeError(f"Unresolved placeholders in {tmpl}: {unresolved}")

            out_name = output_name_for_template(tmpl, case_id)
            out_path = out_dir / out_name
            write_text(out_path, rendered)
            rendered_files.append(str(out_path))

        manifest = {
            "template_id": template_id,
            "template_dir": str(template_dir),
            "case_id": case_id,
            "mapping": mapping,
            "raw_values": case["raw_values"],
            "rendered_files": rendered_files,
        }

        with (out_dir / f"{case_id}_manifest.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)

        count += len(rendered_files)

    print(f"[OK] rendered {len(case_mappings)} cases from {template_dir} -> {out_dir}")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Render multiple C/C++ cases from normalized template values.")
    parser.add_argument("--root", default="normalized_templates", help="Input template root.")
    parser.add_argument("--out-root", default="rendered_cases_batch", help="Output root.")
    parser.add_argument("--max-cases", type=int, default=64, help="Global maximum cases per template.")
    args = parser.parse_args()

    root = Path(args.root)
    out_root = Path(args.out_root)

    if not root.exists():
        print(f"[ERROR] template root not found: {root}")
        return 1

    if out_root.exists():
        shutil.rmtree(out_root)

    template_dirs = find_template_dirs(root)
    if not template_dirs:
        print(f"[ERROR] no template_meta.yaml found under {root}")
        return 1

    total_files = 0
    for td in template_dirs:
        total_files += render_template_dir(td, root, out_root, args.max_cases)

    print("=" * 80)
    print(f"[SUMMARY] template dirs: {len(template_dirs)}")
    print(f"[SUMMARY] rendered source files: {total_files}")
    print(f"[SUMMARY] output root: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

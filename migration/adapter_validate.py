import argparse
import copy
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml


STANDARD_FIELDS = [
    "target_library",
    "target_api",
    "applicability",
    "include_headers",
    "type_mapping",
    "constant_mapping",
    "init_block",
    "input_construction_block",
    "trigger_block",
    "return_value_semantics",
    "oracle_strategy",
    "cleanup_block",
    "preserved_features",
    "lost_or_weakened_features",
    "notes",
]

EXECUTABLE_BLOCK_FIELDS = [
    "init_block",
    "input_construction_block",
    "trigger_block",
    "cleanup_block",
]

DESCRIPTIVE_BLOCK_FIELDS = [
    "oracle_strategy",
    "notes",
    "return_value_semantics",
]

FORBIDDEN_PATTERNS = [
    "malloc(",
    "free(buf)",
    "unsigned char *buf",
    "char *buf",
    "&tolen",
    "abs(VALUE)",
    "[VALUE]",
    "[BUFLEN]",
    "return;",
]

OPENSSL_FORBIDDEN_EXECUTABLE_PATTERNS = [
    "mbedtls_",
    "mbedtls_mpi",
    "X->",
    "->mpi",
    "->p",
    "->n",
    "->s",
]

OPENSSL_INIT_BLOCK = "X = BN_new();"

OPENSSL_INPUT_CONSTRUCTION = (
    "BN_set_word(X, magnitude);\n"
    "if (signed_value < 0) { BN_set_negative(X, 1); }"
)

OPENSSL_CLEANUP_BLOCK = "BN_clear_free(X);"

OPENSSL_TRIGGER_BY_API = {
    "BN_bn2binpad": "ret = BN_bn2binpad(X, buf, BUFLEN);",
    "BN_signed_bn2bin": "ret = BN_signed_bn2bin(X, buf, BUFLEN);",
}


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}
    if not isinstance(obj, dict):
        return {}
    return obj


def dump_yaml(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(obj, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)


def strip_code_fence(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ensure_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def iter_string_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_string_values(item)


def find_required_output_schema(obj: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    if isinstance(obj.get("adapter"), dict):
        adapter_obj = obj["adapter"]
        schema = adapter_obj.get("required_output_schema")
        if isinstance(schema, dict):
            return schema, True

    schema = obj.get("required_output_schema")
    if isinstance(schema, dict):
        return schema, True

    return obj, False


def infer_missing_target(adapter: Dict[str, Any], original: Dict[str, Any]) -> None:
    if adapter.get("target_library") and adapter.get("target_api"):
        return

    wrapped = original.get("adapter")
    candidate = wrapped.get("candidate") if isinstance(wrapped, dict) else None
    if not isinstance(candidate, dict):
        candidate = original.get("candidate")
    if not isinstance(candidate, dict):
        return

    adapter.setdefault("target_library", candidate.get("library", ""))
    adapter.setdefault("target_api", candidate.get("api", ""))


def build_standard_adapter(raw: Dict[str, Any], original: Dict[str, Any]) -> Dict[str, Any]:
    adapter: Dict[str, Any] = {}

    for field in STANDARD_FIELDS:
        adapter[field] = copy.deepcopy(raw.get(field))

    infer_missing_target(adapter, original)

    adapter["target_library"] = str(adapter.get("target_library") or "")
    adapter["target_api"] = str(adapter.get("target_api") or "")
    adapter["applicability"] = str(adapter.get("applicability") or "needs_review")
    adapter["include_headers"] = [str(x) for x in ensure_list(adapter.get("include_headers")) if str(x).strip()]
    adapter["type_mapping"] = ensure_dict(adapter.get("type_mapping"))
    adapter["constant_mapping"] = ensure_dict(adapter.get("constant_mapping"))
    adapter["init_block"] = strip_code_fence(adapter.get("init_block"))
    adapter["input_construction_block"] = strip_code_fence(adapter.get("input_construction_block"))
    adapter["trigger_block"] = strip_code_fence(adapter.get("trigger_block"))
    adapter["return_value_semantics"] = str(adapter.get("return_value_semantics") or "")
    adapter["oracle_strategy"] = adapter.get("oracle_strategy") or {}
    adapter["cleanup_block"] = strip_code_fence(adapter.get("cleanup_block"))
    adapter["preserved_features"] = ensure_list(adapter.get("preserved_features"))
    adapter["lost_or_weakened_features"] = ensure_list(adapter.get("lost_or_weakened_features"))
    adapter["notes"] = ensure_list(adapter.get("notes"))

    for key, value in original.items():
        if key.startswith("_") and key not in adapter and key != "_llm_raw_preview":
            adapter[key] = copy.deepcopy(value)

    return adapter


def normalize_placeholder_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {}
    for key, value in mapping.items():
        clean_key = str(key).replace("[VALUE]", "VALUE").replace("[BUFLEN]", "BUFLEN")
        if isinstance(value, str):
            clean_value = value.replace("[VALUE]", "VALUE").replace("[BUFLEN]", "BUFLEN")
        else:
            clean_value = value
        normalized[clean_key] = clean_value
    return normalized


def normalize_openssl(adapter: Dict[str, Any], warnings: List[str]) -> None:
    headers = []
    for header in adapter.get("include_headers", []):
        normalized = "openssl/bn.h" if str(header).strip() == "openssl/BN.h" else str(header).strip()
        if normalized and normalized not in headers:
            headers.append(normalized)
    adapter["include_headers"] = headers

    target_library = adapter.get("target_library")
    target_api = adapter.get("target_api")
    if target_library != "openssl" or target_api not in OPENSSL_TRIGGER_BY_API:
        return

    init_block = strip_code_fence(adapter.get("init_block"))
    if init_block != OPENSSL_INIT_BLOCK:
        warnings.append("normalized OpenSSL init_block to remove source-library mbedTLS initialization")
    adapter["init_block"] = OPENSSL_INIT_BLOCK

    input_block = strip_code_fence(adapter.get("input_construction_block"))
    if input_block != OPENSSL_INPUT_CONSTRUCTION:
        warnings.append(f"normalized input_construction_block for OpenSSL {target_api}")
    adapter["input_construction_block"] = OPENSSL_INPUT_CONSTRUCTION

    trigger = strip_code_fence(adapter.get("trigger_block"))
    trigger = re.sub(r"^\s*int\s+ret\s*=", "ret =", trigger)
    expected = OPENSSL_TRIGGER_BY_API[target_api]

    if trigger != expected:
        warnings.append(f"normalized trigger_block for OpenSSL {target_api}")
    adapter["trigger_block"] = expected

    cleanup_block = strip_code_fence(adapter.get("cleanup_block"))
    if cleanup_block != OPENSSL_CLEANUP_BLOCK:
        warnings.append(f"normalized cleanup_block for OpenSSL {target_api}")
    adapter["cleanup_block"] = OPENSSL_CLEANUP_BLOCK


def validate_required_fields(adapter: Dict[str, Any], errors: List[str]) -> None:
    for field in STANDARD_FIELDS:
        if field not in adapter:
            errors.append(f"missing required field: {field}")

    for field in ["target_library", "target_api", "trigger_block"]:
        if not adapter.get(field):
            errors.append(f"empty required field: {field}")


def validate_code_blocks(adapter: Dict[str, Any], errors: List[str], warnings: List[str]) -> None:
    for field in EXECUTABLE_BLOCK_FIELDS:
        value = adapter.get(field)
        strings = list(iter_string_values(value))
        text = "\n".join(strings)

        for pattern in FORBIDDEN_PATTERNS:
            if pattern in text:
                errors.append(f"{field} contains forbidden token: {pattern}")

        if re.search(r"\bVALUE\b", text):
            errors.append(f"{field} contains forbidden bare VALUE variable")

        if adapter.get("target_library") == "openssl":
            for pattern in OPENSSL_FORBIDDEN_EXECUTABLE_PATTERNS:
                if pattern in text:
                    errors.append(f"{field} contains OpenSSL-forbidden source/internal token: {pattern}")

    cleanup = "\n".join(iter_string_values(adapter.get("cleanup_block")))
    if "free(buf)" in cleanup:
        errors.append("cleanup_block must not free caller-owned buf")

    for field in DESCRIPTIVE_BLOCK_FIELDS:
        text = "\n".join(iter_string_values(adapter.get(field)))
        for placeholder in ["[VALUE]", "[BUFLEN]"]:
            if placeholder in text:
                warnings.append(
                    f"descriptive {field} mentions placeholder {placeholder}, ignored for executable validation"
                )


def normalize_and_validate(obj: Dict[str, Any]) -> Dict[str, Any]:
    raw, used_schema_wrapper = find_required_output_schema(obj)
    adapter = build_standard_adapter(raw, obj)

    errors: List[str] = []
    warnings: List[str] = []

    if used_schema_wrapper:
        warnings.append("normalized adapter.required_output_schema into standard adapter")

    adapter["constant_mapping"] = normalize_placeholder_mapping(adapter.get("constant_mapping", {}))
    if adapter.get("_llm_status") == "fallback":
        warnings.append("adapter was generated by fallback, not by successful LLM output")

    normalize_openssl(adapter, warnings)
    validate_required_fields(adapter, errors)
    validate_code_blocks(adapter, errors, warnings)

    adapter["validation"] = {
        "status": "needs_repair" if errors else "ok",
        "errors": errors,
        "warnings": warnings,
        "normalized": True,
    }
    return adapter


def validate_all(adapter_root: Path, out_root: Path) -> Tuple[int, int]:
    adapter_files = sorted(adapter_root.rglob("adapter.yaml"))
    ok_count = 0
    repair_count = 0

    for adapter_file in adapter_files:
        rel = adapter_file.relative_to(adapter_root)
        out_file = out_root / rel

        adapter = normalize_and_validate(load_yaml(adapter_file))
        dump_yaml(out_file, adapter)

        meta_file = adapter_file.parent / "adapter_meta.yaml"
        if meta_file.exists():
            shutil.copy2(meta_file, out_file.parent / "adapter_meta.yaml")

        status = adapter["validation"]["status"]
        if status == "ok":
            ok_count += 1
        else:
            repair_count += 1

        print(f"[{status.upper()}] {adapter_file} -> {out_file}")

    print("=" * 80)
    print(f"[SUMMARY] adapters scanned: {len(adapter_files)}")
    print(f"[SUMMARY] ok: {ok_count}")
    print(f"[SUMMARY] needs_repair: {repair_count}")
    print(f"[SUMMARY] output root: {out_root}")

    return ok_count, repair_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize and validate generated adapter.yaml files.")
    parser.add_argument("--adapter-root", default="adapters")
    parser.add_argument("--out-root", default="adapters_validated")
    args = parser.parse_args()

    adapter_root = Path(args.adapter_root)
    out_root = Path(args.out_root)

    if not adapter_root.exists():
        parser.error(f"adapter root not found: {adapter_root}")

    validate_all(adapter_root, out_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

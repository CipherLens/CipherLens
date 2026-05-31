import argparse
import copy
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml


STANDARD_FIELDS = [
    "source_pattern_id",
    "template_id",
    "harness_family",
    "oracle_type",
    "target_library",
    "target_api",
    "applicability",
    "adapter_recipe",
    "evidence_file",
    "slot_bindings",
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

RECIPE_OMIT_FIELDS = [
    "include_headers",
    "type_mapping",
    "constant_mapping",
    "init_block",
    "input_construction_block",
    "trigger_block",
    "return_value_semantics",
    "oracle_strategy",
    "cleanup_block",
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

D2I_X509_FORBIDDEN_RESIDUE = [
    "BIGNUM",
    "BN_new",
    "BN_free",
    "BN_set_word",
    "BUFLEN",
    "signed_value",
    "magnitude",
    "openssl/bn.h",
]

EVP_DECRYPT_FINAL_FORBIDDEN_RESIDUE = [
    "BIGNUM",
    "BN_new",
    "BN_free",
    "BN_set_word",
    "d2i_X509",
    "X509_free",
    "ASN1_item_d2i",
    "BUFLEN",
    "CANARY_SIZE",
    "consumed_len",
    "openssl/bn.h",
    "openssl/x509.h",
]

BIGNUM_ARITHMETIC_FORBIDDEN_RESIDUE = [
    "EVP_DecryptFinal_ex",
    "EVP_CIPHER_CTX",
    "d2i_X509",
    "X509_free",
    "ASN1_item_d2i",
    "openssl/x509.h",
    "openssl/evp.h",
    "CANARY_SIZE",
    "BUFLEN",
    "consumed_len",
]

BIGNUM_BUFFER_CANARY_APIS = {
    "BN_bn2binpad",
    "BN_signed_bn2bin",
}

NULL_DEREF_DISPATCH_APIS = {
    "EVP_DigestVerify",
}

CRASH_SANITIZER_ORACLE_APIS = {
    "PEM_read_bio_PrivateKey",
}

INVALID_PARAMETER_SETUP_ORACLE_APIS = {
    "EVP_CIPHER_CTX_ctrl",
}

OBJECT_STATE_LIFECYCLE_APIS = {
    "ASN1_STRING_set",
}

OBJECT_STATE_LIFECYCLE_FORBIDDEN_RESIDUE = [
    "BIGNUM",
    "BN_new",
    "BN_free",
    "BN_set_word",
    "BN_bn2binpad",
    "BN_signed_bn2bin",
    "BN_usub",
    "BN_ucmp",
    "d2i_X509",
    "X509_free",
    "ASN1_item_d2i",
    "d2i_RSAPrivateKey",
    "d2i_PrivateKey",
    "d2i_RSA_PUBKEY",
    "EVP_DecryptFinal_ex",
    "EVP_CIPHER_CTX",
    "EVP_CIPHER_CTX_ctrl",
    "EVP_DigestVerifyInit",
    "PEM_read_bio_PrivateKey",
    "CANARY_SIZE",
    "BUFLEN",
    "consumed_len",
    "openssl/bn.h",
    "openssl/x509.h",
    "openssl/evp.h",
    "openssl/pem.h",
]

INVALID_PARAMETER_SETUP_ORACLE_FORBIDDEN_RESIDUE = [
    "BIGNUM",
    "BN_new",
    "BN_free",
    "BN_set_word",
    "BN_bn2binpad",
    "BN_signed_bn2bin",
    "BN_usub",
    "BN_ucmp",
    "d2i_X509",
    "X509_free",
    "ASN1_item_d2i",
    "d2i_RSAPrivateKey",
    "d2i_PrivateKey",
    "d2i_RSA_PUBKEY",
    "EVP_DecryptFinal_ex",
    "EVP_DigestVerifyInit",
    "PEM_read_bio_PrivateKey",
    "CANARY_SIZE",
    "BUFLEN",
    "consumed_len",
    "openssl/bn.h",
    "openssl/x509.h",
    "openssl/pem.h",
]

CRASH_SANITIZER_ORACLE_FORBIDDEN_RESIDUE = [
    "BIGNUM",
    "BN_new",
    "BN_free",
    "BN_set_word",
    "BN_bn2binpad",
    "BN_signed_bn2bin",
    "BN_usub",
    "BN_ucmp",
    "d2i_X509",
    "X509_free",
    "ASN1_item_d2i",
    "d2i_RSAPrivateKey",
    "d2i_PrivateKey",
    "d2i_RSA_PUBKEY",
    "EVP_DecryptFinal_ex",
    "EVP_CIPHER_CTX",
    "EVP_DigestVerifyInit",
    "CANARY_SIZE",
    "BUFLEN",
    "consumed_len",
    "openssl/bn.h",
    "openssl/x509.h",
]

NULL_DEREF_DISPATCH_FORBIDDEN_RESIDUE = [
    "BIGNUM",
    "BN_new",
    "BN_free",
    "BN_set_word",
    "BN_bn2binpad",
    "BN_signed_bn2bin",
    "BN_usub",
    "BN_ucmp",
    "d2i_X509",
    "X509_free",
    "ASN1_item_d2i",
    "EVP_DecryptFinal_ex",
    "EVP_CIPHER_CTX",
    "d2i_RSAPrivateKey",
    "d2i_PrivateKey",
    "d2i_RSA_PUBKEY",
    "CANARY_SIZE",
    "BUFLEN",
    "consumed_len",
    "openssl/bn.h",
    "openssl/x509.h",
]

BIGNUM_BUFFER_CANARY_FORBIDDEN_RESIDUE = [
    "EVP_DecryptFinal_ex",
    "EVP_CIPHER_CTX",
    "d2i_X509",
    "X509_free",
    "ASN1_item_d2i",
    "openssl/x509.h",
    "openssl/evp.h",
    "consumed_len",
    "BN_usub",
    "BN_ucmp",
    "bignum_negative_result_rejection_oracle",
]

X509_ASN1_RECIPE_FORBIDDEN_RESIDUE = [
    "BN_usub",
    "BN_ucmp",
    "BN_signed_bn2bin",
    "CANARY_SIZE",
    "BUFLEN",
    "EVP_DecryptFinal_ex",
    "EVP_CIPHER_CTX",
    "d2i_RSAPrivateKey",
    "d2i_PrivateKey",
    "d2i_RSA_PUBKEY",
    "openssl/bn.h",
    "openssl/evp.h",
]


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
    adapter["adapter_recipe"] = str(adapter.get("adapter_recipe") or "")
    adapter["evidence_file"] = str(adapter.get("evidence_file") or "")
    adapter["slot_bindings"] = ensure_dict(adapter.get("slot_bindings"))
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


def is_recipe_adapter(adapter: Dict[str, Any]) -> bool:
    return bool(adapter.get("adapter_recipe"))


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

    if is_recipe_adapter(adapter):
        return

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
        if is_recipe_adapter(adapter) and field in RECIPE_OMIT_FIELDS:
            continue
        if field not in adapter:
            errors.append(f"missing required field: {field}")

    required_nonempty = ["target_library", "target_api"]
    if not is_recipe_adapter(adapter):
        required_nonempty.append("trigger_block")

    for field in required_nonempty:
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


def validate_d2i_x509_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    if adapter.get("target_api") != "d2i_X509":
        return

    if is_recipe_adapter(adapter):
        return

    headers = [str(x).strip() for x in ensure_list(adapter.get("include_headers"))]
    if "openssl/x509.h" not in headers:
        errors.append("d2i_X509 adapter must include openssl/x509.h")

    init_text = "\n".join(iter_string_values(adapter.get("init_block")))
    input_text = "\n".join(iter_string_values(adapter.get("input_construction_block")))
    trigger_text = "\n".join(iter_string_values(adapter.get("trigger_block")))
    cleanup_text = "\n".join(iter_string_values(adapter.get("cleanup_block")))
    semantic_text = "\n".join([init_text, input_text, trigger_text])
    adapter_text = "\n".join(iter_string_values(adapter))

    for token in D2I_X509_FORBIDDEN_RESIDUE:
        if token in adapter_text:
            errors.append(f"d2i_X509 adapter contains bignum residue: {token}")

    if "d2i_X509" not in trigger_text:
        errors.append("d2i_X509 adapter trigger_block must call d2i_X509")

    if "X509_free" not in cleanup_text:
        errors.append("d2i_X509 adapter cleanup_block must call X509_free")

    if not re.search(r"\bX509\s*\*", semantic_text):
        errors.append("d2i_X509 adapter init/input/trigger must declare or use an X509 pointer")

    has_input_pointer = (
        re.search(r"\bconst\s+unsigned\s+char\s*\*\s*p\b", semantic_text) is not None
        or ("p = der" in input_text and "&p" in trigger_text)
    )
    if not has_input_pointer:
        errors.append("d2i_X509 adapter must expose a const unsigned char *p style input pointer")

    if "der_len" not in trigger_text:
        errors.append("d2i_X509 adapter trigger_block must use der_len")

    if "consumed_len" not in trigger_text and "p - der" not in trigger_text:
        errors.append("d2i_X509 adapter trigger_block must record consumed_len or p - der")


def resolve_recipe_path(adapter: Dict[str, Any]) -> Path:
    return Path(str(adapter.get("adapter_recipe") or ""))


def load_recipe_for_adapter(adapter: Dict[str, Any], errors: List[str]) -> Dict[str, Any]:
    recipe_path = resolve_recipe_path(adapter)
    if not recipe_path:
        errors.append("adapter_recipe is empty")
        return {}
    if not recipe_path.exists():
        errors.append(f"adapter_recipe not found: {recipe_path}")
        return {}
    try:
        recipe = load_yaml(recipe_path)
    except Exception as e:
        errors.append(f"adapter_recipe yaml load failed: {recipe_path}: {e}")
        return {}
    if not recipe:
        errors.append(f"adapter_recipe is empty or invalid: {recipe_path}")
    return recipe


def validate_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> bool:
    if not is_recipe_adapter(adapter):
        return False

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return True

    if recipe.get("target_api") != adapter.get("target_api"):
        errors.append(
            f"adapter_recipe target_api mismatch: recipe={recipe.get('target_api')} "
            f"adapter={adapter.get('target_api')}"
        )

    if adapter.get("target_api") == "EVP_DecryptFinal_ex":
        if recipe.get("harness_family") != "return_code_outlen_semantic":
            errors.append("EVP_DecryptFinal_ex recipe must use harness_family=return_code_outlen_semantic")
    elif adapter.get("target_api") == "BN_usub":
        if recipe.get("harness_family") != "bignum_arithmetic_semantic":
            errors.append("BN_usub recipe must use harness_family=bignum_arithmetic_semantic")
        if recipe.get("oracle_type") != "bignum_negative_result_rejection_oracle":
            errors.append("BN_usub recipe must use oracle_type=bignum_negative_result_rejection_oracle")
    elif adapter.get("target_api") in BIGNUM_BUFFER_CANARY_APIS:
        if recipe.get("harness_family") != "buffer_canary_boundary":
            errors.append(
                f"{adapter.get('target_api')} recipe must use harness_family=buffer_canary_boundary"
            )
    elif adapter.get("target_api") in OBJECT_STATE_LIFECYCLE_APIS:
        if recipe.get("harness_family") != "object_state_lifecycle":
            errors.append(
                f"{adapter.get('target_api')} recipe must use harness_family=object_state_lifecycle"
            )
        if recipe.get("oracle_type") not in {
            "stale_pointer_length_state_oracle",
            "object_lifecycle_state_oracle",
        }:
            errors.append(
                f"{adapter.get('target_api')} recipe must use an object_state_lifecycle oracle_type"
            )
    elif adapter.get("target_api") in INVALID_PARAMETER_SETUP_ORACLE_APIS:
        if recipe.get("harness_family") != "invalid_parameter_setup_oracle":
            errors.append(
                f"{adapter.get('target_api')} recipe must use harness_family=invalid_parameter_setup_oracle"
            )
        if recipe.get("oracle_type") not in {
            "invalid_aead_tag_length_oracle",
            "invalid_parameter_return_code_oracle",
        }:
            errors.append(
                f"{adapter.get('target_api')} recipe must use an invalid_parameter_setup_oracle oracle_type"
            )
    elif adapter.get("target_api") in CRASH_SANITIZER_ORACLE_APIS:
        if recipe.get("harness_family") != "crash_sanitizer_oracle":
            errors.append(
                f"{adapter.get('target_api')} recipe must use harness_family=crash_sanitizer_oracle"
            )
        if recipe.get("oracle_type") not in {
            "heap_underflow_sanitizer_oracle",
            "heap_overflow_sanitizer_oracle",
            "generic_sanitizer_crash_oracle",
        }:
            errors.append(
                f"{adapter.get('target_api')} recipe must use a crash_sanitizer_oracle oracle_type"
            )
    elif adapter.get("target_api") in NULL_DEREF_DISPATCH_APIS:
        if recipe.get("harness_family") != "null_deref_dispatch":
            errors.append(
                f"{adapter.get('target_api')} recipe must use harness_family=null_deref_dispatch"
            )
        if recipe.get("oracle_type") != "crash_sanitizer_or_safe_error_oracle":
            errors.append(
                f"{adapter.get('target_api')} recipe must use oracle_type=crash_sanitizer_or_safe_error_oracle"
            )
    elif adapter.get("target_api") == "d2i_X509":
        if recipe.get("harness_family") != "x509_asn1_inner_boundary":
            errors.append("d2i_X509 recipe must use harness_family=x509_asn1_inner_boundary")
        if recipe.get("oracle_type") != "inner_asn1_boundary_semantic_oracle":
            errors.append("d2i_X509 recipe must use oracle_type=inner_asn1_boundary_semantic_oracle")

    if not isinstance(recipe.get("forbidden_terms"), list) or not recipe.get("forbidden_terms"):
        errors.append("adapter_recipe must define non-empty forbidden_terms")

    allowed_slots = recipe.get("allowed_slots")
    if not isinstance(allowed_slots, dict) or not allowed_slots:
        errors.append("adapter_recipe must define non-empty allowed_slots")
        allowed_slots = {}

    slot_bindings = ensure_dict(adapter.get("slot_bindings"))
    required_slots = list(allowed_slots.keys())

    for slot in required_slots:
        if slot not in slot_bindings or str(slot_bindings.get(slot) or "").strip() == "":
            errors.append(f"recipe adapter missing required slot_binding: {slot}")

    unknown_slots = sorted(set(slot_bindings) - set(allowed_slots))
    for slot in unknown_slots:
        errors.append(f"recipe adapter slot_binding is not allowed by recipe: {slot}")

    adapter_text = "\n".join(iter_string_values(adapter))
    for token in recipe.get("forbidden_terms", []) or []:
        if str(token) and str(token) in adapter_text:
            errors.append(f"recipe adapter contains forbidden term: {token}")

    return True


def validate_bn_usub_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    if adapter.get("target_api") != "BN_usub" or not is_recipe_adapter(adapter):
        return

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return

    recipe_text = "\n".join(iter_string_values(recipe))
    adapter_text = "\n".join(iter_string_values(adapter))
    combined_text = "\n".join([recipe_text, adapter_text])
    recipe_semantic_text_obj = copy.deepcopy(recipe)
    recipe_semantic_text_obj.pop("forbidden_terms", None)
    cross_family_text = "\n".join([adapter_text, "\n".join(iter_string_values(recipe_semantic_text_obj))])

    headers = [str(x).strip() for x in ensure_list(recipe.get("include_headers"))]
    if "openssl/bn.h" not in headers:
        errors.append("BN_usub recipe adapter must include openssl/bn.h in adapter_recipe")

    for token in BIGNUM_ARITHMETIC_FORBIDDEN_RESIDUE:
        if token in cross_family_text:
            errors.append(f"BN_usub recipe adapter contains cross-family residue: {token}")

    for token in ["BN_new", "BN_free", "BN_usub"]:
        if token not in combined_text:
            errors.append(f"BN_usub recipe adapter must preserve required token: {token}")

    if "BN_set_word" not in combined_text and "BN_bin2bn" not in combined_text:
        errors.append("BN_usub recipe adapter must construct operands with BN_set_word or BN_bin2bn")

    allowed_slots = ensure_dict(recipe.get("allowed_slots"))
    slot_bindings = ensure_dict(adapter.get("slot_bindings"))

    observable_slots = {
        "comparison observable": ["comparison_variable"],
        "arithmetic relation observable": ["expected_relation", "result_observable"],
        "return_code observable": ["return_code_variable"],
    }
    for label, slots in observable_slots.items():
        if not any(slot in allowed_slots and str(slot_bindings.get(slot) or "").strip() for slot in slots):
            errors.append(f"BN_usub recipe adapter must expose {label}")

    behavior_text = "\n".join(
        iter_string_values(
            {
                "safe_behavior": recipe.get("safe_behavior"),
                "semantic_mismatch_behavior": recipe.get("semantic_mismatch_behavior"),
                "bug_behavior": recipe.get("bug_behavior"),
                "unexpected_success": recipe.get("unexpected_success"),
            }
        )
    ).lower()
    if "cmp" not in behavior_text and "comparison" not in behavior_text:
        errors.append("BN_usub recipe must describe comparison-based behavior")
    if "ret" not in recipe_text and "return_code" not in recipe_text:
        errors.append("BN_usub recipe must describe return-code observability")


def validate_bignum_buffer_canary_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    target_api = adapter.get("target_api")
    if target_api not in BIGNUM_BUFFER_CANARY_APIS or not is_recipe_adapter(adapter):
        return

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return

    recipe_text = "\n".join(iter_string_values(recipe))
    adapter_text = "\n".join(iter_string_values(adapter))
    combined_text = "\n".join([recipe_text, adapter_text])
    recipe_semantic_text_obj = copy.deepcopy(recipe)
    recipe_semantic_text_obj.pop("forbidden_terms", None)
    cross_family_text = "\n".join([adapter_text, "\n".join(iter_string_values(recipe_semantic_text_obj))])

    headers = [str(x).strip() for x in ensure_list(recipe.get("include_headers"))]
    if "openssl/bn.h" not in headers:
        errors.append(f"{target_api} recipe adapter must include openssl/bn.h in adapter_recipe")

    for token in BIGNUM_BUFFER_CANARY_FORBIDDEN_RESIDUE:
        if token in cross_family_text:
            errors.append(f"{target_api} recipe adapter contains cross-family residue: {token}")

    for token in ["BN_new", "BN_free", target_api]:
        if token not in combined_text:
            errors.append(f"{target_api} recipe adapter must preserve required token: {token}")

    if not any(token in combined_text for token in ["BN_set_word", "BN_bin2bn", "BN_dec2bn"]):
        errors.append(f"{target_api} recipe adapter must construct value with BN_set_word, BN_bin2bn, or BN_dec2bn")

    allowed_slots = ensure_dict(recipe.get("allowed_slots"))
    slot_bindings = ensure_dict(adapter.get("slot_bindings"))

    observable_slots = {
        "buffer observable": ["output_buffer", "buffer_observable"],
        "canary observable": ["canary_observable", "canary_size"],
        "return_code observable": ["return_code_variable"],
    }
    for label, slots in observable_slots.items():
        if not any(slot in allowed_slots and str(slot_bindings.get(slot) or "").strip() for slot in slots):
            errors.append(f"{target_api} recipe adapter must expose {label}")

    behavior_text = "\n".join(
        iter_string_values(
            {
                "safe_behavior": recipe.get("safe_behavior"),
                "bug_behavior": recipe.get("bug_behavior"),
                "unexpected_success": recipe.get("unexpected_success"),
            }
        )
    ).lower()
    if "canary" not in behavior_text and "boundary" not in behavior_text:
        errors.append(f"{target_api} recipe must describe canary/boundary behavior")
    if "ret" not in recipe_text and "return_code" not in recipe_text:
        errors.append(f"{target_api} recipe must describe return-code observability")



def validate_x509_asn1_inner_boundary_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    if adapter.get("target_api") != "d2i_X509" or not is_recipe_adapter(adapter):
        return

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return

    if recipe.get("harness_family") != "x509_asn1_inner_boundary":
        errors.append("d2i_X509 recipe adapter must use harness_family=x509_asn1_inner_boundary")
    if recipe.get("oracle_type") != "inner_asn1_boundary_semantic_oracle":
        errors.append("d2i_X509 recipe adapter must use oracle_type=inner_asn1_boundary_semantic_oracle")

    recipe_text = "\n".join(iter_string_values(recipe))
    adapter_text = "\n".join(iter_string_values(adapter))
    combined_text = "\n".join([recipe_text, adapter_text])

    recipe_semantic_text_obj = copy.deepcopy(recipe)
    recipe_semantic_text_obj.pop("forbidden_terms", None)
    cross_family_text = "\n".join([adapter_text, "\n".join(iter_string_values(recipe_semantic_text_obj))])

    headers = [str(x).strip() for x in ensure_list(recipe.get("include_headers"))]
    if "openssl/x509.h" not in headers:
        errors.append("d2i_X509 recipe adapter must include openssl/x509.h in adapter_recipe")

    for token in X509_ASN1_RECIPE_FORBIDDEN_RESIDUE:
        if token in cross_family_text:
            errors.append(f"d2i_X509 recipe adapter contains cross-family residue: {token}")

    for token in ["d2i_X509", "X509_free"]:
        if token not in combined_text:
            errors.append(f"d2i_X509 recipe adapter must preserve required token: {token}")

    allowed_slots = ensure_dict(recipe.get("allowed_slots"))
    slot_bindings = ensure_dict(adapter.get("slot_bindings"))

    observable_slots = {
        "malformed input selector": ["malformed_der_structure"],
        "input buffer observable": ["input_buffer"],
        "input length observable": ["input_length"],
        "pointer observable": ["pointer_variable"],
        "consumption observable": ["consumed_len_variable"],
        "return-code observable": ["return_code_variable"],
        "decoded object observable": ["decoded_object"],
    }

    for label, slots in observable_slots.items():
        if not any(slot in allowed_slots and str(slot_bindings.get(slot) or "").strip() for slot in slots):
            errors.append(f"d2i_X509 recipe adapter must expose {label}")

    behavior_text = "\n".join(
        iter_string_values(
            {
                "safe_behavior": recipe.get("safe_behavior"),
                "bug_behavior": recipe.get("bug_behavior"),
                "lost_or_weakened_features": recipe.get("lost_or_weakened_features"),
            }
        )
    ).lower()

    if "malformed" not in behavior_text and "inner-boundary" not in behavior_text and "asn.1" not in behavior_text:
        errors.append("d2i_X509 recipe must describe malformed ASN.1/X.509 inner-boundary behavior")

    if "ret" not in recipe_text and "return_code" not in recipe_text:
        errors.append("d2i_X509 recipe must describe return-code observability")


def validate_object_state_lifecycle_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    target_api = adapter.get("target_api")
    if target_api not in OBJECT_STATE_LIFECYCLE_APIS or not is_recipe_adapter(adapter):
        return

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return

    if recipe.get("harness_family") != "object_state_lifecycle":
        errors.append(f"{target_api} recipe adapter must use harness_family=object_state_lifecycle")

    recipe_text = "\n".join(iter_string_values(recipe))
    adapter_text = "\n".join(iter_string_values(adapter))
    recipe_semantic_obj = copy.deepcopy(recipe)
    recipe_semantic_obj.pop("forbidden_terms", None)
    cross_family_text = "\n".join([adapter_text, "\n".join(iter_string_values(recipe_semantic_obj))])

    headers = [str(x).strip() for x in ensure_list(recipe.get("include_headers"))]
    if "openssl/asn1.h" not in headers:
        errors.append(f"{target_api} recipe adapter must include openssl/asn1.h in adapter_recipe")

    for token in OBJECT_STATE_LIFECYCLE_FORBIDDEN_RESIDUE:
        if token in cross_family_text:
            errors.append(f"{target_api} recipe adapter contains cross-family residue: {token}")

    required_tokens = ["ASN1_STRING_set", "ASN1_STRING_new", "ASN1_STRING_free"]
    combined_text = "\n".join([recipe_text, adapter_text])
    for token in required_tokens:
        if token not in combined_text:
            errors.append(f"{target_api} recipe adapter must preserve required token: {token}")

    allowed_slots = ensure_dict(recipe.get("allowed_slots"))
    slot_bindings = ensure_dict(adapter.get("slot_bindings"))

    observable_slots = {
        "ASN1_STRING variable observable": ["asn1_string_variable"],
        "return code observable": ["return_code_variable"],
    }
    for label, slots in observable_slots.items():
        if not any(slot in allowed_slots and str(slot_bindings.get(slot) or "").strip() for slot in slots):
            errors.append(f"{target_api} recipe adapter must expose {label}")

    behavior_text = "\n".join(
        iter_string_values({
            "safe_behavior": recipe.get("safe_behavior"),
            "bug_behavior": recipe.get("bug_behavior"),
        })
    ).lower()
    if "safe" not in behavior_text and "realloc" not in behavior_text:
        errors.append(f"{target_api} recipe must describe safe reallocation behavior")
    if "crash" not in behavior_text and "asan" not in behavior_text and "null" not in behavior_text:
        errors.append(f"{target_api} recipe must describe crash/ASAN/NULL bug behavior")


def validate_invalid_parameter_setup_oracle_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    target_api = adapter.get("target_api")
    if target_api not in INVALID_PARAMETER_SETUP_ORACLE_APIS or not is_recipe_adapter(adapter):
        return

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return

    if recipe.get("harness_family") != "invalid_parameter_setup_oracle":
        errors.append(f"{target_api} recipe adapter must use harness_family=invalid_parameter_setup_oracle")

    recipe_text = "\n".join(iter_string_values(recipe))
    adapter_text = "\n".join(iter_string_values(adapter))
    recipe_semantic_obj = copy.deepcopy(recipe)
    recipe_semantic_obj.pop("forbidden_terms", None)
    cross_family_text = "\n".join([adapter_text, "\n".join(iter_string_values(recipe_semantic_obj))])

    headers = [str(x).strip() for x in ensure_list(recipe.get("include_headers"))]
    if "openssl/evp.h" not in headers:
        errors.append(f"{target_api} recipe adapter must include openssl/evp.h in adapter_recipe")

    for token in INVALID_PARAMETER_SETUP_ORACLE_FORBIDDEN_RESIDUE:
        if token in cross_family_text:
            errors.append(f"{target_api} recipe adapter contains cross-family residue: {token}")

    required_tokens = ["EVP_CIPHER_CTX_ctrl", "EVP_CTRL_CCM_SET_TAG", "EVP_aes_128_ccm"]
    combined_text = "\n".join([recipe_text, adapter_text])
    for token in required_tokens:
        if token not in combined_text:
            errors.append(f"{target_api} recipe adapter must preserve required token: {token}")

    allowed_slots = ensure_dict(recipe.get("allowed_slots"))
    slot_bindings = ensure_dict(adapter.get("slot_bindings"))

    observable_slots = {
        "tag length observable": ["aead_cipher", "return_code_variable"],
        "ctx observable": ["ctx_variable"],
    }
    for label, slots in observable_slots.items():
        if not any(slot in allowed_slots and str(slot_bindings.get(slot) or "").strip() for slot in slots):
            errors.append(f"{target_api} recipe adapter must expose {label}")

    behavior_text = "\n".join(
        iter_string_values({
            "safe_behavior": recipe.get("safe_behavior"),
            "bug_behavior": recipe.get("bug_behavior"),
        })
    ).lower()
    if "reject" not in behavior_text and "ret <= 0" not in behavior_text:
        errors.append(f"{target_api} recipe must describe rejection safe behavior")
    if "accept" not in behavior_text and "ret > 0" not in behavior_text:
        errors.append(f"{target_api} recipe must describe acceptance bug behavior")


def validate_crash_sanitizer_oracle_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    target_api = adapter.get("target_api")
    if target_api not in CRASH_SANITIZER_ORACLE_APIS or not is_recipe_adapter(adapter):
        return

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return

    if recipe.get("harness_family") != "crash_sanitizer_oracle":
        errors.append(f"{target_api} recipe adapter must use harness_family=crash_sanitizer_oracle")

    recipe_text = "\n".join(iter_string_values(recipe))
    adapter_text = "\n".join(iter_string_values(adapter))
    recipe_semantic_obj = copy.deepcopy(recipe)
    recipe_semantic_obj.pop("forbidden_terms", None)
    cross_family_text = "\n".join([adapter_text, "\n".join(iter_string_values(recipe_semantic_obj))])

    headers = [str(x).strip() for x in ensure_list(recipe.get("include_headers"))]
    if "openssl/pem.h" not in headers:
        errors.append(f"{target_api} recipe adapter must include openssl/pem.h in adapter_recipe")

    for token in CRASH_SANITIZER_ORACLE_FORBIDDEN_RESIDUE:
        if token in cross_family_text:
            errors.append(f"{target_api} recipe adapter contains cross-family residue: {token}")

    required_tokens = ["PEM_read_bio_PrivateKey", "BIO_new_mem_buf", "BIO_free"]
    combined_text = "\n".join([recipe_text, adapter_text])
    for token in required_tokens:
        if token not in combined_text:
            errors.append(f"{target_api} recipe adapter must preserve required token: {token}")

    allowed_slots = ensure_dict(recipe.get("allowed_slots"))
    slot_bindings = ensure_dict(adapter.get("slot_bindings"))

    observable_slots = {
        "bio observable": ["bio_variable"],
        "key result observable": ["pkey_variable"],
    }
    for label, slots in observable_slots.items():
        if not any(slot in allowed_slots and str(slot_bindings.get(slot) or "").strip() for slot in slots):
            errors.append(f"{target_api} recipe adapter must expose {label}")

    behavior_text = "\n".join(
        iter_string_values({
            "safe_behavior": recipe.get("safe_behavior"),
            "bug_behavior": recipe.get("bug_behavior"),
        })
    ).lower()
    if "null" not in behavior_text and "reject" not in behavior_text:
        errors.append(f"{target_api} recipe must describe NULL/rejection safe behavior")
    if "crash" not in behavior_text and "asan" not in behavior_text and "sanitizer" not in behavior_text:
        errors.append(f"{target_api} recipe must describe crash/ASAN bug behavior")


def validate_null_deref_dispatch_recipe_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    target_api = adapter.get("target_api")
    if target_api not in NULL_DEREF_DISPATCH_APIS or not is_recipe_adapter(adapter):
        return

    recipe = load_recipe_for_adapter(adapter, errors)
    if not recipe:
        return

    if recipe.get("harness_family") != "null_deref_dispatch":
        errors.append(f"{target_api} recipe adapter must use harness_family=null_deref_dispatch")
    if recipe.get("oracle_type") != "crash_sanitizer_or_safe_error_oracle":
        errors.append(f"{target_api} recipe adapter must use oracle_type=crash_sanitizer_or_safe_error_oracle")

    recipe_text = "\n".join(iter_string_values(recipe))
    adapter_text = "\n".join(iter_string_values(adapter))
    recipe_semantic_obj = copy.deepcopy(recipe)
    recipe_semantic_obj.pop("forbidden_terms", None)
    cross_family_text = "\n".join([adapter_text, "\n".join(iter_string_values(recipe_semantic_obj))])

    headers = [str(x).strip() for x in ensure_list(recipe.get("include_headers"))]
    if "openssl/evp.h" not in headers:
        errors.append(f"{target_api} recipe adapter must include openssl/evp.h in adapter_recipe")

    for token in NULL_DEREF_DISPATCH_FORBIDDEN_RESIDUE:
        if token in cross_family_text:
            errors.append(f"{target_api} recipe adapter contains cross-family residue: {token}")

    required_tokens = ["EVP_DigestVerifyInit", "EVP_PKEY_CTX_set_rsa_padding", "EVP_MD_CTX"]
    combined_text = "\n".join([recipe_text, adapter_text])
    for token in required_tokens:
        if token not in combined_text:
            errors.append(f"{target_api} recipe adapter must preserve required token: {token}")

    allowed_slots = ensure_dict(recipe.get("allowed_slots"))
    slot_bindings = ensure_dict(adapter.get("slot_bindings"))

    observable_slots = {
        "hash algorithm observable": ["md_algorithm"],
        "incompatible key observable": ["incompatible_key_variable"],
        "return code observable": ["return_code_variable"],
    }
    for label, slots in observable_slots.items():
        if not any(slot in allowed_slots and str(slot_bindings.get(slot) or "").strip() for slot in slots):
            errors.append(f"{target_api} recipe adapter must expose {label}")

    behavior_text = "\n".join(
        iter_string_values(
            {
                "safe_behavior": recipe.get("safe_behavior"),
                "bug_behavior": recipe.get("bug_behavior"),
            }
        )
    ).lower()
    if "crash" not in behavior_text and "asan" not in behavior_text and "segv" not in behavior_text:
        errors.append(f"{target_api} recipe must describe crash/ASAN/SEGV bug behavior")
    if "safe" not in behavior_text and "reject" not in behavior_text:
        errors.append(f"{target_api} recipe must describe safe rejection behavior")


def validate_evp_decrypt_final_adapter(adapter: Dict[str, Any], errors: List[str]) -> None:
    if adapter.get("target_api") != "EVP_DecryptFinal_ex":
        return

    if is_recipe_adapter(adapter):
        return

    headers = [str(x).strip() for x in ensure_list(adapter.get("include_headers"))]
    if "openssl/evp.h" not in headers:
        errors.append("EVP_DecryptFinal_ex adapter must include openssl/evp.h")

    init_text = "\n".join(iter_string_values(adapter.get("init_block")))
    input_text = "\n".join(iter_string_values(adapter.get("input_construction_block")))
    trigger_text = "\n".join(iter_string_values(adapter.get("trigger_block")))
    cleanup_text = "\n".join(iter_string_values(adapter.get("cleanup_block")))
    semantic_text = "\n".join([init_text, input_text, trigger_text])
    adapter_text = "\n".join(iter_string_values(adapter))

    for token in EVP_DECRYPT_FINAL_FORBIDDEN_RESIDUE:
        if token in adapter_text:
            errors.append(f"EVP_DecryptFinal_ex adapter contains cross-family residue: {token}")

    if "EVP_DecryptFinal_ex" not in trigger_text:
        errors.append("EVP_DecryptFinal_ex adapter trigger_block must call EVP_DecryptFinal_ex")

    if not re.search(r"\bEVP_CIPHER_CTX\b\s*\*?", semantic_text):
        errors.append("EVP_DecryptFinal_ex adapter init/input/trigger must use EVP_CIPHER_CTX")

    if "EVP_CIPHER_CTX_new" not in semantic_text:
        errors.append("EVP_DecryptFinal_ex adapter must initialize ctx with EVP_CIPHER_CTX_new")

    if "EVP_DecryptInit_ex" not in semantic_text:
        errors.append("EVP_DecryptFinal_ex adapter must initialize decryption with EVP_DecryptInit_ex")

    if "EVP_DecryptUpdate" not in semantic_text:
        errors.append("EVP_DecryptFinal_ex adapter must construct finalization state with EVP_DecryptUpdate")

    if "EVP_CIPHER_CTX_free" not in cleanup_text:
        errors.append("EVP_DecryptFinal_ex adapter cleanup_block must call EVP_CIPHER_CTX_free")

    ret_observable = (
        re.search(r"\bret\b", trigger_text) is not None
        or re.search(r"\bret\b", adapter.get("return_value_semantics", "")) is not None
        or re.search(r"\bret\b", "\n".join(iter_string_values(adapter.get("oracle_strategy")))) is not None
    )
    if not ret_observable:
        errors.append("EVP_DecryptFinal_ex adapter must expose observable return code ret")

    outlen_text = "\n".join([
        semantic_text,
        adapter.get("return_value_semantics", ""),
        "\n".join(iter_string_values(adapter.get("oracle_strategy"))),
    ])
    if not re.search(r"\b(final_len|out_len|outl|olen)\b", outlen_text):
        errors.append("EVP_DecryptFinal_ex adapter must expose output length such as final_len/out_len/outl/olen")

    oracle_text = "\n".join([
        adapter.get("return_value_semantics", ""),
        "\n".join(iter_string_values(adapter.get("oracle_strategy"))),
        "\n".join(iter_string_values(adapter.get("notes"))),
    ]).lower()
    has_failure_oracle = (
        ("ret" in oracle_text or "return" in oracle_text)
        and ("final_len" in oracle_text or "out_len" in oracle_text or "outl" in oracle_text or "olen" in oracle_text)
        and ("padding" in oracle_text or "final" in oracle_text or "failure" in oracle_text or "error" in oracle_text)
    )
    if not has_failure_oracle:
        errors.append(
            "EVP_DecryptFinal_ex adapter must describe invalid-padding/finalization failure "
            "as return-code plus output-length oracle"
        )

    bug_signal_text = "\n".join(iter_string_values(ensure_dict(adapter.get("oracle_strategy")).get("bug_signals"))).lower()
    if re.search(r"\bret\s*!=\s*0\b", bug_signal_text):
        errors.append(
            "EVP_DecryptFinal_ex invalid-padding bug signal must use failure return "
            "(ret <= 0 or ret == 0), not ret != 0"
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

    if is_recipe_adapter(adapter):
        for field in RECIPE_OMIT_FIELDS:
            adapter.pop(field, None)

    normalize_openssl(adapter, warnings)
    validate_required_fields(adapter, errors)
    if not is_recipe_adapter(adapter):
        validate_code_blocks(adapter, errors, warnings)
    if is_recipe_adapter(adapter):
        validate_recipe_adapter(adapter, errors)
    validate_x509_asn1_inner_boundary_recipe_adapter(adapter, errors)
    validate_d2i_x509_adapter(adapter, errors)
    validate_evp_decrypt_final_adapter(adapter, errors)
    validate_bn_usub_recipe_adapter(adapter, errors)
    validate_bignum_buffer_canary_recipe_adapter(adapter, errors)
    validate_null_deref_dispatch_recipe_adapter(adapter, errors)
    validate_crash_sanitizer_oracle_recipe_adapter(adapter, errors)
    validate_invalid_parameter_setup_oracle_recipe_adapter(adapter, errors)
    validate_object_state_lifecycle_recipe_adapter(adapter, errors)

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

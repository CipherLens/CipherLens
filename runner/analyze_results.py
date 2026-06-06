import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import yaml


ASAN_PATTERNS = [
    "AddressSanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-free",
    "SEGV",
    "segmentation fault",
]

UBSAN_PATTERNS = [
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "undefined behavior",
]

BUG_PATTERNS = [
    "[BUG]",
    "Canary corrupted",
    "out-of-bounds write detected",
    "wrote beyond",
]

DER_TRAILING_GARBAGE_BUG_PATTERNS = [
    "[BUG] target decoded first DER object but left trailing garbage unconsumed.",
]

X509_ASN1_INNER_BOUNDARY_BUG_PATTERNS = [
    "[BUG] target accepted malformed X509/ASN1 inner-boundary input.",
]

RETURN_CODE_OUTLEN_BUG_PATTERNS = [
    "[BUG] target rejected invalid padding but final_len was polluted.",
    "[BUG] source rejected invalid padding but finish_olen was polluted",
    "[BUG] invalid padding rejected but outlen is unsafe/nonzero.",
]

SAFE_PATTERNS = [
    "[OK] Canary intact",
    "fixed behavior",
    "rejected safely",
]

DER_TRAILING_GARBAGE_SAFE_REJECT_PATTERNS = [
    "[OK] parser rejected trailing garbage.",
    "[INFO] parser rejected trailing garbage with alternate ret=",
    "[OK] target rejected trailing-garbage input.",
    "[OK] target decoded and consumed full input exactly.",
]

X509_ASN1_INNER_BOUNDARY_SAFE_REJECT_PATTERNS = [
    "[OK] target rejected malformed X509/ASN1 inner-boundary input.",
]

RETURN_CODE_OUTLEN_SAFE_REJECT_PATTERNS = [
    "[OK] target rejected invalid padding and final_len remained zero.",
    "[OK] source rejected invalid padding and finish_olen remained zero",
    "[OK] fixed behavior: invalid padding rejected and outlen remains zero.",
]

RETURN_CODE_OUTLEN_TRIAGE_PATTERNS = [
    "[TRIAGE] target accepted invalid padding unexpectedly.",
]

BIGNUM_ARITHMETIC_SAFE_REJECT_PATTERNS = [
    "[OK] target rejected lhs<rhs unsigned subtraction or avoided producing result.",
    "[OK] source rejected negative mbedTLS absolute subtraction.",
]

BIGNUM_ARITHMETIC_TRIAGE_PATTERNS = [
    "[TRIAGE] target produced result for lhs<rhs unsigned subtraction; semantic projection needs review.",
    "[INFO] target lhs>=rhs normal unsigned subtraction path.",
    "[TRIAGE] source produced result for negative mbedTLS absolute subtraction; semantic projection needs review.",
    "[INFO] source lhs>=rhs normal mbedTLS sub_abs path.",
]

BIGNUM_BN_USUB_SEMANTIC_PROJECTION_PATTERNS = [
    "[TRIAGE] target produced result for lhs<rhs unsigned subtraction; semantic projection needs review.",
]

BIGNUM_SERIALIZATION_BUFFER_SAFE_REJECT_PATTERNS = [
    "[OK] target rejected small output buffer and canary intact.",
]

BIGNUM_SERIALIZATION_BUFFER_NORMAL_PATTERNS = [
    "[INFO] target serialized into provided buffer; canary intact.",
]

NULL_DEREF_DISPATCH_SAFE_REJECT_PATTERNS = [
    "[OK] null_deref_dispatch:",
]

NULL_DEREF_DISPATCH_TRIAGE_PATTERNS = [
    "[TRIAGE] null_deref_dispatch:",
]

OBJECT_STATE_LIFECYCLE_SAFE_PATTERNS = [
    "[OK] fixed behavior: safe reallocation",
    "[OK] object_state_lifecycle: safe update",
    "[OK] object_state_lifecycle: safe",
]

OBJECT_STATE_LIFECYCLE_TRIAGE_PATTERNS = [
    "[INFO] object_state_lifecycle:",
    "[TRIAGE] object_state_lifecycle:",
]

MAC_CONTEXT_LIFECYCLE_BUG_PATTERNS = [
    "[BUG] mac_context_lifecycle: crash or sanitizer signal",
]

MAC_CONTEXT_LIFECYCLE_SAFE_PATTERNS = [
    "[OK] mac_context_lifecycle: pre-setup operation rejected safely",
    "[OK] mac_context_lifecycle: initialized size matched",
    "[OK] mac_context_lifecycle: initialized MAC operation completed",
]

MAC_CONTEXT_LIFECYCLE_TRIAGE_PATTERNS = [
    "[TRIAGE] mac_context_lifecycle: unexpected size/state",
]

INVALID_PARAM_SETUP_BUG_PATTERNS = [
    "[BUG] source accepted invalid CCM shortened tag length",
    "[BUG] target accepted invalid CCM tag length",
    "[BUG] invalid AEAD tag length accepted",
]

PKEY_CAPABILITY_MISMATCH_SAFE_REJECT_PATTERNS = [
    "[SAFE] public-only key signing rejected:",
    "[VERDICT] safe_fixed_behavior",
    "[SAFE] EVP_DigestSignInit rejected public-only key",
    "[SAFE] EVP_DigestSign rejected public-only key",
    # psa_import_key failure is also a safe rejection path:
    # key type / curve not supported → import fails safely with no crash
    "[INFO] psa_import_key failed:",
]

PKEY_CAPABILITY_MISMATCH_TRIAGE_PATTERNS = [
    "[TRIAGE] signing with public-only key succeeded",
    "[WARNING] public-only key signing succeeded!",
]

RSA_INVALID_KEY_SIGN_SAFE_REJECT_PATTERNS = [
    "[SAFE] invalid RSA key signing rejected",
]

RSA_INVALID_KEY_SIGN_TRIAGE_PATTERNS = [
    "[TRIAGE] signing with invalid RSA key succeeded",
    "[WARNING] invalid RSA key signing succeeded",
]

INVALID_PARAM_SETUP_SAFE_REJECT_PATTERNS = [
    "[OK] source rejected invalid CCM",
    "[OK] target rejected invalid CCM",
]

INVALID_PARAM_SETUP_NORMAL_PATTERNS = [
    "[OK] source accepted valid CCM tag length",
    "[OK] target accepted valid CCM tag length",
]

INVALID_PARAM_SETUP_TRIAGE_PATTERNS = [
    "[INFO] source rejected valid CCM tag length",
    "[INFO] target rejected valid CCM tag length",
    "[INFO] invalid_parameter_setup_oracle:",
]

HARNESS_ERROR_PATTERNS = [
    "read A failed",
    "read B failed",
    "prepare_output_with_canary failed",
    "mbedtls_mpi_lset failed",
    "input construction failed",
    "BN_new failed",
]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def read_text_field(record: Dict[str, Any]) -> str:
    compile_part = record.get("compile", {}) or {}
    run_part = record.get("run", {}) or {}

    return "\n".join([
        str(compile_part.get("stdout", "")),
        str(compile_part.get("stderr", "")),
        str(run_part.get("stdout", "")),
        str(run_part.get("stderr", "")),
    ])


def contains_any(text: str, patterns: List[str]) -> bool:
    lower = text.lower()
    return any(p.lower() in lower for p in patterns)


def template_info(record: Dict[str, Any]) -> Dict[str, Any]:
    value = record.get("template", {})
    return value if isinstance(value, dict) else {}


def record_harness_family(record: Dict[str, Any], result: Dict[str, Any] | None = None) -> str:
    tmpl = template_info(record)
    if tmpl.get("harness_family"):
        return str(tmpl.get("harness_family"))
    if result and result.get("harness_family"):
        return str(result.get("harness_family"))
    return ""


def record_oracle_type(record: Dict[str, Any], result: Dict[str, Any] | None = None) -> str:
    tmpl = template_info(record)
    if tmpl.get("oracle_type"):
        return str(tmpl.get("oracle_type"))
    if result and result.get("oracle_type"):
        return str(result.get("oracle_type"))
    return ""


def record_target_api(record: Dict[str, Any]) -> str:
    return str(template_info(record).get("target_api") or "")


def record_target_library(record: Dict[str, Any]) -> str:
    return str(template_info(record).get("target_library") or record.get("library") or "")


def ast_mask_selection_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    selection = record.get("ast_mask_selection", {})
    if not isinstance(selection, dict) or not selection:
        return {}
    summary = selection.get("summary") if isinstance(selection.get("summary"), dict) else selection
    out = {
        "available": True,
        "source_file": selection.get("source_file", summary.get("source_file", "")),
        "harness_family": summary.get("harness_family", ""),
        "trigger_apis": summary.get("trigger_apis", []),
        "selected_count": summary.get("selected_count"),
        "by_suggested_use": summary.get("by_suggested_use", {}),
        "by_role": summary.get("by_role", {}),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def is_reference_artifact(record: Dict[str, Any]) -> bool:
    source = str(record.get("source", ""))
    relative = str(record.get("relative_source", ""))
    name = Path(source).name or Path(relative).name
    return record.get("library") == "unknown" and name in {"poc_original.c", "poc_original.cpp"}


def is_x509_asn1_inner_boundary_record(record: Dict[str, Any], text: str, result: Dict[str, Any]) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    if record_harness_family(record, result) in {"x509_asn1_inner_boundary", "asn1_inner_boundary"}:
        return True
    if record_oracle_type(record, result) == "inner_asn1_boundary_semantic_oracle":
        return True
    return (
        "X509_ASN1_INNER_SUBSTRUCTURE_BOUNDARY" in joined
        or "MBEDTLS-POC-0017" in joined
        or "x509_asn1_inner_boundary" in joined
        or "malformed X509/ASN1 inner-boundary input" in joined
    )


def is_return_code_outlen_record(record: Dict[str, Any], text: str, result: Dict[str, Any]) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    if record_harness_family(record, result) == "return_code_outlen_semantic":
        return True
    if record_oracle_type(record, result) == "invalid_padding_output_length_oracle":
        return True
    return (
        "CIPHER_PKCS_PADDING_INVALID_OUTLEN_UNDERFLOW" in joined
        or "MBEDTLS-POC-0004" in joined
        or "invalid_padding_output_length_oracle" in joined
        or "final_len remained zero" in joined
        or "finish_olen" in joined
    )


def is_bignum_arithmetic_semantic_record(record: Dict[str, Any], text: str, result: Dict[str, Any]) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    if record_harness_family(record, result) == "bignum_arithmetic_semantic":
        return True
    if record_oracle_type(record, result) == "bignum_negative_result_rejection_oracle":
        return True
    return (
        "BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY" in joined
        or "MBEDTLS-POC-0002" in joined
        or "bignum_negative_result_rejection_oracle" in joined
        or "lhs<rhs unsigned subtraction" in joined
        or "negative mbedTLS absolute subtraction" in joined
    )


def is_openssl_bn_usub_semantic_projection(record: Dict[str, Any], text: str, result: Dict[str, Any]) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)

    if result.get("library") != "openssl":
        return False

    if "BN_usub" not in joined and "openssl_BN_usub" not in joined:
        return False

    if not is_bignum_arithmetic_semantic_record(record, text, result):
        return False

    has_projection_label = contains_any(text, BIGNUM_BN_USUB_SEMANTIC_PROJECTION_PATTERNS)
    has_lhs_lt_rhs_success = (
        re.search(r"\bcmp\s*=\s*-1\b", text) is not None
        and re.search(r"\bret\s*=\s*1\b", text) is not None
    )

    return has_projection_label or has_lhs_lt_rhs_success


def is_bignum_serialization_buffer_boundary_record(
    record: Dict[str, Any],
    text: str,
    result: Dict[str, Any],
) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    if record_harness_family(record, result) == "buffer_canary_boundary":
        return True
    if record_oracle_type(record, result) in {
        "bignum_serialization_buffer_boundary_oracle",
        "canary_after_output_limbs_and_return_code",
    }:
        return True
    return (
        "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER" in joined
        or "MBEDTLS-POC-0001" in joined
        or "bignum_serialization_buffer_boundary_oracle" in joined
        or "BN_signed_bn2bin" in joined
        or "target rejected small output buffer and canary intact" in joined
        or "target serialized into provided buffer; canary intact" in joined
    )


def is_openssl_bn_signed_bn2bin_buffer_boundary_record(
    record: Dict[str, Any],
    text: str,
    result: Dict[str, Any],
) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)

    return (
        result.get("library") == "openssl"
        and "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER" in joined
        and "BN_signed_bn2bin" in joined
        and is_bignum_serialization_buffer_boundary_record(record, text, result)
    )


def is_object_state_lifecycle_record(
    record: Dict[str, Any],
    text: str,
    result: Dict[str, Any],
) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    if record_harness_family(record, result) == "object_state_lifecycle":
        return True
    if record_oracle_type(record, result) in {"stale_pointer_length_state_oracle", "object_lifecycle_state_oracle"}:
        return True
    return (
        "ASN1_STORE_NAMED_DATA_ZERO_LEN_STALE_STATE" in joined
        or "MBEDTLS-POC-0005" in joined
        or "object_state_lifecycle" in joined
        or "ASN1_STRING_set" in joined
        or "asn1_store_named_data" in joined
        or "safe reallocation after zero-length" in joined
    )


def is_mac_context_lifecycle_record(
    record: Dict[str, Any],
    text: str,
    result: Dict[str, Any],
) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    if record_harness_family(record, result) == "object_state_lifecycle":
        return True
    if record_oracle_type(record, result) == "mac_context_size_lifecycle_oracle":
        return True
    return (
        "EVP_MAC_GET_SIZE_UNINIT_LIFECYCLE" in joined
        or "OPENSSL-ISSUE-22842" in joined
        or "mac_context_lifecycle" in joined
        or "mac_context_size_lifecycle_oracle" in joined
        or "mbedtls_md_hmac_starts" in joined
        or "EVP_MAC_CTX_get_mac_size" in joined
    )


def is_invalid_param_setup_record(
    record: Dict[str, Any],
    text: str,
    result: Dict[str, Any],
) -> bool:
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    if record_harness_family(record, result) == "invalid_parameter_setup_oracle":
        return True
    if record_oracle_type(record, result) in {"invalid_aead_tag_length_oracle", "invalid_parameter_return_code_oracle"}:
        return True
    return (
        "PSA_AEAD_INVALID_SHORTENED_TAG_SETUP" in joined
        or "MBEDTLS-POC-0028" in joined
        or "invalid_parameter_setup_oracle" in joined
        or "EVP_CIPHER_CTX_ctrl" in joined
        or "CCM shortened tag length" in joined
        or "CCM tag length" in joined
    )


def is_der_pointer_consumption_record(record: Dict[str, Any], text: str, result: Dict[str, Any]) -> bool:
    if record_harness_family(record, result) == "der_pointer_consumption":
        return True
    if record_oracle_type(record, result) == "pointer_consumption_semantic_oracle":
        return True
    markers = [
        str(record.get("relative_source", "")),
        str(record.get("source", "")),
        str(result.get("template_id", "")),
        str(result.get("case_name", "")),
        text,
    ]
    joined = "\n".join(markers)
    return (
        "RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE" in joined
        or "MBEDTLS-POC-0020" in joined
        or "der_pointer_consumption" in joined
        or "trailing garbage unconsumed" in joined
    )


def parse_ret_expected(text: str) -> Dict[str, Any]:
    ret = None
    expected = None

    m = re.search(r"\bret\s*=\s*(-?\d+)", text)
    if m:
        ret = int(m.group(1))

    m = re.search(r"\bexpected\s*=\s*(-?\d+)", text)
    if m:
        expected = int(m.group(1))

    return {
        "ret": ret,
        "expected": expected,
        "ret_matches_expected": ret is not None and expected is not None and ret == expected,
    }


def load_manifest_for_record(record: Dict[str, Any]) -> Dict[str, Any]:
    source = record.get("source", "")
    if not source:
        return {}

    src_path = Path(source)
    if not src_path.exists():
        return {}

    # Supported forms:
    #   default_mbedtls.c     -> default_manifest.yaml
    #   case_0000_mbedtls.c   -> case_0000_manifest.yaml
    stem = src_path.stem

    if stem.startswith("case_"):
        parts = stem.split("_")
        if len(parts) >= 2:
            prefix = "_".join(parts[:2])
        else:
            prefix = parts[0]
    else:
        prefix = stem.split("_", 1)[0]

    manifest = src_path.parent / f"{prefix}_manifest.yaml"

    if not manifest.exists():
        return {}

    try:
        with manifest.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def classify_record(record: Dict[str, Any]) -> Dict[str, Any]:
    status = record.get("status", "")
    text = read_text_field(record)
    run_part = record.get("run", {}) or {}
    compile_part = record.get("compile", {}) or {}

    ret_info = parse_ret_expected(text)

    tmpl = template_info(record)
    result = {
        "source": record.get("source", ""),
        "relative_source": record.get("relative_source", ""),
        "library": record.get("library", ""),
        "template": tmpl,
        "metadata_files": record.get("metadata_files", {}) if isinstance(record.get("metadata_files", {}), dict) else {},
        "ast_mask_selection": ast_mask_selection_summary(record),
        "template_id": tmpl.get("template_id", ""),
        "source_template_id": tmpl.get("source_template_id", ""),
        "harness_family": tmpl.get("harness_family", ""),
        "oracle_type": tmpl.get("oracle_type", ""),
        "target_library": record_target_library(record),
        "target_api": record_target_api(record),
        "raw_status": status,
        "verdict": "",
        "reason": "",
        "exit_code": run_part.get("returncode"),
        "compile_returncode": compile_part.get("returncode"),
        "run_timeout": run_part.get("timeout", False),
        "compile_timeout": compile_part.get("timeout", False),
        "ret": ret_info["ret"],
        "expected": ret_info["expected"],
        "ret_matches_expected": ret_info["ret_matches_expected"],
    }

    manifest = load_manifest_for_record(record)
    if manifest:
        result["template_id"] = result.get("template_id") or manifest.get("template_id", "")
        result["case_name"] = manifest.get("case_name", "")
        result["mutation_mapping"] = manifest.get("mapping", {})

    if status == "dry_run":
        result["verdict"] = "not_executed"
        result["reason"] = "Dry-run compile command was recorded but the harness was not compiled or executed."
        return result

    if is_reference_artifact(record):
        result["verdict"] = "reference_artifact_skipped"
        result["reason"] = "Reference PoC artifact is not a generated source/target library harness for verdict analysis."
        return result

    if record.get("library") == "unknown":
        result["verdict"] = "unknown_library_skipped"
        result["reason"] = "Runner could not infer a supported target library from the case filename."
        return result

    if status == "compile_error":
        result["verdict"] = "build_or_template_error"
        result["reason"] = "Compilation failed. This usually indicates an invalid template, missing API, wrong library version, or missing compile flags."
        return result

    if status == "run_timeout":
        result["verdict"] = "timeout"
        result["reason"] = "The harness timed out during execution."
        return result

    if contains_any(text, ASAN_PATTERNS):
        result["verdict"] = "sanitizer_crash"
        result["reason"] = "ASAN-like crash pattern found in output."
        return result

    if contains_any(text, UBSAN_PATTERNS):
        result["verdict"] = "ubsan_crash"
        result["reason"] = "UBSAN-like runtime error pattern found in output."
        return result

    if contains_any(text, DER_TRAILING_GARBAGE_BUG_PATTERNS) and is_der_pointer_consumption_record(record, text, result):
        result["verdict"] = "bug_candidate"
        result["reason"] = "DER parser decoded the leading object but left trailing garbage unconsumed."
        return result

    if contains_any(text, X509_ASN1_INNER_BOUNDARY_BUG_PATTERNS):
        result["verdict"] = "bug_candidate"
        result["reason"] = "X.509/ASN.1 parser accepted malformed inner-boundary DER input."
        return result

    if (
        contains_any(text, RETURN_CODE_OUTLEN_BUG_PATTERNS)
        and is_return_code_outlen_record(record, text, result)
    ):
        result["verdict"] = "bug_candidate"
        result["reason"] = "Invalid-padding finalization failed but the caller-visible output length was polluted."
        return result

    if (
        contains_any(text, MAC_CONTEXT_LIFECYCLE_BUG_PATTERNS)
        and is_mac_context_lifecycle_record(record, text, result)
    ):
        result["verdict"] = "bug_candidate"
        result["reason"] = "MAC context lifecycle crashed or reported a sanitizer signal during state use."
        return result

    if contains_any(text, BUG_PATTERNS):
        result["verdict"] = "bug_candidate"
        result["reason"] = "Harness reported explicit BUG/canary corruption pattern."
        return result

    if contains_any(text, HARNESS_ERROR_PATTERNS):
        result["verdict"] = "harness_input_error"
        result["reason"] = "The generated case failed during input construction or harness setup."
        return result

    if (
        result.get("library") == "mbedtls"
        and status == "run_ok"
        and ret_info["ret"] == -96
        and is_x509_asn1_inner_boundary_record(record, text, result)
    ):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = (
            "Current mbedTLS runner returned MBEDTLS_ERR_ASN1_OUT_OF_DATA "
            "(-96) for MBEDTLS-POC-0017 X.509/ASN.1 inner-boundary input."
        )
        return result

    if ret_info["ret_matches_expected"]:
        result["verdict"] = "fixed_behavior"
        result["reason"] = "Return code matches expected fixed behavior and no bug/crash pattern was observed."
        return result

    if contains_any(text, DER_TRAILING_GARBAGE_SAFE_REJECT_PATTERNS) and is_der_pointer_consumption_record(record, text, result):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = "DER parser rejected the trailing-garbage input."
        return result

    if contains_any(text, X509_ASN1_INNER_BOUNDARY_SAFE_REJECT_PATTERNS):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = "X.509/ASN.1 parser rejected malformed inner-boundary DER input."
        return result

    if (
        contains_any(text, RETURN_CODE_OUTLEN_SAFE_REJECT_PATTERNS)
        and is_return_code_outlen_record(record, text, result)
    ):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = "Invalid-padding finalization failed and the caller-visible output length remained safe."
        return result

    if (
        contains_any(text, RETURN_CODE_OUTLEN_TRIAGE_PATTERNS)
        and is_return_code_outlen_record(record, text, result)
    ):
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = "Invalid-padding input was accepted unexpectedly and needs manual triage."
        return result

    if (
        contains_any(text, BIGNUM_ARITHMETIC_SAFE_REJECT_PATTERNS)
        and is_bignum_arithmetic_semantic_record(record, text, result)
    ):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = (
            "Bignum arithmetic semantic projection rejected or avoided the negative "
            "unsigned/absolute subtraction path."
        )
        return result

    if (
        contains_any(text, BIGNUM_SERIALIZATION_BUFFER_SAFE_REJECT_PATTERNS)
        and is_bignum_serialization_buffer_boundary_record(record, text, result)
    ):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = "Bignum serialization rejected a too-small target buffer and preserved the canary."
        return result

    if (
        contains_any(text, BIGNUM_SERIALIZATION_BUFFER_NORMAL_PATTERNS)
        and is_openssl_bn_signed_bn2bin_buffer_boundary_record(record, text, result)
    ):
        result["verdict"] = "normal_expected_behavior"
        result["reason"] = (
            "OpenSSL BN_signed_bn2bin serialized into a sufficiently large caller-provided "
            "buffer and preserved the canary. This is expected normal serialization behavior, "
            "not a migrated bug candidate."
        )
        return result

    if is_openssl_bn_usub_semantic_projection(record, text, result):
        result["verdict"] = "semantic_projection_limitation"
        result["reason"] = (
            "OpenSSL BN_usub returned success for lhs<rhs under its low-level "
            "unsigned-subtraction precondition. This is expected OpenSSL behavior "
            "or a semantic projection limitation, not a migrated bug candidate."
        )
        return result

    if (
        contains_any(text, BIGNUM_ARITHMETIC_TRIAGE_PATTERNS)
        and is_bignum_arithmetic_semantic_record(record, text, result)
    ):
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = (
            "Bignum arithmetic semantic projection reached a normal or mismatched "
            "arithmetic path that needs manual review."
        )
        return result

    if (
        contains_any(text, OBJECT_STATE_LIFECYCLE_SAFE_PATTERNS)
        and is_object_state_lifecycle_record(record, text, result)
    ):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = (
            "Object state lifecycle handled safely: zero-length update did not create stale "
            "pointer-length state; later reuse completed without crash."
        )
        return result

    if (
        contains_any(text, MAC_CONTEXT_LIFECYCLE_TRIAGE_PATTERNS)
        and is_mac_context_lifecycle_record(record, text, result)
    ):
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = "MAC context lifecycle semantic projection reached unexpected state or size behavior."
        return result

    if (
        contains_any(text, MAC_CONTEXT_LIFECYCLE_SAFE_PATTERNS)
        and is_mac_context_lifecycle_record(record, text, result)
    ):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = (
            "MAC context lifecycle semantic projection behaved safely: pre-setup "
            "use was rejected without crash and/or initialized size matched."
        )
        return result

    if (
        contains_any(text, OBJECT_STATE_LIFECYCLE_TRIAGE_PATTERNS)
        and is_object_state_lifecycle_record(record, text, result)
    ):
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = "Object state lifecycle behavior needs manual review."
        return result

    if (
        contains_any(text, INVALID_PARAM_SETUP_BUG_PATTERNS)
        and is_invalid_param_setup_record(record, text, result)
    ):
        result["verdict"] = "bug_candidate"
        result["reason"] = "Invalid AEAD setup parameter (e.g., CCM tag length) was accepted when it should be rejected."
        return result

    if (
        contains_any(text, INVALID_PARAM_SETUP_SAFE_REJECT_PATTERNS)
        and is_invalid_param_setup_record(record, text, result)
    ):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = "Invalid AEAD setup parameter (e.g., invalid CCM tag length) was correctly rejected."
        return result

    if (
        contains_any(text, INVALID_PARAM_SETUP_NORMAL_PATTERNS)
        and is_invalid_param_setup_record(record, text, result)
    ):
        result["verdict"] = "normal_expected_behavior"
        result["reason"] = (
            "Valid AEAD setup parameter (e.g., valid CCM tag length) was accepted. "
            "This is expected normal behavior, not a migrated bug candidate."
        )
        return result

    if (
        contains_any(text, INVALID_PARAM_SETUP_TRIAGE_PATTERNS)
        and is_invalid_param_setup_record(record, text, result)
    ):
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = "AEAD setup parameter behavior needs manual review."
        return result

    if contains_any(text, RSA_INVALID_KEY_SIGN_SAFE_REJECT_PATTERNS):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = (
            "Invalid or tiny RSA key signing was safely rejected by the target library "
            "(rsa_invalid_key_sign_rejection_oracle: import/init/sign returned an error without crash)."
        )
        return result

    if contains_any(text, PKEY_CAPABILITY_MISMATCH_SAFE_REJECT_PATTERNS):
        result["verdict"] = "safe_reject_behavior"
        result["reason"] = (
            "Public-only key signing was safely rejected by the target library "
            "(capability mismatch oracle: PSA_ERROR_NOT_PERMITTED or equivalent error return)."
        )
        return result

    if contains_any(text, RSA_INVALID_KEY_SIGN_TRIAGE_PATTERNS):
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = (
            "Signing with invalid or tiny RSA key succeeded. Manual review required "
            "to verify oracle correctness and key construction."
        )
        return result

    if contains_any(text, PKEY_CAPABILITY_MISMATCH_TRIAGE_PATTERNS):
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = (
            "Signing with public-only key succeeded — capability mismatch not detected. "
            "Manual review required to verify oracle correctness."
        )
        return result

    if contains_any(text, SAFE_PATTERNS):
        result["verdict"] = "safe_behavior"
        result["reason"] = "Safe output pattern was observed and no bug/crash pattern was found."
        return result

    if status == "run_ok":
        result["verdict"] = "normal_behavior_needs_triage"
        result["reason"] = "Program exited normally, but no strong safe/fixed oracle pattern was found."
        return result

    if status == "run_nonzero":
        result["verdict"] = "nonzero_needs_triage"
        result["reason"] = "Program exited with nonzero code but no sanitizer or explicit BUG pattern was found."
        return result

    result["verdict"] = "unknown"
    result["reason"] = f"Unhandled raw status: {status}"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze runner jsonl results and produce verdict summary.")
    parser.add_argument(
        "--input",
        default="runner/results/run_default.jsonl",
        help="Input runner jsonl path.",
    )
    parser.add_argument(
        "--output",
        default="runner/results/run_default.summary.json",
        help="Output summary json path.",
    )
    parser.add_argument(
        "--case-output",
        default="",
        help="Optional per-case verdict jsonl path.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"[ERROR] input result not found: {input_path}")
        return 1

    records = load_jsonl(input_path)
    cases = [classify_record(r) for r in records]

    verdict_counter = Counter(c["verdict"] for c in cases)
    raw_status_counter = Counter(c["raw_status"] for c in cases)
    library_counter = Counter(c.get("library", "") for c in cases)
    harness_family_counter = Counter(c.get("harness_family", "") for c in cases if c.get("harness_family"))
    oracle_type_counter = Counter(c.get("oracle_type", "") for c in cases if c.get("oracle_type"))
    target_api_counter = Counter(c.get("target_api", "") for c in cases if c.get("target_api"))

    summary = {
        "input": str(input_path),
        "total_cases": len(cases),
        "verdict_counts": dict(verdict_counter),
        "raw_status_counts": dict(raw_status_counter),
        "library_counts": dict(library_counter),
        "harness_family_counts": dict(harness_family_counter),
        "oracle_type_counts": dict(oracle_type_counter),
        "target_api_counts": dict(target_api_counter),
        "cases": cases,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    if args.case_output:
        case_out = Path(args.case_output)
        case_out.parent.mkdir(parents=True, exist_ok=True)
        with case_out.open("w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")

    print(f"[OK] summary written to {output_path}")
    print(f"[INFO] total cases: {len(cases)}")
    print(f"[INFO] verdict counts: {dict(verdict_counter)}")
    print(f"[INFO] raw status counts: {dict(raw_status_counter)}")
    print(f"[INFO] library counts: {dict(library_counter)}")
    print(f"[INFO] harness family counts: {dict(harness_family_counter)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

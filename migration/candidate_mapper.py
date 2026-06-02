import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


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


def load_optional_yaml(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {}
    return load_yaml(path)


def infer_selected_mask_units_path(mask_report_path: Optional[Path]) -> Optional[Path]:
    if mask_report_path is None:
        return None
    candidate = mask_report_path.parent / "selected_mask_units.yaml"
    return candidate if candidate.exists() else None


def compact_selected_unit(unit: Dict[str, Any], max_code_chars: int = 220) -> Dict[str, Any]:
    keep = [
        "unit_id",
        "role",
        "mask_level",
        "placeholder",
        "suggested_use",
        "function",
        "code",
        "selection_reason",
        "source",
    ]
    out = {key: unit.get(key) for key in keep if unit.get(key) not in (None, "", [])}
    if "code" in out:
        out["code"] = " ".join(str(out["code"]).split())[:max_code_chars]
    if "selection_reason" in out:
        out["selection_reason"] = " ".join(str(out["selection_reason"]).split())[:max_code_chars]
    return out


def selected_units_by_use(selected_report: Dict[str, Any], limit_per_use: int = 5) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for unit in selected_report.get("selected_units", []) or []:
        if not isinstance(unit, dict):
            continue
        key = str(unit.get("suggested_use") or "unspecified")
        bucket = grouped.setdefault(key, [])
        if len(bucket) < limit_per_use:
            bucket.append(compact_selected_unit(unit))
    return grouped


def selected_units_summary(selected_report: Dict[str, Any]) -> Dict[str, Any]:
    if not selected_report:
        return {"available": False}
    units = [u for u in selected_report.get("selected_units", []) or [] if isinstance(u, dict)]
    selection_summary = selected_report.get("selection_summary", {})
    if not isinstance(selection_summary, dict):
        selection_summary = {}
    return {
        "available": True,
        "template_id": selected_report.get("template_id", ""),
        "harness_family": selected_report.get("harness_family", ""),
        "trigger_apis": selected_report.get("trigger_apis", []),
        "selected_count": len(units),
        "by_role": selection_summary.get("by_role", {}),
        "by_mask_level": selection_summary.get("by_mask_level", {}),
        "by_suggested_use": selection_summary.get("by_suggested_use", {}),
    }


def selected_ast_alignment(selected_report: Dict[str, Any], api: str) -> Dict[str, Any]:
    summary = selected_units_summary(selected_report)
    if not summary.get("available"):
        return summary
    grouped = selected_units_by_use(selected_report)
    trigger_units = grouped.get("migrate_api_call", [])
    oracle_units = grouped.get("preserve_oracle", [])
    return {
        **summary,
        "candidate_api": api,
        "migration_relevant_units": {
            "migrate_api_call": trigger_units,
            "mutate_value": grouped.get("mutate_value", []),
            "mutate_api_argument": grouped.get("mutate_api_argument", []),
            "preserve_oracle": oracle_units,
            "preserve_input_preparation": grouped.get("preserve_input_preparation", []),
        },
        "alignment_note": (
            "Candidate scoring considered selected AST-lite units for source trigger calls, "
            "mutation points, input construction, and oracle observability."
        ),
    }


def infer_harness_family(mask_report: Dict[str, Any], selected_report: Optional[Dict[str, Any]] = None) -> str:
    selected_report = selected_report or {}
    poc_pattern = mask_report.get("poc_pattern", {})
    return str(
        selected_report.get("harness_family")
        or mask_report.get("harness_family")
        or poc_pattern.get("harness_family")
        or ""
    )


def weighted_score(scores: Dict[str, int]) -> int:
    return round(
        0.15 * scores.get("operation_family", 0)
        + 0.20 * scores.get("function_behavior", 0)
        + 0.20 * scores.get("parameter_structure", 0)
        + 0.30 * scores.get("vulnerability_path", 0)
        + 0.15 * scores.get("harness_feasibility", 0)
    )


def decide(scores: Dict[str, int]) -> str:
    final = weighted_score(scores)
    vuln_path = scores.get("vulnerability_path", 0)

    if final >= 75 and vuln_path >= 70:
        return "generate"
    if final >= 55 and vuln_path >= 50:
        return "needs_llm_review"
    return "skip"


def migration_applicability_for_candidate(
    decision: str,
    scores: Dict[str, int],
    reason: str,
    lost: List[str],
) -> Dict[str, str]:
    if decision == "generate":
        return {
            "migration_applicability": "applicable",
            "migration_reason": "Candidate preserves the required vulnerability path well enough for automatic migration generation.",
        }

    if decision == "skip":
        lost_set = set(lost or [])
        if {
            "manual_output_limb_boundary_control",
            "direct_canary_after_output_limbs",
        } & lost_set:
            migration_reason = (
                "Functionally related but migration_not_applicable for automatic generation: "
                "vulnerability-path mismatch; missing manual output limb boundary control; "
                "missing direct canary after output limbs."
            )
        else:
            migration_reason = (
                "migration_not_applicable for automatic generation because the candidate "
                "does not preserve the required vulnerability path."
            )

        return {
            "migration_applicability": "migration_not_applicable",
            "migration_reason": migration_reason,
        }

    return {}


def make_candidate(
    library: str,
    api: str,
    scores: Dict[str, int],
    reason: str,
    parameter_mapping: Dict[str, Any],
    preserved: List[str],
    lost: List[str],
    selected_report: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    final = weighted_score(scores)
    decision = decide(scores)
    applicability = migration_applicability_for_candidate(
        decision=decision,
        scores={**scores, "final": final},
        reason=reason,
        lost=lost,
    )
    candidate = {
        "target_library": library,
        "target_api": api,
        "library": library,
        "api": api,
        "scores": {
            **scores,
            "final": final,
        },
        "decision": decision,
        "reason": reason,
        **applicability,
        "parameter_mapping": parameter_mapping,
        "preserved_vulnerability_features": preserved,
        "lost_or_weakened_features": lost,
    }
    if selected_report:
        candidate["ast_mask_alignment"] = selected_ast_alignment(selected_report, api)
    if extra:
        candidate.update(extra)
    return candidate


def candidates_for_mpi_write_string(mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        make_candidate(
            library="openssl",
            api="BN_bn2binpad",
            scores={
                "operation_family": 80,
                "function_behavior": 65,
                "parameter_structure": 60,
                "vulnerability_path": 90,
                "harness_feasibility": 85,
            },
            reason=(
                "BN_bn2binpad serializes a BIGNUM into a caller-provided output "
                "buffer with an explicit length. It preserves the key boundary-risk "
                "path, although it does not preserve radix-based text formatting."
            ),
            parameter_mapping={
                "[VALUE]": "BN_set_word(X, abs(VALUE)) plus BN_set_negative(X, 1) for negative values",
                "[BUFLEN]": "BN_bn2binpad third argument: tolen",
                "[CANARY_SIZE]": "same canary region after caller buffer",
                "[RADIX]": "no direct counterpart; target serializes big-endian binary",
                "X": "BIGNUM *X",
                "buf": "unsigned char *to",
            },
            preserved=[
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
            lost=[
                "radix_parameter",
                "textual_sign_byte_before_digits",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_signed_bn2bin",
            scores={
                "operation_family": 80,
                "function_behavior": 75,
                "parameter_structure": 70,
                "vulnerability_path": 85,
                "harness_feasibility": 80,
            },
            reason=(
                "BN_signed_bn2bin is closer to the negative integer serialization path "
                "because it preserves signed binary encoding and caller-provided output "
                "buffer length. It is a strong candidate if the target OpenSSL version "
                "supports this API."
            ),
            parameter_mapping={
                "[VALUE]": "BN_set_word plus BN_set_negative",
                "[BUFLEN]": "BN_signed_bn2bin third argument: tolen",
                "[CANARY_SIZE]": "same canary guard layout",
                "[RADIX]": "no direct counterpart; signed binary encoding",
                "X": "BIGNUM *X",
                "buf": "unsigned char *to",
            },
            preserved=[
                "negative_integer_path",
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
            lost=[
                "radix_parameter",
                "textual radix string representation",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_bn2hex",
            scores={
                "operation_family": 75,
                "function_behavior": 45,
                "parameter_structure": 30,
                "vulnerability_path": 20,
                "harness_feasibility": 80,
            },
            reason=(
                "BN_bn2hex performs bignum serialization, but returns a "
                "library-allocated string. It does not preserve the caller-provided "
                "small output buffer boundary path."
            ),
            parameter_mapping={
                "[VALUE]": "BIGNUM construction possible",
                "[RADIX]": "hex output is fixed",
                "[BUFLEN]": "no caller-provided buffer length counterpart",
                "[CANARY_SIZE]": "canary oracle not naturally applicable",
            },
            preserved=[
                "bignum_serialization",
            ],
            lost=[
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_bn2dec",
            scores={
                "operation_family": 75,
                "function_behavior": 45,
                "parameter_structure": 30,
                "vulnerability_path": 20,
                "harness_feasibility": 80,
            },
            reason=(
                "BN_bn2dec is semantically related to decimal serialization, but "
                "it returns a library-allocated string and does not expose caller-controlled "
                "output buffer length."
            ),
            parameter_mapping={
                "[VALUE]": "BIGNUM construction possible",
                "[RADIX]": "decimal output is fixed",
                "[BUFLEN]": "no caller-provided buffer length counterpart",
                "[CANARY_SIZE]": "canary oracle not naturally applicable",
            },
            preserved=[
                "bignum_serialization",
            ],
            lost=[
                "caller_provided_output_buffer",
                "explicit_output_buffer_length",
                "library_writes_to_caller_buffer",
                "observable_boundary_oracle",
            ],
        ),
    ]


def candidates_for_mpi_sub_abs(mask_report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        make_candidate(
            library="openssl",
            api="BN_usub",
            scores={
                "operation_family": 85,
                "function_behavior": 70,
                "parameter_structure": 60,
                "vulnerability_path": 45,
                "harness_feasibility": 70,
            },
            reason=(
                "BN_usub is functionally related to unsigned bignum subtraction, "
                "but OpenSSL generally manages BIGNUM expansion internally. The source "
                "pattern depends on output limb boundary control, so vulnerability-path "
                "equivalence is uncertain."
            ),
            parameter_mapping={
                "[A_VALUE]": "BIGNUM *A",
                "[B_VALUE]": "BIGNUM *B",
                "[X_LIMB_COUNT]": "no direct public counterpart for forcing result limb capacity",
                "[CANARY_SIZE]": "not directly applicable unless internal buffer control is exposed",
            },
            preserved=[
                "bignum_subtraction",
                "A_B_operand_relation",
            ],
            lost=[
                "manual_output_limb_boundary_control",
                "direct_canary_after_output_limbs",
            ],
        ),
        make_candidate(
            library="openssl",
            api="BN_sub",
            scores={
                "operation_family": 85,
                "function_behavior": 75,
                "parameter_structure": 60,
                "vulnerability_path": 40,
                "harness_feasibility": 75,
            },
            reason=(
                "BN_sub supports signed subtraction behavior, but the original "
                "mbedtls_mpi_sub_abs pattern is tied to output limb allocation and "
                "negative-result boundary checks. The migration should be reviewed "
                "rather than directly generated."
            ),
            parameter_mapping={
                "[A_VALUE]": "BIGNUM *A",
                "[B_VALUE]": "BIGNUM *B",
                "[X_LIMB_COUNT]": "no direct public equivalent",
                "[CANARY_SIZE]": "not naturally applicable",
            },
            preserved=[
                "bignum_subtraction",
                "signed_result_behavior",
            ],
            lost=[
                "manual_output_limb_boundary_control",
                "direct_canary_after_output_limbs",
            ],
        ),
    ]


def candidates_for_null_deref_dispatch(mask_report: Dict[str, Any], selected_report: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    template_id = mask_report.get("template_id", "")
    source_api = mask_report.get("source_api", "")
    common_preserved = [
        "signature verification dispatch path",
        "key object/type mismatch reaches generic verification API",
        "return-code or sanitizer observable oracle",
        "safe rejection can be distinguished from crash/null-deref behavior",
    ]
    common_lost = [
        "exact mbedTLS opaque PSA key representation is not preserved",
        "exact mbedTLS numeric error code is not preserved",
        "target adapter must construct an incompatible OpenSSL EVP_PKEY scenario",
    ]

    return [
        make_candidate(
            library="openssl",
            api="EVP_DigestVerify",
            scores={
                "operation_family": 86,
                "function_behavior": 76,
                "parameter_structure": 64,
                "vulnerability_path": 68,
                "harness_feasibility": 78,
            },
            reason=(
                "EVP_DigestVerify exercises OpenSSL generic signature verification dispatch. "
                "A migrated harness can construct an incompatible key/signature setup and observe "
                "whether the target rejects safely or reaches a crash/null-deref-like path. The "
                "source opaque-PSA-key detail is not identical, so adapter generation should keep "
                "this as a review-required candidate."
            ),
            parameter_mapping={
                "source verify API": "EVP_DigestVerify or EVP_DigestVerifyFinal on an EVP_MD_CTX",
                "PK_VERIFY_TYPE": "OpenSSL padding/key-type setup such as RSA-PSS vs incompatible EVP_PKEY",
                "MD_ALG": "EVP_MD such as EVP_sha256()",
                "hash/input buffer": "message bytes passed through DigestVerifyUpdate or direct verify path",
                "signature buffer": "signature bytes supplied to EVP_DigestVerify/Final",
                "oracle": "safe <=0 return or sanitizer/null-deref crash evidence",
                "cleanup": "EVP_MD_CTX_free and EVP_PKEY_free",
            },
            preserved=common_preserved,
            lost=common_lost,
            selected_report=selected_report,
            extra={
                "source_template_id": template_id,
                "source_api": source_api,
            },
        ),
        make_candidate(
            library="openssl",
            api="EVP_DigestVerifyInit",
            scores={
                "operation_family": 84,
                "function_behavior": 72,
                "parameter_structure": 66,
                "vulnerability_path": 62,
                "harness_feasibility": 82,
            },
            reason=(
                "EVP_DigestVerifyInit is the setup entry point for OpenSSL verification dispatch. "
                "It can expose safe rejection of incompatible key types early, but by itself may not "
                "reach the full verify/final dispatch path, so it is a weaker review candidate."
            ),
            parameter_mapping={
                "source verify setup": "EVP_DigestVerifyInit with EVP_MD_CTX and EVP_PKEY",
                "PK_VERIFY_TYPE": "OpenSSL key/padding configuration before or after init",
                "MD_ALG": "EVP_MD such as EVP_sha256()",
                "oracle": "init return code plus sanitizer/crash evidence",
                "cleanup": "EVP_MD_CTX_free and EVP_PKEY_free",
            },
            preserved=[
                "generic signature verification dispatch setup",
                "key object/type mismatch observability",
                "return-code oracle",
            ],
            lost=[
                "full verify finalization path may not be reached",
                *common_lost,
            ],
            selected_report=selected_report,
            extra={
                "source_template_id": template_id,
                "source_api": source_api,
            },
        ),
    ]


def candidates_for_der_pointer_consumption(mask_report: Dict[str, Any], selected_report: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    template_id = mask_report.get("template_id", "")
    source_api = mask_report.get("source_api", "")
    common_preserved = [
        "DER key parser",
        "caller-controlled DER buffer and explicit input length",
        "valid object followed by appended trailing garbage",
        "return pointer success/failure oracle",
        "pointer advancement oracle via const unsigned char **ppin",
    ]
    common_lost = [
        "exact mbedTLS numeric error code is not preserved",
        "target must explicitly check consumed pointer against full input length",
    ]

    return [
        make_candidate(
            library="openssl",
            api="d2i_RSAPrivateKey",
            scores={
                "operation_family": 95,
                "function_behavior": 95,
                "parameter_structure": 90,
                "vulnerability_path": 95,
                "harness_feasibility": 90,
            },
            reason=(
                "Strong RSA-private DER candidate. d2i_RSAPrivateKey decodes a PKCS#1 "
                "RSAPrivateKey from caller-provided DER and advances the input pointer, "
                "which preserves the top-level exact-consumption oracle selected from the source AST."
            ),
            parameter_mapping={
                "DER buffer": "const unsigned char *p initialized to der",
                "DER length": "long length argument to d2i_RSAPrivateKey",
                "source parse success/failure": "RSA * return pointer is NULL/non-NULL",
                "top-level consumption oracle": "consumed_len = p - der; compare consumed_len with der_len",
                "cleanup": "RSA_free(decoded RSA object)",
            },
            preserved=[
                *common_preserved,
                "RSA private key path",
                "PKCS#1 RSAPrivateKey top-level ASN.1 SEQUENCE",
            ],
            lost=common_lost,
            selected_report=selected_report,
            extra={
                "source_template_id": template_id,
                "source_api": source_api,
                "required_features": [
                    "PKCS#1 RSA private DER input",
                    "appended trailing garbage after the top-level SEQUENCE",
                    "check returned RSA pointer",
                    "check p == der + der_len after success",
                    "free returned RSA with RSA_free",
                ],
            },
        ),
        make_candidate(
            library="openssl",
            api="d2i_PrivateKey",
            scores={
                "operation_family": 90,
                "function_behavior": 85,
                "parameter_structure": 88,
                "vulnerability_path": 85,
                "harness_feasibility": 88,
            },
            reason=(
                "Applicable generic private-key DER candidate. With EVP_PKEY_RSA it preserves "
                "the RSA private-key parse path and exposes pointer advancement, but it weakens "
                "the exact PKCS#1 parser equivalence compared with d2i_RSAPrivateKey."
            ),
            parameter_mapping={
                "DER buffer": "const unsigned char *p initialized to der",
                "DER length": "long length argument to d2i_PrivateKey",
                "source RSA parser choice": "EVP_PKEY_RSA type argument",
                "source parse success/failure": "EVP_PKEY * return pointer is NULL/non-NULL",
                "top-level consumption oracle": "consumed_len = p - der; compare consumed_len with der_len",
                "cleanup": "EVP_PKEY_free(decoded key)",
            },
            preserved=[
                "DER private key parser",
                "RSA private key path when type is EVP_PKEY_RSA",
                *common_preserved[1:],
            ],
            lost=[
                "generic EVP private-key path is less RSA-specific than mbedtls_rsa_parse_key",
                "may accept PKCS#8 PrivateKeyInfo as well as key-specific formats",
                *common_lost,
            ],
            selected_report=selected_report,
            extra={
                "source_template_id": template_id,
                "source_api": source_api,
                "required_features": [
                    "pass type EVP_PKEY_RSA",
                    "construct RSA private DER plus trailing bytes",
                    "check returned EVP_PKEY pointer",
                    "check pointer advancement for exact input consumption",
                    "free returned EVP_PKEY with EVP_PKEY_free",
                ],
            },
        ),
        make_candidate(
            library="openssl",
            api="d2i_RSA_PUBKEY",
            scores={
                "operation_family": 90,
                "function_behavior": 82,
                "parameter_structure": 88,
                "vulnerability_path": 80,
                "harness_feasibility": 84,
            },
            reason=(
                "Applicable RSA public-key DER candidate. It preserves a public RSA DER parse path "
                "and exposes pointer advancement, but the target input shape is SubjectPublicKeyInfo "
                "rather than the raw PKCS#1 RSAPublicKey shape."
            ),
            parameter_mapping={
                "DER buffer": "const unsigned char *p initialized to der",
                "DER length": "long length argument to d2i_RSA_PUBKEY",
                "source public parser": "d2i_RSA_PUBKEY target call",
                "source parse success/failure": "RSA * return pointer is NULL/non-NULL",
                "top-level consumption oracle": "consumed_len = p - der; compare consumed_len with der_len",
                "cleanup": "RSA_free(decoded RSA object)",
            },
            preserved=[
                "DER public key parser",
                "RSA public key path",
                *common_preserved[1:],
            ],
            lost=[
                "SubjectPublicKeyInfo public-key shape differs from raw PKCS#1 RSAPublicKey",
                *common_lost,
            ],
            selected_report=selected_report,
            extra={
                "source_template_id": template_id,
                "source_api": source_api,
                "required_features": [
                    "RSA public DER input",
                    "append trailing garbage after top-level object",
                    "check returned RSA pointer",
                    "check pointer advancement for exact input consumption",
                    "free returned RSA with RSA_free",
                ],
            },
        ),
        make_candidate(
            library="openssl",
            api="d2i_PUBKEY",
            scores={
                "operation_family": 82,
                "function_behavior": 72,
                "parameter_structure": 86,
                "vulnerability_path": 68,
                "harness_feasibility": 82,
            },
            reason=(
                "Related public-key DER candidate with pointer advancement, but generic EVP public-key "
                "decoding weakens RSA-specific parser-path equivalence. Keep for review unless a recipe "
                "or adapter constrains the key type and object shape."
            ),
            parameter_mapping={
                "DER buffer": "const unsigned char *p initialized to der",
                "DER length": "long length argument to d2i_PUBKEY",
                "source parse success/failure": "EVP_PKEY * return pointer is NULL/non-NULL",
                "top-level consumption oracle": "consumed_len = p - der; compare consumed_len with der_len",
                "cleanup": "EVP_PKEY_free(decoded key)",
            },
            preserved=[
                "DER public key parser",
                "caller-controlled DER buffer and explicit input length",
                "valid object followed by appended trailing garbage",
                "return pointer success/failure oracle",
                "pointer advancement oracle via const unsigned char **ppin",
            ],
            lost=[
                "generic EVP public-key path weakens RSA-specific parser equivalence",
                "target object shape is SubjectPublicKeyInfo rather than raw RSA public key",
                *common_lost,
            ],
            selected_report=selected_report,
            extra={
                "source_template_id": template_id,
                "source_api": source_api,
            },
        ),
        make_candidate(
            library="openssl",
            api="d2i_AutoPrivateKey",
            scores={
                "operation_family": 88,
                "function_behavior": 82,
                "parameter_structure": 88,
                "vulnerability_path": 82,
                "harness_feasibility": 86,
            },
            reason=(
                "Broad private-key DER candidate. It can observe trailing-byte acceptance through "
                "pointer advancement, but auto-detection weakens exact algorithm and container control."
            ),
            parameter_mapping={
                "DER buffer": "const unsigned char *p initialized to der",
                "DER length": "long length argument to d2i_AutoPrivateKey",
                "source parse success/failure": "EVP_PKEY * return pointer is NULL/non-NULL",
                "top-level consumption oracle": "consumed_len = p - der; compare consumed_len with der_len",
                "cleanup": "EVP_PKEY_free(decoded key)",
            },
            preserved=[
                "DER private key parser",
                "auto-detected RSA private key path",
                *common_preserved[1:],
            ],
            lost=[
                "auto-detection weakens exact algorithm/container control",
                "may route through a generic decoder path rather than a single RSA parser",
                *common_lost,
            ],
            selected_report=selected_report,
            extra={
                "source_template_id": template_id,
                "source_api": source_api,
            },
        ),
    ]


def map_candidates(mask_report: Dict[str, Any], selected_report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    template_id = mask_report.get("template_id", "")
    source_api = mask_report.get("source_api", "")
    poc_pattern = mask_report.get("poc_pattern", {})
    selected_report = selected_report or {}
    harness_family = infer_harness_family(mask_report, selected_report)

    if template_id == "BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER":
        candidates = candidates_for_mpi_write_string(mask_report)
    elif template_id == "BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY":
        candidates = candidates_for_mpi_sub_abs(mask_report)
    elif harness_family == "der_pointer_consumption" or template_id == "RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE":
        candidates = candidates_for_der_pointer_consumption(mask_report, selected_report)
    elif harness_family == "null_deref_dispatch":
        candidates = candidates_for_null_deref_dispatch(mask_report, selected_report)
    else:
        candidates = []

    if selected_report:
        for candidate in candidates:
            candidate.setdefault("ast_mask_alignment", selected_ast_alignment(selected_report, candidate.get("api", "")))
            candidate.setdefault("source_template_id", template_id)
            candidate.setdefault("source_api", source_api)

    return {
        "template_id": template_id,
        "source": {
            "library": mask_report.get("source_library", ""),
            "api": source_api,
            "pattern_id": poc_pattern.get("pattern_id"),
            "root_cause_summary": poc_pattern.get("root_cause", {}).get("summary"),
            "vulnerability_path_features": poc_pattern.get("vulnerability_path_features", {}),
            "migration_guidance": poc_pattern.get("migration_guidance", {}),
            "harness_family": harness_family,
            "trigger_apis": selected_report.get("trigger_apis") or mask_report.get("trigger_apis", []),
            "ast_mask_selection": {
                **selected_units_summary(selected_report),
                "selected_units_by_use": selected_units_by_use(selected_report),
            } if selected_report else {"available": False},
        },
        "scoring_policy": {
            "operation_family": 0.15,
            "function_behavior": 0.20,
            "parameter_structure": 0.20,
            "vulnerability_path": 0.30,
            "harness_feasibility": 0.15,
            "decision_rule": {
                "generate": "final >= 75 and vulnerability_path >= 70",
                "needs_llm_review": "final >= 55 and vulnerability_path >= 50",
                "skip": "otherwise",
            },
        },
        "target_candidates": candidates,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Map and score cross-library API migration candidates."
    )
    parser.add_argument(
        "--mask-report",
        default="normalized_templates/bignum/mpi_write_string/mask_report.yaml",
        help="Input mask_report.yaml",
    )
    parser.add_argument(
        "--output",
        default="migration_candidates/bignum/mpi_write_string/candidates.yaml",
        help="Output candidates.yaml",
    )
    parser.add_argument(
        "--selected-mask-units",
        help="Optional selected_mask_units.yaml. If omitted, candidate_mapper looks next to --mask-report.",
    )
    args = parser.parse_args()

    mask_report_path = Path(args.mask_report)
    mask_report = load_yaml(mask_report_path)
    selected_path = Path(args.selected_mask_units) if args.selected_mask_units else infer_selected_mask_units_path(mask_report_path)
    selected_report = load_optional_yaml(selected_path)
    result = map_candidates(mask_report, selected_report=selected_report)
    dump_yaml(Path(args.output), result)

    print(f"[OK] candidates written to {args.output}")
    print(f"[INFO] template_id: {result['template_id']}")
    print(f"[INFO] selected_mask_units_loaded: {bool(selected_report)}")

    if not result["target_candidates"]:
        print("[WARN] no target candidates generated")

    for c in result["target_candidates"]:
        print(
            c["library"],
            c["api"],
            "decision=",
            c["decision"],
            "final=",
            c["scores"]["final"],
            "vuln_path=",
            c["scores"]["vulnerability_path"],
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


SUPPORTED_SIGNATURE_MUTATIONS = {
    "valid_signature",
    "invalid_signature",
    "truncated_signature",
    "all_zero_signature",
    "bitflip_signature",
}

SUPPORTED_DIGEST_MUTATIONS = {
    "matching_digest",
    "wrong_digest_algorithm",
    "wrong_hash_length",
}

SUPPORTED_KEY_MUTATIONS = {
    "matching_key",
    "wrong_key",
}

SUPPORTED_PADDING_MUTATIONS = {
    "rsa_pkcs1_v15",
    "rsa_pss",
    "pss_saltlen_mismatch",
}

SUPPORTED_VERIFY_APIS = {
    "EVP_DigestVerify",
    "EVP_PKEY_verify",
}


@dataclass(frozen=True)
class PkeyVerifyCasePlan:
    supported: bool
    values: Dict[str, str]
    placeholders: Dict[str, Any]
    unsupported_dimensions: List[Dict[str, Any]]
    expected_verdict_class: str
    expected_candidate_types: List[str]


def _unsupported(dimension: str, value: str, reason: str) -> Dict[str, Any]:
    return {
        "dimension": dimension,
        "value": value,
        "reason": reason,
        "unsupported_combo": True,
        "requires_template_extension": True,
    }


def _as_values(matrix_case: Dict[str, Any]) -> Dict[str, str]:
    raw = matrix_case.get("values", {}) or {}
    return {str(k): str(v) for k, v in raw.items()}


def _digest_alg(digest_mutation: str) -> str:
    if digest_mutation == "wrong_digest_algorithm":
        return "EVP_sha512()"
    return "EVP_sha256()"


def _padding_mode(padding_mutation: str) -> str:
    if padding_mutation in {"rsa_pss", "pss_saltlen_mismatch"}:
        return "RSA_PKCS1_PSS_PADDING"
    return "RSA_PKCS1_PADDING"


def _expected_verdict(values: Dict[str, str], unsupported: List[Dict[str, Any]]) -> str:
    if unsupported:
        return "projection_limitation"
    if (
        values.get("signature_mutation") == "valid_signature"
        and values.get("digest_mutation") == "matching_digest"
        and values.get("key_mutation") == "matching_key"
        and values.get("padding_mutation") in {"rsa_pkcs1_v15", "rsa_pss"}
    ):
        return "safe_behavior"
    return "unexpected_success_candidate"


def _hash_initializer(digest_mutation: str) -> Tuple[str, int]:
    if digest_mutation == "wrong_hash_length":
        hash_len = 16
    else:
        hash_len = 32
    data = list(range(1, 65))
    return "{ " + ", ".join(f"0x{x:02x}" for x in data) + " }", hash_len


def _signature_seed_initializer() -> Tuple[str, int]:
    data = [0x42] * 256
    return "{ " + ", ".join(f"0x{x:02x}" for x in data) + " }", len(data)


def _verify_setup_snippet(values: Dict[str, str]) -> str:
    return f"""
    if (!make_rsa_key(KEY_BITS, &sign_key)) {{
        printf("HARNESS_ERROR: failed to generate signing RSA key\\n");
        goto cleanup;
    }}
    if (!make_rsa_key(KEY_BITS, &wrong_key)) {{
        printf("HARNESS_ERROR: failed to generate wrong RSA key\\n");
        goto cleanup;
    }}
    verify_key = ({'wrong_key' if values.get('key_mutation') == 'wrong_key' else 'sign_key'});

    if (strcmp(VERIFY_API_NAME, "EVP_DigestVerify") == 0) {{
        if (!make_digest_signature(sign_key, &signature, &signature_len)) {{
            printf("HARNESS_ERROR: failed to create EVP_DigestVerify baseline signature\\n");
            goto cleanup;
        }}
    }} else if (strcmp(VERIFY_API_NAME, "EVP_PKEY_verify") == 0) {{
        if (!make_pkey_signature(sign_key, &signature, &signature_len)) {{
            printf("HARNESS_ERROR: failed to create EVP_PKEY_verify baseline signature\\n");
            goto cleanup;
        }}
    }} else {{
        printf("HARNESS_ERROR: unsupported verify api %s\\n", VERIFY_API_NAME);
        goto cleanup;
    }}

    apply_signature_mutation(signature, &signature_len, sizeof(signature_storage));
"""


def _verify_call_snippet(values: Dict[str, str]) -> str:
    return """
    if (strcmp(VERIFY_API_NAME, "EVP_DigestVerify") == 0) {
        verify_ret = run_digest_verify(verify_key, signature, signature_len);
    } else if (strcmp(VERIFY_API_NAME, "EVP_PKEY_verify") == 0) {
        verify_ret = run_pkey_verify(verify_key, signature, signature_len);
    } else {
        printf("HARNESS_ERROR: unsupported verify api %s\\n", VERIFY_API_NAME);
        goto cleanup;
    }
"""


def _oracle_snippet(expected_verdict_class: str) -> str:
    return f"""
    printf("[INFO] verify_ret=%d expected=%s api=%s signature_mutation=%s digest_mutation=%s key_mutation=%s padding_mutation=%s\\n",
           verify_ret, EXPECTED_VERDICT_CLASS, VERIFY_API_NAME, SIGNATURE_MUTATION,
           DIGEST_MUTATION, KEY_MUTATION, PADDING_MUTATION);

    if (strcmp(EXPECTED_VERDICT_CLASS, "safe_behavior") == 0) {{
        if (verify_ret == 1) {{
            printf("[OK] baseline valid signature accepted\\n");
            exit_code = 0;
        }} else {{
            printf("[TRIAGE] baseline valid signature rejected ret=%d\\n", verify_ret);
            exit_code = 3;
        }}
    }} else if (strcmp(EXPECTED_VERDICT_CLASS, "unexpected_success_candidate") == 0) {{
        if (verify_ret == 1) {{
            printf("[BUG] unexpected verification success\\n");
            exit_code = 2;
        }} else {{
            printf("[SAFE] rejected invalid signature\\n");
            exit_code = 0;
        }}
    }} else {{
        printf("[TRIAGE] unsupported expected verdict class %s ret=%d\\n", EXPECTED_VERDICT_CLASS, verify_ret);
        exit_code = 4;
    }}
"""


def build_case_plan(matrix_case: Dict[str, Any]) -> PkeyVerifyCasePlan:
    values = _as_values(matrix_case)
    unsupported: List[Dict[str, Any]] = []

    verify_api = values.get("verify_api", "")
    key_type = values.get("key_type", "")
    signature_mutation = values.get("signature_mutation", "")
    digest_mutation = values.get("digest_mutation", "")
    key_mutation = values.get("key_mutation", "")
    padding_mutation = values.get("padding_mutation", "")

    if verify_api not in SUPPORTED_VERIFY_APIS:
        unsupported.append(_unsupported("verify_api", verify_api, "OpenSSL controlled template only supports EVP_DigestVerify and EVP_PKEY_verify"))
    if key_type != "rsa":
        unsupported.append(_unsupported("key_type", key_type, "v0 controlled template only supports RSA key generation"))
    if signature_mutation not in SUPPORTED_SIGNATURE_MUTATIONS:
        unsupported.append(_unsupported("signature_mutation", signature_mutation, "signature mutation requires template extension"))
    if digest_mutation not in SUPPORTED_DIGEST_MUTATIONS:
        unsupported.append(_unsupported("digest_mutation", digest_mutation, "digest mutation requires template extension"))
    if key_mutation not in SUPPORTED_KEY_MUTATIONS:
        unsupported.append(_unsupported("key_mutation", key_mutation, "key mutation requires template extension"))
    if padding_mutation not in SUPPORTED_PADDING_MUTATIONS:
        unsupported.append(_unsupported("padding_mutation", padding_mutation, "padding mutation requires template extension"))

    expected_verdict_class = _expected_verdict(values, unsupported)
    hash_init, hash_len = _hash_initializer(digest_mutation)
    signature_init, signature_len = _signature_seed_initializer()

    placeholders = {
        "[VERIFY_API]": verify_api,
        "[KEY_TYPE]": key_type,
        "[KEY_BITS]": 2048,
        "[PADDING_MODE]": _padding_mode(padding_mutation),
        "[DIGEST_ALG]": _digest_alg(digest_mutation),
        "[HASH_BYTES]": hash_init,
        "[HASH_LEN]": hash_len,
        "[SIGNATURE_BYTES]": signature_init,
        "[SIGNATURE_LEN]": signature_len,
        "[VERIFY_SETUP]": _verify_setup_snippet(values),
        "[VERIFY_CALL]": _verify_call_snippet(values),
        "[VERIFY_ORACLE_OBSERVATION]": _oracle_snippet(expected_verdict_class),
        "[EXPECTED_VERDICT_CLASS]": expected_verdict_class,
        "[SIGNATURE_MUTATION]": signature_mutation,
        "[DIGEST_MUTATION]": digest_mutation,
        "[KEY_MUTATION]": key_mutation,
        "[PADDING_MUTATION]": padding_mutation,
    }

    expected_candidate_types = list(matrix_case.get("expected_candidate_types", []) or [])
    if expected_verdict_class not in expected_candidate_types:
        expected_candidate_types.append(expected_verdict_class)

    return PkeyVerifyCasePlan(
        supported=not unsupported,
        values=values,
        placeholders=placeholders,
        unsupported_dimensions=unsupported,
        expected_verdict_class=expected_verdict_class,
        expected_candidate_types=expected_candidate_types,
    )

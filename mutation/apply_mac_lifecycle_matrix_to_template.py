from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


DEFAULT_ROOT = Path("artifacts/sprints/mac_lifecycle_family_v1")

LIFECYCLE_SEQUENCES = [
    "normal_init_update_final",
    "repeated_final",
    "update_after_final",
    "abort_then_update",
]
INPUT_LENGTHS = [0, 1, 16, 64]
KEY_LENGTHS = ["valid", "zero", "short"]


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f) or {}
    return obj if isinstance(obj, dict) else {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def key_len_value(key_length: str) -> int:
    return {"valid": 16, "zero": 0, "short": 8}[key_length]


def expected_for(sequence: str, key_length: str) -> dict[str, Any]:
    if key_length != "valid":
        return {
            "openssl": "setup_or_init_error_expected",
            "mbedtls_psa": "key_import_or_setup_error_expected",
            "expected_verdict": "needs_manual_triage",
        }
    if sequence == "normal_init_update_final":
        return {"openssl": "success", "mbedtls_psa": "success", "expected_verdict": "normal_success"}
    if sequence in {"repeated_final", "update_after_final"}:
        return {
            "openssl": "permissive_or_legacy_behavior_possible",
            "mbedtls_psa": "bad_state_after_finish",
            "expected_verdict": "behavior_divergence_candidate",
        }
    return {
        "openssl": "no_direct_abort_api_projection",
        "mbedtls_psa": "bad_state_after_abort",
        "expected_verdict": "needs_manual_triage",
    }


def build_matrix() -> dict[str, Any]:
    cases = []
    idx = 0
    for sequence in LIFECYCLE_SEQUENCES:
        for input_len in INPUT_LENGTHS:
            for key_length in KEY_LENGTHS:
                case_id = f"mac_lifecycle_{idx:04d}"
                exp = expected_for(sequence, key_length)
                cases.append(
                    {
                        "case_id": case_id,
                        "family": "mac_lifecycle",
                        "mutation_dimensions": {
                            "lifecycle_sequence": sequence,
                            "algorithm": "cmac_aes",
                            "input_length": input_len,
                            "key_length": key_length,
                        },
                        "expected_baseline": {
                            "openssl": exp["openssl"],
                            "mbedtls_psa": exp["mbedtls_psa"],
                        },
                        "expected_verdict": exp["expected_verdict"],
                    }
                )
                idx += 1
    return {
        "schema_version": 1,
        "family": "mac_lifecycle",
        "case_count": len(cases),
        "cases": cases,
        "notes": [
            "Small controlled v1 matrix: 4 lifecycle sequences x 4 input lengths x 3 key lengths.",
            "OpenSSL abort_then_update is a projection limitation because EVP_MAC has no direct PSA-style abort API.",
        ],
    }


def c_array(name: str, length: int, seed: int) -> str:
    size = max(1, length)
    values = [f"0x{((seed + i * 17) & 0xff):02x}" for i in range(size)]
    return f"static unsigned char {name}[{size}] = {{{', '.join(values)}}};"


def openssl_case(case: dict[str, Any]) -> str:
    dims = case["mutation_dimensions"]
    case_id = case["case_id"]
    sequence = dims["lifecycle_sequence"]
    input_len = int(dims["input_length"])
    key_len = key_len_value(str(dims["key_length"]))
    return f"""#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

{c_array("key_bytes", key_len, 0x31)}
{c_array("input_bytes", input_len, 0x61)}

static void print_result(const char *name, long value) {{
    printf("RESULT {case_id} openssl %s=%ld\\n", name, value);
}}

int main(void) {{
    const char *sequence = "{sequence}";
    size_t key_len = {key_len};
    size_t input_len = {input_len};
    unsigned char out1[64];
    unsigned char out2[64];
    size_t out1_len = 0;
    size_t out2_len = 0;
    int init_ok = 0;
    int update1_ok = 0;
    int final1_ok = 0;
    int final2_ok = -1;
    int update_after_final_ok = -1;
    int projection_limitation = 0;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;
    if (mac != NULL) {{
        ctx = EVP_MAC_CTX_new(mac);
    }}
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (ctx != NULL) {{
        init_ok = EVP_MAC_init(ctx, key_bytes, key_len, params);
    }}
    if (init_ok == 1) {{
        update1_ok = EVP_MAC_update(ctx, input_bytes, input_len);
        final1_ok = EVP_MAC_final(ctx, out1, &out1_len, sizeof(out1));
        if (strcmp(sequence, "repeated_final") == 0) {{
            final2_ok = EVP_MAC_final(ctx, out2, &out2_len, sizeof(out2));
        }} else if (strcmp(sequence, "update_after_final") == 0) {{
            update_after_final_ok = EVP_MAC_update(ctx, input_bytes, input_len);
            final2_ok = EVP_MAC_final(ctx, out2, &out2_len, sizeof(out2));
        }} else if (strcmp(sequence, "abort_then_update") == 0) {{
            projection_limitation = 1;
        }}
    }}

    print_result("init_ok", init_ok);
    print_result("update1_ok", update1_ok);
    print_result("final1_ok", final1_ok);
    print_result("out1_len", (long) out1_len);
    print_result("final2_ok", final2_ok);
    print_result("out2_len", (long) out2_len);
    print_result("update_after_final_ok", update_after_final_ok);
    print_result("projection_limitation", projection_limitation);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return 0;
}}
"""


def mbedtls_case(case: dict[str, Any]) -> str:
    dims = case["mutation_dimensions"]
    case_id = case["case_id"]
    sequence = dims["lifecycle_sequence"]
    input_len = int(dims["input_length"])
    key_len = key_len_value(str(dims["key_length"]))
    return f"""#include <stdio.h>
#include <string.h>
#include <psa/crypto.h>

{c_array("key_bytes", key_len, 0x41)}
{c_array("input_bytes", input_len, 0x71)}

static void print_result(const char *name, long value) {{
    printf("RESULT {case_id} mbedtls_psa %s=%ld\\n", name, value);
}}

int main(void) {{
    const char *sequence = "{sequence}";
    size_t key_len = {key_len};
    size_t input_len = {input_len};
    unsigned char out1[64];
    unsigned char out2[64];
    size_t out1_len = 0;
    size_t out2_len = 0;
    psa_status_t crypto_init_status = psa_crypto_init();
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);
    psa_status_t import_status = psa_import_key(&attributes, key_bytes, key_len, &key_id);
    psa_status_t setup_status = PSA_ERROR_BAD_STATE;
    psa_status_t update1_status = PSA_ERROR_BAD_STATE;
    psa_status_t final1_status = PSA_ERROR_BAD_STATE;
    psa_status_t final2_status = PSA_ERROR_BAD_STATE;
    psa_status_t update_after_final_status = PSA_ERROR_BAD_STATE;
    psa_status_t abort_status = PSA_ERROR_BAD_STATE;
    psa_status_t update_after_abort_status = PSA_ERROR_BAD_STATE;

    if (crypto_init_status == PSA_SUCCESS && import_status == PSA_SUCCESS) {{
        setup_status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_CMAC);
        if (setup_status == PSA_SUCCESS) {{
            update1_status = psa_mac_update(&operation, input_bytes, input_len);
            final1_status = psa_mac_sign_finish(&operation, out1, sizeof(out1), &out1_len);
            if (strcmp(sequence, "repeated_final") == 0) {{
                final2_status = psa_mac_sign_finish(&operation, out2, sizeof(out2), &out2_len);
            }} else if (strcmp(sequence, "update_after_final") == 0) {{
                update_after_final_status = psa_mac_update(&operation, input_bytes, input_len);
                final2_status = psa_mac_sign_finish(&operation, out2, sizeof(out2), &out2_len);
            }} else if (strcmp(sequence, "abort_then_update") == 0) {{
                psa_mac_operation_t operation2 = PSA_MAC_OPERATION_INIT;
                setup_status = psa_mac_sign_setup(&operation2, key_id, PSA_ALG_CMAC);
                if (setup_status == PSA_SUCCESS) {{
                    abort_status = psa_mac_abort(&operation2);
                    update_after_abort_status = psa_mac_update(&operation2, input_bytes, input_len);
                }}
            }}
        }}
    }}

    print_result("crypto_init_status", crypto_init_status);
    print_result("import_status", import_status);
    print_result("setup_status", setup_status);
    print_result("update1_status", update1_status);
    print_result("final1_status", final1_status);
    print_result("out1_len", (long) out1_len);
    print_result("final2_status", final2_status);
    print_result("out2_len", (long) out2_len);
    print_result("update_after_final_status", update_after_final_status);
    print_result("abort_status", abort_status);
    print_result("update_after_abort_status", update_after_abort_status);

    psa_mac_abort(&operation);
    if (key_id != 0) {{
        psa_destroy_key(key_id);
    }}
    return 0;
}}
"""


def render(root: Path) -> None:
    matrix_path = root / "render_matrix.yaml"
    if not matrix_path.exists():
        dump_yaml(matrix_path, build_matrix())
    matrix = load_yaml(matrix_path)
    adapter = load_yaml(root / "recipe" / "adapter.yaml")

    cross_root = root / "cross_templates_recipe"
    rendered_root = root / "rendered_cases"
    write_text(
        cross_root / "README.md",
        "# MAC Lifecycle Controlled Cross Templates\n\nGenerated from recipe-slot adapter and render_matrix.yaml. No LLM free-form C is used.\n",
    )
    dump_yaml(
        cross_root / "cross_mapping.yaml",
        {
            "schema_version": 1,
            "harness_family": "mac_lifecycle",
            "oracle_type": "lifecycle_state_transition_semantic_oracle",
            "source": {"library": "openssl", "api": "EVP_MAC_final"},
            "target": {"library": "mbedtls", "api": "psa_mac_sign_finish"},
            "adapter": str(root / "recipe" / "adapter.yaml"),
        },
    )

    for case in matrix.get("cases", []) or []:
        case_id = str(case["case_id"])
        case_dir = rendered_root / case_id
        manifest = {
            **case,
            "adapter": str(root / "recipe" / "adapter.yaml"),
            "slot_bindings": adapter.get("slot_bindings", {}),
            "sources": {
                "openssl": f"{case_id}_openssl.c",
                "mbedtls_psa": f"{case_id}_mbedtls.c",
            },
            "controlled_renderer": "mutation.apply_mac_lifecycle_matrix_to_template",
            "llm_freeform_c_used": False,
        }
        dump_yaml(case_dir / "case_manifest.yaml", manifest)
        dump_yaml(
            case_dir / "template_meta.yaml",
            {
                "template_id": "MAC_LIFECYCLE_V1_SOURCE_TEMPLATE",
                "harness_family": "mac_lifecycle",
                "oracle_type": "lifecycle_state_transition_semantic_oracle",
                "source_library": "openssl",
                "source_api": "EVP_MAC_final",
                "cross_library": {
                    "openssl": {"target_api": "EVP_MAC_final"},
                    "mbedtls": {"target_api": "psa_mac_sign_finish"},
                },
            },
        )
        dump_yaml(
            case_dir / "cross_mapping.yaml",
            {
                "harness_family": "mac_lifecycle",
                "oracle_type": "lifecycle_state_transition_semantic_oracle",
                "source": {"library": "openssl", "api": "EVP_MAC_final"},
                "target": {"library": "mbedtls", "api": "psa_mac_sign_finish"},
                "case_id": case_id,
            },
        )
        write_text(case_dir / f"{case_id}_openssl.c", openssl_case(case))
        write_text(case_dir / f"{case_id}_mbedtls.c", mbedtls_case(case))


def main() -> int:
    parser = argparse.ArgumentParser(description="Render controlled MAC lifecycle cases.")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    render(args.root)
    matrix = load_yaml(args.root / "render_matrix.yaml")
    print(f"Rendered {len(matrix.get('cases', []) or [])} MAC lifecycle cases under {args.root / 'rendered_cases'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

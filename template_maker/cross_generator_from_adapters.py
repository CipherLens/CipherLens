import argparse
import copy
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sanitize_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", str(s))


def strip_code_fence(s: Any) -> str:
    text = str(s or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def indent_block(block: str, spaces: int = 4) -> str:
    block = strip_code_fence(block)
    if not block:
        return " " * spaces + "/* empty */"
    pad = " " * spaces
    return "\n".join(pad + line if line.strip() else "" for line in block.splitlines())


def normalize_init_block(block: str) -> str:
    block = strip_code_fence(block)
    # We declare BIGNUM *X = NULL in the harness. Avoid redeclaration.
    block = block.replace("BIGNUM *X = BN_new();", "X = BN_new();")
    block = block.replace("BIGNUM* X = BN_new();", "X = BN_new();")
    return block


def normalize_include_header(header: Any) -> str:
    h = str(header or "").strip()
    h = h.strip("<>\"")
    if h.startswith("include/"):
        h = h[len("include/"):]
    return h


def render_include_lines(adapter: Dict[str, Any], default_headers: List[str]) -> str:
    headers = []
    seen = set()

    for h in default_headers + list(adapter.get("include_headers") or []):
        h = normalize_include_header(h)
        if h and h not in seen:
            seen.add(h)
            headers.append(h)

    return "\n".join(f"#include <{h}>" for h in headers)


def copy_if_exists(src_dir: Path, out_dir: Path, names: List[str]) -> None:
    for name in names:
        src = src_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)


def infer_source_template_id(adapter: Dict[str, Any], adapter_file: Path, adapter_root: Path) -> Optional[str]:
    for key in ["source_template_id", "template_id"]:
        value = adapter.get(key)
        if value:
            return str(value)

    try:
        rel = adapter_file.parent.relative_to(adapter_root)
        if len(rel.parts) >= 2:
            return rel.parts[0]
    except ValueError:
        pass

    parent = adapter_file.parent.parent.name
    return parent or None


def find_normalized_template_dir(template_id: str, root: Path = Path("normalized_templates")) -> Optional[Path]:
    if not template_id or not root.exists():
        return None

    for meta_path in sorted(root.rglob("template_meta.yaml")):
        meta = load_yaml(meta_path)
        if meta.get("template_id") == template_id or meta.get("source_template_id") == template_id:
            return meta_path.parent

    return None


def load_or_infer_adapter_meta(
    adapter: Dict[str, Any],
    adapter_file: Path,
    adapter_root: Path,
) -> Dict[str, Any]:
    meta_path = adapter_file.parent / "adapter_meta.yaml"
    if meta_path.exists():
        return load_yaml(meta_path)

    template_id = infer_source_template_id(adapter, adapter_file, adapter_root)
    source_template_dir = find_normalized_template_dir(str(template_id or ""))
    if source_template_dir is None:
        raise FileNotFoundError(
            f"adapter_meta.yaml missing and no normalized template found for template_id={template_id!r}"
        )

    target_library = adapter.get("target_library")
    target_api = adapter.get("target_api")

    return {
        "candidate": {
            "target_api": target_api,
            "target_library": target_library,
        },
        "source_files": {
            "template_meta": str(source_template_dir / "template_meta.yaml"),
            "mask_report": str(source_template_dir / "mask_report.yaml"),
            "source_template": str(source_template_dir / "tmpl_mbedtls.c"),
        },
        "inferred_adapter_meta": True,
    }


def optional_path(value: Any) -> Optional[Path]:
    text = str(value or "").strip()
    if not text:
        return None
    return Path(text)


def is_recipe_adapter(adapter: Dict[str, Any]) -> bool:
    return bool(adapter.get("adapter_recipe") and adapter.get("slot_bindings"))


def load_adapter_recipe(adapter: Dict[str, Any]) -> Dict[str, Any]:
    recipe_path = optional_path(adapter.get("adapter_recipe"))
    if recipe_path is None:
        raise ValueError("recipe adapter is missing adapter_recipe")
    if not recipe_path.exists():
        raise FileNotFoundError(f"adapter_recipe not found: {recipe_path}")
    recipe = load_yaml(recipe_path)
    if not recipe:
        raise ValueError(f"adapter_recipe is empty or invalid: {recipe_path}")
    return recipe


def slot(adapter: Dict[str, Any], recipe: Dict[str, Any], name: str) -> str:
    bindings = adapter.get("slot_bindings") or {}
    if name in bindings and str(bindings[name]).strip():
        return str(bindings[name]).strip()

    spec = (recipe.get("allowed_slots") or {}).get(name, {})
    if isinstance(spec, dict) and "default" in spec:
        return str(spec["default"]).strip()

    raise ValueError(f"missing recipe slot binding: {name}")


def c_identifier(name: str, fallback: str) -> str:
    text = str(name or "").strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", text):
        return fallback
    return text


def is_bignum_arithmetic_semantic_recipe(adapter: Dict[str, Any], recipe: Optional[Dict[str, Any]] = None) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("target_api") == "BN_usub"
        and recipe.get("harness_family") == "bignum_arithmetic_semantic"
        and recipe.get("oracle_type") == "bignum_negative_result_rejection_oracle"
    )


SEMANTIC_PROJECTION_FORBIDDEN_TOKENS = [
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

BUFFER_CANARY_RECIPE_FORBIDDEN_TOKENS = [
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
]

OBJECT_STATE_LIFECYCLE_FORBIDDEN_TOKENS = [
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

INVALID_PARAMETER_SETUP_ORACLE_FORBIDDEN_TOKENS = [
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

CRASH_SANITIZER_ORACLE_FORBIDDEN_TOKENS = [
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

NULL_DEREF_DISPATCH_FORBIDDEN_TOKENS = [
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
    "CANARY_SIZE",
    "BUFLEN",
    "consumed_len",
    "openssl/bn.h",
    "openssl/x509.h",
]


def scrub_forbidden_tokens(value: Any, replacement: str = "omitted_from_semantic_projection") -> Any:
    if isinstance(value, str):
        out = value
        for token in SEMANTIC_PROJECTION_FORBIDDEN_TOKENS:
            out = out.replace(token, replacement)
        return out
    if isinstance(value, list):
        return [scrub_forbidden_tokens(item, replacement) for item in value]
    if isinstance(value, dict):
        return {
            scrub_forbidden_tokens(k, replacement): scrub_forbidden_tokens(v, replacement)
            for k, v in value.items()
        }
    return value


def scrub_cross_family_tokens(
    value: Any,
    forbidden_tokens: List[str],
    replacement: str = "omitted_cross_family_residue",
) -> Any:
    if isinstance(value, str):
        out = value
        for token in forbidden_tokens:
            out = out.replace(token, replacement)
        return out
    if isinstance(value, list):
        return [scrub_cross_family_tokens(item, forbidden_tokens, replacement) for item in value]
    if isinstance(value, dict):
        return {
            scrub_cross_family_tokens(k, forbidden_tokens, replacement):
            scrub_cross_family_tokens(v, forbidden_tokens, replacement)
            for k, v in value.items()
        }
    return value


def is_bignum_serialization_buffer_boundary_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("target_api") == "BN_signed_bn2bin"
        and recipe.get("harness_family") == "buffer_canary_boundary"
        and recipe.get("oracle_type") == "bignum_serialization_buffer_boundary_oracle"
    )



def is_der_pointer_consumption_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("target_api") in {"d2i_PrivateKey", "d2i_RSAPrivateKey", "d2i_RSA_PUBKEY"}
        and recipe.get("harness_family") == "der_pointer_consumption"
        and recipe.get("oracle_type") == "pointer_consumption_semantic_oracle"
    )



def is_x509_asn1_inner_boundary_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("target_api") == "d2i_X509"
        and recipe.get("harness_family") in {"x509_asn1_inner_boundary", "asn1_inner_boundary"}
        and recipe.get("oracle_type") == "inner_asn1_boundary_semantic_oracle"
    )


def is_object_state_lifecycle_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("harness_family") == "object_state_lifecycle"
        and recipe.get("oracle_type") in {
            "stale_pointer_length_state_oracle",
            "object_lifecycle_state_oracle",
        }
    )


def render_object_state_lifecycle_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)
    target_api = recipe.get("target_api", "")

    if target_api != "ASN1_STRING_set":
        raise ValueError(
            f"object_state_lifecycle recipe renderer currently supports only ASN1_STRING_set, got {target_api!r}"
        )
    if recipe.get("harness_family") != "object_state_lifecycle":
        raise ValueError("recipe harness_family must be object_state_lifecycle")

    s_var = c_identifier(slot(adapter, recipe, "asn1_string_variable"), "s")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")
    first_data_var = c_identifier(slot(adapter, recipe, "first_data_variable"), "first_data")
    reuse_data_var = c_identifier(slot(adapter, recipe, "reuse_data_variable"), "reuse_data")

    include_lines = render_include_lines(
        {"include_headers": recipe.get("include_headers", [])},
        ["stdio.h", "stdlib.h", "string.h", "openssl/asn1.h", "openssl/err.h"],
    )

    return f'''{include_lines}

#define FIRST_VALUE_LEN [FIRST_VALUE_LEN]

int main(void)
{{
    ASN1_STRING *{s_var} = NULL;
    int {ret_var} = 0;
    unsigned char {first_data_var}[FIRST_VALUE_LEN];
    unsigned char {reuse_data_var}[FIRST_VALUE_LEN];

    setbuf(stdout, NULL);

    memset({first_data_var}, 0x11, FIRST_VALUE_LEN);
    memset({reuse_data_var}, 0xaa, FIRST_VALUE_LEN);

    printf("template_mutation FIRST_VALUE_LEN=%d\\n", FIRST_VALUE_LEN);

    /*
     * Semantic projection from mbedtls_asn1_store_named_data lifecycle:
     *   step1: nonzero value → internal buffer allocated
     *   step2: zero-length update → internal state modified
     *   step3: same-length reuse → safe reallocation or potential crash
     *
     * OpenSSL ASN1_STRING_set keeps the buffer allocated on zero-length update.
     * Expected result: migrated_safe (no crash; OpenSSL handles lifecycle safely).
     */
    {s_var} = ASN1_STRING_new();
    if ({s_var} == NULL) {{
        printf("[ERROR] ASN1_STRING_new failed.\\n");
        return 2;
    }}

    /* Step 1: set nonzero value (FIRST_VALUE_LEN bytes). */
    {ret_var} = ASN1_STRING_set({s_var}, {first_data_var}, FIRST_VALUE_LEN);
    printf("step1 ASN1_STRING_set(len=%d) ret=%d data=%p len=%d\\n",
           FIRST_VALUE_LEN, {ret_var},
           (void *) ASN1_STRING_get0_data({s_var}),
           ASN1_STRING_length({s_var}));
    if ({ret_var} != 1) {{
        printf("[INFO] object_state_lifecycle: step1 failed. ret=%d\\n", {ret_var});
        ASN1_STRING_free({s_var});
        return 2;
    }}

    /* Step 2: zero-length update (the stale-state trigger in vulnerable systems). */
    {ret_var} = ASN1_STRING_set({s_var}, NULL, 0);
    printf("step2 ASN1_STRING_set(len=0) ret=%d data=%p len=%d\\n",
           {ret_var},
           (void *) ASN1_STRING_get0_data({s_var}),
           ASN1_STRING_length({s_var}));
    if ({ret_var} != 1) {{
        printf("[INFO] object_state_lifecycle: step2 failed. ret=%d\\n", {ret_var});
        ASN1_STRING_free({s_var});
        return 2;
    }}

    /* Step 3: reuse with same length as step1.
     * Buggy systems: skip reallocation, memcpy to NULL → crash.
     * OpenSSL: safe reallocation or in-place write. */
    {ret_var} = ASN1_STRING_set({s_var}, {reuse_data_var}, FIRST_VALUE_LEN);
    printf("step3 ASN1_STRING_set(len=%d) ret=%d data=%p len=%d\\n",
           FIRST_VALUE_LEN, {ret_var},
           (void *) ASN1_STRING_get0_data({s_var}),
           ASN1_STRING_length({s_var}));

    if ({ret_var} == 1 &&
        ASN1_STRING_length({s_var}) == FIRST_VALUE_LEN &&
        ASN1_STRING_get0_data({s_var}) != NULL) {{
        printf("[OK] object_state_lifecycle: safe update after zero-length reset. ret=%d\\n", {ret_var});
    }} else if ({ret_var} != 1) {{
        printf("[INFO] object_state_lifecycle: step3 failed. ret=%d\\n", {ret_var});
    }} else {{
        printf("[TRIAGE] object_state_lifecycle: unexpected state. ret=%d len=%d\\n",
               {ret_var}, ASN1_STRING_length({s_var}));
    }}

    ASN1_STRING_free({s_var});
    return 0;
}}
'''


def is_invalid_parameter_setup_oracle_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("harness_family") == "invalid_parameter_setup_oracle"
        and recipe.get("oracle_type") in {
            "invalid_aead_tag_length_oracle",
            "invalid_parameter_return_code_oracle",
        }
    )


def render_invalid_parameter_setup_oracle_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)
    target_api = recipe.get("target_api", "")

    if target_api != "EVP_CIPHER_CTX_ctrl":
        raise ValueError(
            f"invalid_parameter_setup_oracle recipe renderer currently supports only EVP_CIPHER_CTX_ctrl, got {target_api!r}"
        )
    if recipe.get("harness_family") != "invalid_parameter_setup_oracle":
        raise ValueError("recipe harness_family must be invalid_parameter_setup_oracle")

    cipher = slot(adapter, recipe, "aead_cipher")
    ctx_var = c_identifier(slot(adapter, recipe, "ctx_variable"), "ctx")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")
    init_ret_var = c_identifier(slot(adapter, recipe, "init_ret_variable"), "init_ret")

    include_lines = render_include_lines(
        {"include_headers": recipe.get("include_headers", [])},
        ["stdio.h", "stdlib.h", "string.h", "openssl/evp.h", "openssl/err.h"],
    )

    return f'''{include_lines}

#define TAG_LENGTH [TAG_LENGTH]

/*
 * CCM allows only even tag lengths from 4 to 16.
 * Returns 1 if valid, 0 if invalid.
 */
static int is_valid_ccm_tag_length(int tlen)
{{
    return (tlen >= 4 && tlen <= 16 && (tlen % 2 == 0));
}}

int main(void)
{{
    EVP_CIPHER_CTX *{ctx_var} = NULL;
    int {ret_var} = 0;
    int {init_ret_var} = 0;

    setbuf(stdout, NULL);

    printf("template_mutation TAG_LENGTH=%d\\n", TAG_LENGTH);

    /*
     * Source vulnerability: PSA psa_aead_setup() accepted invalid CCM tag
     * length 3 without validation. Fixed by psa_validate_tag_length().
     * Target probe: EVP_CIPHER_CTX_ctrl with EVP_CTRL_CCM_SET_TAG and
     * invalid tag length. Oracle: ctrl return code (0=rejected, 1=accepted).
     */
    {ctx_var} = EVP_CIPHER_CTX_new();
    if ({ctx_var} == NULL) {{
        printf("[ERROR] EVP_CIPHER_CTX_new failed.\\n");
        return 2;
    }}

    {init_ret_var} = EVP_DecryptInit_ex({ctx_var}, {cipher}, NULL, NULL, NULL);
    printf("EVP_DecryptInit_ex ret=%d\\n", {init_ret_var});
    if ({init_ret_var} <= 0) {{
        printf("[INFO] invalid_parameter_setup_oracle: EVP_DecryptInit_ex failed (init_ret=%d).\\n",
               {init_ret_var});
        EVP_CIPHER_CTX_free({ctx_var});
        return 2;
    }}

    printf("calling EVP_CIPHER_CTX_ctrl(EVP_CTRL_CCM_SET_TAG, %d)...\\n", TAG_LENGTH);
    {ret_var} = EVP_CIPHER_CTX_ctrl({ctx_var}, EVP_CTRL_CCM_SET_TAG, TAG_LENGTH, NULL);
    printf("EVP_CIPHER_CTX_ctrl ret=%d\\n", {ret_var});

    if (!is_valid_ccm_tag_length(TAG_LENGTH)) {{
        if ({ret_var} > 0) {{
            printf("[BUG] target accepted invalid CCM tag length=%d at ctrl.\\n", TAG_LENGTH);
        }} else {{
            printf("[OK] target rejected invalid CCM tag length=%d.\\n", TAG_LENGTH);
        }}
    }} else {{
        if ({ret_var} > 0) {{
            printf("[OK] target accepted valid CCM tag length=%d.\\n", TAG_LENGTH);
        }} else {{
            printf("[INFO] target rejected valid CCM tag length=%d (needs triage).\\n", TAG_LENGTH);
        }}
    }}

    EVP_CIPHER_CTX_free({ctx_var});
    return 0;
}}
'''


def is_crash_sanitizer_oracle_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("harness_family") == "crash_sanitizer_oracle"
        and recipe.get("oracle_type") in {
            "heap_underflow_sanitizer_oracle",
            "heap_overflow_sanitizer_oracle",
            "generic_sanitizer_crash_oracle",
        }
    )


def render_crash_sanitizer_oracle_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)
    target_api = recipe.get("target_api", "")

    if target_api != "PEM_read_bio_PrivateKey":
        raise ValueError(
            f"crash_sanitizer_oracle recipe renderer currently supports only PEM_read_bio_PrivateKey, got {target_api!r}"
        )
    if recipe.get("harness_family") != "crash_sanitizer_oracle":
        raise ValueError("recipe harness_family must be crash_sanitizer_oracle")

    pem_label = slot(adapter, recipe, "pem_header_label")
    password = slot(adapter, recipe, "password_string")
    bio_var = c_identifier(slot(adapter, recipe, "bio_variable"), "bio")
    pkey_var = c_identifier(slot(adapter, recipe, "pkey_variable"), "pkey")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")

    include_lines = render_include_lines(
        {"include_headers": recipe.get("include_headers", [])},
        ["stdio.h", "stdlib.h", "string.h", "openssl/pem.h", "openssl/evp.h",
         "openssl/bio.h", "openssl/err.h"],
    )

    pem_header = f"-----BEGIN {pem_label}-----"
    pem_footer = f"-----END {pem_label}-----"

    return f'''{include_lines}

#define PEM_BODY_CONTENT "[PEM_BODY]"

static const char malformed_pem[] =
    "{pem_header}\\r\\n"
    "Proc-Type: 4,ENCRYPTED\\r\\n"
    "DEK-Info: AES-128-CBC,AAAABBBBCCCCDDDDEEEEFFFFAAAABBBB\\r\\n"
    "\\r\\n"
    PEM_BODY_CONTENT "\\r\\n"
    "{pem_footer}\\r\\n";

static int poc_pem_pwd_cb(char *buf, int size, int rwflag, void *userdata)
{{
    const char *pwd = "{password}";
    int len = (int) strlen(pwd);
    (void) rwflag;
    (void) userdata;
    if (len > size) {{
        len = size;
    }}
    memcpy(buf, pwd, (size_t) len);
    return len;
}}

int main(void)
{{
    BIO *{bio_var} = NULL;
    EVP_PKEY *{pkey_var} = NULL;
    int {ret_var} = 0;

    setbuf(stdout, NULL);

    printf("template_mutation PEM_BODY=%s\\n", PEM_BODY_CONTENT);

    /*
     * Construct malformed encrypted PEM with short base64 body.
     * Source vulnerability: mbedTLS pem_check_pkcs_padding reads
     * input[input_len - 1] without checking input_len >= 1 when the
     * decoded buffer is empty. Oracle: ASAN heap-buffer-underflow or safe rejection.
     */
    {bio_var} = BIO_new_mem_buf(malformed_pem, -1);
    if ({bio_var} == NULL) {{
        printf("[ERROR] BIO_new_mem_buf failed.\\n");
        return 2;
    }}

    printf("calling PEM_read_bio_PrivateKey with malformed encrypted PEM...\\n");

    {pkey_var} = PEM_read_bio_PrivateKey({bio_var}, NULL, poc_pem_pwd_cb, NULL);

    if ({pkey_var} == NULL) {{
        printf("[OK] null_deref_dispatch: malformed encrypted PEM rejected safely by PEM_read_bio_PrivateKey.\\n");
        {ret_var} = 0;
    }} else {{
        printf("[TRIAGE] crash_sanitizer_oracle: malformed encrypted PEM accepted unexpectedly.\\n");
        EVP_PKEY_free({pkey_var});
        {ret_var} = 2;
    }}

    BIO_free({bio_var});
    return {ret_var};
}}
'''


def is_pkey_capability_mismatch_oracle_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if recipe is None:
        recipe = load_adapter_recipe(adapter)
    return (
        adapter.get("target_api") in {"psa_sign_message", "psa_sign_hash"}
        and recipe.get("harness_family") == "pkey_capability_mismatch_oracle"
    )


def render_pkey_capability_mismatch_oracle_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)
    target_api = adapter.get("target_api", "psa_sign_message")

    if recipe.get("harness_family") != "pkey_capability_mismatch_oracle":
        raise ValueError("recipe harness_family must be pkey_capability_mismatch_oracle")

    key_type = slot(adapter, recipe, "key_type")
    key_bits = slot(adapter, recipe, "key_bits")
    key_algorithm = slot(adapter, recipe, "key_algorithm")
    key_usage_flags = slot(adapter, recipe, "key_usage_flags")
    message_bytes = slot(adapter, recipe, "message_bytes")
    message_len = slot(adapter, recipe, "message_len")

    # Standard Ed25519 public key (32 bytes) for default case
    ed25519_pub_key_hex = (
        "0x7d,0x4d,0x0e,0x7f,0x61,0x53,0xa6,0x9b,"
        "0x62,0x42,0xb5,0x22,0xab,0xbe,0xe6,0x85,"
        "0xfd,0xa4,0x42,0x0f,0x88,0x34,0xb1,0x08,"
        "0xc3,0xbd,0xae,0x36,0x9e,0xf5,0x49,0xfa"
    )

    return f"""\
#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * Harness: pkey_capability_mismatch_oracle
 * Pattern: OPENSSL-ISSUE-19524 (public-only key signing capability mismatch)
 * Target API: {target_api}
 * Oracle: PSA must reject signing with public-only key (no SIGN_MESSAGE usage)
 */

int main(void)
{{
    static const unsigned char pub_key_bytes[] = {{
        {ed25519_pub_key_hex}
    }};
    static const unsigned char message[] = {message_bytes};
    unsigned char sig[128];
    size_t sig_len = 0;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    int ret = 1;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {{
        fprintf(stderr, "[ERROR] psa_crypto_init failed: %d\\n", (int)status);
        goto end;
    }}

    /* Set key attributes: public-only key without PSA_KEY_USAGE_SIGN_MESSAGE */
    psa_set_key_type(&attributes, {key_type});
    psa_set_key_bits(&attributes, {key_bits});
    psa_set_key_usage_flags(&attributes, {key_usage_flags});
    psa_set_key_algorithm(&attributes, {key_algorithm});

    status = psa_import_key(&attributes, pub_key_bytes, sizeof(pub_key_bytes), &key_id);
    printf("psa_import_key returned %d\\n", (int)status);
    if (status != PSA_SUCCESS) {{
        fprintf(stderr, "[INFO] psa_import_key failed: %d\\n", (int)status);
        ret = 0;
        goto end;
    }}

    /* Core trigger: attempt to sign with public-only key */
    status = {target_api}(key_id, {key_algorithm},
                          message, {message_len},
                          sig, sizeof(sig), &sig_len);
    printf("{target_api} returned %d sig_len=%zu\\n", (int)status, sig_len);

    if (status == PSA_SUCCESS) {{
        /* Signing succeeded with public-only key = semantic violation */
        fprintf(stderr, "[WARNING] public-only key signing succeeded! capability mismatch!\\n");
        printf("[TRIAGE] signing with public-only key succeeded — capability mismatch\\n");
    }} else {{
        printf("[SAFE] public-only key signing rejected safely: %d\\n", (int)status);
        printf("[VERDICT] safe_fixed_behavior\\n");
    }}
    ret = 0;

end:
    if (key_id != 0)
        psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
    return ret;
}}
"""


def is_null_deref_dispatch_recipe(
    adapter: Dict[str, Any],
    recipe: Optional[Dict[str, Any]] = None,
) -> bool:
    if not is_recipe_adapter(adapter):
        return False
    recipe = recipe or load_adapter_recipe(adapter)
    return (
        recipe.get("target_api") == "EVP_DigestVerify"
        and recipe.get("harness_family") == "null_deref_dispatch"
        and recipe.get("oracle_type") == "crash_sanitizer_or_safe_error_oracle"
    )


def render_null_deref_dispatch_mbedtls_harness(source_meta: Dict[str, Any]) -> str:
    return r'''#include <stdio.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "psa/crypto.h"

#define KEY_BITS [KEY_BITS]

int main(void)
{
    mbedtls_pk_context pk;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t psa_status;
    int key_generated = 0;
    int ret = 0;

    unsigned char hash[32];
    unsigned char sig[512];

    setbuf(stdout, NULL);

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0x5a, sizeof(sig));

    mbedtls_pk_init(&pk);

    printf("template_mutation KEY_BITS=%d\n", KEY_BITS);

    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        printf("[ERROR] psa_crypto_init failed: %d\n", (int) psa_status);
        ret = 2;
        goto cleanup;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, KEY_BITS);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));

    psa_status = psa_generate_key(&key_attr, &key_id);
    if (psa_status != PSA_SUCCESS) {
        printf("[ERROR] psa_generate_key failed: %d\n", (int) psa_status);
        ret = 2;
        goto cleanup;
    }
    key_generated = 1;

    /*
     * mbedtls_pk_wrap_psa replaces the historical mbedtls_pk_setup_opaque
     * (removed in 4.x). Wraps a PSA key into a PK context.
     */
    ret = mbedtls_pk_wrap_psa(&pk, key_id);
    if (ret != 0) {
        printf("[ERROR] mbedtls_pk_wrap_psa failed: %d\n", ret);
        goto cleanup;
    }

    printf("psa_key_type=%u\n", (unsigned) mbedtls_pk_get_key_type(&pk));
    printf("calling mbedtls_pk_verify_ext with MBEDTLS_PK_SIGALG_RSA_PSS...\n");

    /*
     * In mbedTLS 3.x buggy: the opaque key path crashed via NULL deref on
     * mbedtls_pk_rsa(). In 4.x this path is gone; the API dispatches
     * through PSA for wrapped keys and returns an error for sign-only keys.
     */
    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_RSA_PSS, &pk,
                                MBEDTLS_MD_SHA256,
                                hash, sizeof(hash),
                                sig, sizeof(sig));

    printf("verify_ext ret=%d\n", ret);
    printf("expected=%d\n", MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);

    if (ret == MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE) {
        printf("[OK] fixed behavior: unsupported opaque verify_ext rejected safely.\n");
    } else if (ret != 0) {
        printf("[OK] fixed behavior: opaque RSA-PSS verify_ext rejected safely. ret=%d\n", ret);
    } else {
        printf("[INFO] opaque key verify returned success for dummy sig.\n");
    }

cleanup:
    mbedtls_pk_free(&pk);
    if (key_generated) {
        psa_destroy_key(key_id);
    }
    return 0;
}
'''


def render_null_deref_dispatch_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)

    if recipe.get("target_api") != "EVP_DigestVerify":
        raise ValueError("null_deref_dispatch recipe renderer currently supports only EVP_DigestVerify")
    if recipe.get("harness_family") != "null_deref_dispatch":
        raise ValueError("recipe harness_family must be null_deref_dispatch")
    if recipe.get("oracle_type") != "crash_sanitizer_or_safe_error_oracle":
        raise ValueError("recipe oracle_type must be crash_sanitizer_or_safe_error_oracle")

    md_alg = slot(adapter, recipe, "md_algorithm")
    ec_curve = slot(adapter, recipe, "ec_curve_nid")
    sign_key_var = c_identifier(slot(adapter, recipe, "signing_key_variable"), "sign_key")
    target_key_var = c_identifier(slot(adapter, recipe, "incompatible_key_variable"), "target_key")
    verify_ctx_var = c_identifier(slot(adapter, recipe, "verify_ctx_variable"), "verify_ctx")
    sign_ctx_var = c_identifier(slot(adapter, recipe, "sign_ctx_variable"), "sign_ctx")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")

    include_lines = render_include_lines(
        {"include_headers": recipe.get("include_headers", [])},
        ["stdio.h", "stdlib.h", "string.h", "openssl/evp.h", "openssl/rsa.h", "openssl/ec.h", "openssl/err.h"],
    )

    return f'''{include_lines}

#define RSA_KEY_BITS [KEY_BITS]

int main(void)
{{
    EVP_PKEY_CTX *kgen_ctx = NULL;
    EVP_PKEY *{sign_key_var} = NULL;
    EVP_PKEY *{target_key_var} = NULL;
    EVP_MD_CTX *{sign_ctx_var} = NULL;
    EVP_MD_CTX *{verify_ctx_var} = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char sig[512];
    size_t sig_len = sizeof(sig);
    const unsigned char test_data[] = "null_deref_dispatch_probe";
    size_t test_data_len = sizeof(test_data) - 1;
    int {ret_var} = 0;
    int exit_code = 0;

    setbuf(stdout, NULL);

    printf("template_mutation KEY_BITS=%d\\n", RSA_KEY_BITS);

    /* Step 1: Generate RSA signing key */
    kgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kgen_ctx == NULL) {{
        printf("[ERROR] RSA keygen ctx new failed.\\n");
        return 2;
    }}
    if (EVP_PKEY_keygen_init(kgen_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kgen_ctx, RSA_KEY_BITS) <= 0 ||
        EVP_PKEY_keygen(kgen_ctx, &{sign_key_var}) <= 0) {{
        printf("[ERROR] RSA keygen failed.\\n");
        EVP_PKEY_CTX_free(kgen_ctx);
        return 2;
    }}
    EVP_PKEY_CTX_free(kgen_ctx);
    kgen_ctx = NULL;

    /* Step 2: Sign test data with RSA-PSS to produce a real signature */
    {sign_ctx_var} = EVP_MD_CTX_new();
    if ({sign_ctx_var} == NULL) {{
        printf("[ERROR] sign ctx new failed.\\n");
        goto cleanup;
    }}
    if (EVP_DigestSignInit({sign_ctx_var}, &pctx, {md_alg}, NULL, {sign_key_var}) <= 0) {{
        printf("[ERROR] DigestSignInit failed.\\n");
        goto cleanup;
    }}
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {{
        printf("[ERROR] set RSA-PSS padding on sign ctx failed.\\n");
        goto cleanup;
    }}
    pctx = NULL;
    if (EVP_DigestSignUpdate({sign_ctx_var}, test_data, test_data_len) <= 0 ||
        EVP_DigestSignFinal({sign_ctx_var}, sig, &sig_len) <= 0) {{
        printf("[ERROR] DigestSign failed.\\n");
        goto cleanup;
    }}
    EVP_MD_CTX_free({sign_ctx_var});
    {sign_ctx_var} = NULL;

    printf("rsa_sign_ok=yes sig_len=%zu\\n", sig_len);

    /* Step 3: Generate incompatible EC key ({ec_curve}) */
    kgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (kgen_ctx == NULL ||
        EVP_PKEY_keygen_init(kgen_ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kgen_ctx, {ec_curve}) <= 0 ||
        EVP_PKEY_keygen(kgen_ctx, &{target_key_var}) <= 0) {{
        printf("[ERROR] EC keygen failed.\\n");
        goto cleanup;
    }}
    EVP_PKEY_CTX_free(kgen_ctx);
    kgen_ctx = NULL;

    printf("ec_key_type=%d\\n", EVP_PKEY_id({target_key_var}));
    printf("calling EVP_DigestVerifyInit with incompatible EC key...\\n");

    /* Step 4: Trigger - EVP_DigestVerifyInit with incompatible EC key */
    {verify_ctx_var} = EVP_MD_CTX_new();
    if ({verify_ctx_var} == NULL) {{
        printf("[ERROR] verify ctx new failed.\\n");
        goto cleanup;
    }}

    {ret_var} = EVP_DigestVerifyInit({verify_ctx_var}, &pctx, {md_alg}, NULL, {target_key_var});
    printf("EVP_DigestVerifyInit ret=%d\\n", {ret_var});
    if ({ret_var} <= 0) {{
        printf("[OK] null_deref_dispatch: incompatible EC key rejected safely at EVP_DigestVerifyInit.\\n");
        exit_code = 0;
        goto cleanup;
    }}

    /* Step 5: Probe RSA-PSS padding dispatch path */
    {ret_var} = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    printf("EVP_PKEY_CTX_set_rsa_padding ret=%d\\n", {ret_var});
    if ({ret_var} <= 0) {{
        printf("[OK] null_deref_dispatch: RSA-PSS padding rejected safely for incompatible EC key.\\n");
        exit_code = 0;
        goto cleanup;
    }}
    pctx = NULL;

    /* Step 6: Attempt verify update and final with incompatible key */
    {ret_var} = EVP_DigestVerifyUpdate({verify_ctx_var}, test_data, test_data_len);
    printf("EVP_DigestVerifyUpdate ret=%d\\n", {ret_var});
    if ({ret_var} <= 0) {{
        printf("[OK] null_deref_dispatch: incompatible EC key rejected safely at EVP_DigestVerifyUpdate.\\n");
        exit_code = 0;
        goto cleanup;
    }}

    {ret_var} = EVP_DigestVerifyFinal({verify_ctx_var}, sig, sig_len);
    printf("EVP_DigestVerifyFinal ret=%d\\n", {ret_var});
    if ({ret_var} <= 0) {{
        printf("[OK] null_deref_dispatch: incompatible EC key rejected safely at EVP_DigestVerifyFinal.\\n");
        exit_code = 0;
    }} else {{
        printf("[TRIAGE] null_deref_dispatch: incompatible EC key verify unexpectedly succeeded. ret=%d\\n", {ret_var});
        exit_code = 2;
    }}

cleanup:
    EVP_MD_CTX_free({sign_ctx_var});
    EVP_MD_CTX_free({verify_ctx_var});
    EVP_PKEY_free({sign_key_var});
    EVP_PKEY_free({target_key_var});
    EVP_PKEY_CTX_free(kgen_ctx);
    return exit_code;
}}
'''


def bignum_semantic_projection_meta(source_meta: Dict[str, Any], adapter: Dict[str, Any]) -> Dict[str, Any]:
    meta = copy.deepcopy(source_meta)
    meta["harness_family"] = "bignum_arithmetic_semantic"
    meta["oracle_type"] = "bignum_negative_result_rejection_oracle"
    meta["semantic_projection"] = {
        "enabled": True,
        "reason": (
            "OpenSSL public BIGNUM storage is opaque, so this recipe template "
            "models the negative-result arithmetic relation rather than the "
            "original mbedTLS output-limb memory boundary."
        ),
        "adapter_recipe": adapter.get("adapter_recipe", ""),
    }

    meta["mutation_points"] = [
        mp for mp in meta.get("mutation_points", [])
        if mp.get("name") in {"A_VALUE", "B_VALUE", "A_BASE", "B_BASE"}
    ]
    meta["generation_policy"] = {
        "max_cases": source_meta.get("generation_policy", {}).get("max_cases", 128),
        "priority": ["A_VALUE", "B_VALUE", "A_BASE", "B_BASE"],
    }
    meta["oracle"] = {
        "semantic": [
            "negative_result_rejection_or_triage",
            "lhs_rhs_unsigned_relation",
        ],
        "behavior": [
            "lhs_lt_rhs_safe_reject",
            "lhs_lt_rhs_semantic_projection_triage",
            "lhs_gte_rhs_normal_arithmetic_path",
        ],
    }
    return scrub_forbidden_tokens(meta)


def bignum_semantic_projection_mask_report(source_meta: Dict[str, Any], adapter: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "template_id": source_meta.get("template_id", ""),
        "source_pattern_id": adapter.get("source_pattern_id", ""),
        "harness_family": "bignum_arithmetic_semantic",
        "oracle_type": "bignum_negative_result_rejection_oracle",
        "semantic_projection": {
            "enabled": True,
            "description": (
                "This generated recipe template intentionally omits the original "
                "source memory-boundary oracle from the cross-template directory. "
                "It preserves only the public arithmetic relation needed by the "
                "OpenSSL BN_usub semantic projection."
            ),
        },
        "mutation_points": [
            {
                "name": mp.get("name"),
                "placeholder": mp.get("placeholder"),
                "type": mp.get("type"),
                "default": mp.get("default"),
                "values": mp.get("values"),
            }
            for mp in source_meta.get("mutation_points", [])
            if mp.get("name") in {"A_VALUE", "B_VALUE", "A_BASE", "B_BASE"}
        ],
    }


def render_buffer_canary_harness(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    include_lines = render_include_lines(adapter, ["openssl/bn.h"])

    init_block = normalize_init_block(adapter.get("init_block", "X = BN_new();"))
    input_block = strip_code_fence(adapter.get("input_construction_block", ""))
    trigger_block = strip_code_fence(adapter.get("trigger_block", ""))
    cleanup_block = strip_code_fence(adapter.get("cleanup_block", "BN_free(X);"))

    target_api = adapter.get("target_api", "unknown_target_api")

    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{include_lines}

#define BUFLEN [BUFLEN]
#define CANARY_SIZE [CANARY_SIZE]
#define CANARY_BYTE 0xA5

static int canary_corrupted(unsigned char *buf)
{{
    for (size_t i = 0; i < CANARY_SIZE; i++) {{
        if (buf[BUFLEN + i] != CANARY_BYTE) {{
            return 1;
        }}
    }}
    return 0;
}}

int main(void)
{{
    BIGNUM *X = NULL;
    unsigned char buf[BUFLEN + CANARY_SIZE];
    int ret = 0;
    long signed_value = [VALUE];
    unsigned long magnitude = 0;

    memset(buf, 0x42, sizeof(buf));
    memset(buf + BUFLEN, CANARY_BYTE, CANARY_SIZE);

    if (signed_value < 0) {{
        magnitude = (unsigned long)(-signed_value);
    }} else {{
        magnitude = (unsigned long)signed_value;
    }}

    /*
     * Adapter-generated initialization.
     */
{indent_block(init_block, 4)}

    if (X == NULL) {{
        printf("target init failed\\n");
        return 2;
    }}

    /*
     * Adapter-generated input construction.
     */
{indent_block(input_block, 4)}

    /*
     * Adapter-generated trigger call.
     * target_api: {target_api}
     */
{indent_block(trigger_block, 4)}

    printf("ret=%d\\n", ret);
    printf("buf/canary prefix=");

    for (size_t i = 0; i < BUFLEN + 8 && i < sizeof(buf); i++) {{
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {{
            printf("%c", c);
        }} else {{
            printf("\\\\x%02x", c);
        }}
    }}
    printf("\\n");

    if (canary_corrupted(buf)) {{
        printf("[BUG] Canary corrupted: target API wrote beyond caller buffer.\\n");
{indent_block(cleanup_block, 8)}
        return 1;
    }}

    printf("[OK] Canary intact.\\n");

{indent_block(cleanup_block, 4)}
    return 0;
}}
'''


def render_return_code_outlen_semantic_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)

    if recipe.get("target_api") != "EVP_DecryptFinal_ex":
        raise ValueError("return_code_outlen_semantic recipe renderer currently supports only EVP_DecryptFinal_ex")
    if recipe.get("harness_family") != "return_code_outlen_semantic":
        raise ValueError("recipe harness_family must be return_code_outlen_semantic")
    if recipe.get("oracle_type") != "invalid_padding_output_length_oracle":
        raise ValueError("recipe oracle_type must be invalid_padding_output_length_oracle")

    cipher = slot(adapter, recipe, "cipher")
    key_var = slot(adapter, recipe, "key_variable")
    iv_var = slot(adapter, recipe, "iv_variable")
    input_var = slot(adapter, recipe, "input_variable")
    input_len_var = slot(adapter, recipe, "input_len_variable")
    output_buffer = slot(adapter, recipe, "output_buffer")
    update_len_var = slot(adapter, recipe, "update_len_variable")
    final_len_var = slot(adapter, recipe, "final_len_variable")
    ret_var = slot(adapter, recipe, "return_code_variable")
    ctx_var = slot(adapter, recipe, "context_variable")

    include_lines = render_include_lines(
        {"include_headers": recipe.get("include_headers", [])},
        ["stdio.h", "stdlib.h", "string.h", "openssl/evp.h"],
    )

    return f'''{include_lines}

#define BLOCK_SIZE [INPUT_LEN]
#define PADDING_BYTE_VALUE 0x[PADDING_BYTE]

static int encrypt_one_block_no_padding(const unsigned char {key_var}[16],
                                        const unsigned char {iv_var}[16],
                                        const unsigned char plaintext[BLOCK_SIZE],
                                        unsigned char ciphertext[BLOCK_SIZE])
{{
    EVP_CIPHER_CTX *enc_ctx = NULL;
    unsigned char tmp[64];
    int enc_update_len = 0;
    int enc_final_len = 0;
    int ok = 0;

    memset(tmp, 0, sizeof(tmp));

    enc_ctx = EVP_CIPHER_CTX_new();
    if (enc_ctx == NULL) {{
        printf("[ERROR] EVP_CIPHER_CTX_new failed for encryption.\\n");
        return -1;
    }}

    if (EVP_EncryptInit_ex(enc_ctx, {cipher}, NULL, {key_var}, {iv_var}) <= 0) {{
        printf("[ERROR] EVP_EncryptInit_ex failed.\\n");
        goto cleanup;
    }}

    if (EVP_CIPHER_CTX_set_padding(enc_ctx, 0) <= 0) {{
        printf("[ERROR] EVP_CIPHER_CTX_set_padding encrypt none failed.\\n");
        goto cleanup;
    }}

    if (EVP_EncryptUpdate(enc_ctx, tmp, &enc_update_len, plaintext, BLOCK_SIZE) <= 0) {{
        printf("[ERROR] EVP_EncryptUpdate failed.\\n");
        goto cleanup;
    }}

    if (EVP_EncryptFinal_ex(enc_ctx, tmp + enc_update_len, &enc_final_len) <= 0) {{
        printf("[ERROR] EVP_EncryptFinal_ex failed.\\n");
        goto cleanup;
    }}

    if (enc_update_len + enc_final_len != BLOCK_SIZE) {{
        printf("[ERROR] unexpected encrypted length: %d\\n", enc_update_len + enc_final_len);
        goto cleanup;
    }}

    memcpy(ciphertext, tmp, BLOCK_SIZE);
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(enc_ctx);
    return ok ? 0 : -1;
}}

int main(void)
{{
    EVP_CIPHER_CTX *{ctx_var} = NULL;
    unsigned char {key_var}[16];
    unsigned char {iv_var}[16];
    unsigned char {input_var}[BLOCK_SIZE];
    unsigned char {output_buffer}[64];
    unsigned char bad_plain[BLOCK_SIZE];
    int {input_len_var} = BLOCK_SIZE;
    int {update_len_var} = 0;
    int {final_len_var} = 0;
    int {ret_var} = 0;

    setbuf(stdout, NULL);

    memset({key_var}, 0, sizeof({key_var}));
    memset({iv_var}, 0, sizeof({iv_var}));
    memset({input_var}, 0, sizeof({input_var}));
    memset({output_buffer}, 0, sizeof({output_buffer}));
    memset(bad_plain, 0x41, sizeof(bad_plain));
    bad_plain[BLOCK_SIZE - 1] = (unsigned char) PADDING_BYTE_VALUE;

    if (encrypt_one_block_no_padding({key_var}, {iv_var}, bad_plain, {input_var}) != 0) {{
        printf("[ERROR] invalid-padding input construction failed.\\n");
        return 2;
    }}

    {ctx_var} = EVP_CIPHER_CTX_new();
    if ({ctx_var} == NULL) {{
        printf("[ERROR] EVP_CIPHER_CTX_new failed.\\n");
        return 2;
    }}

    if (EVP_DecryptInit_ex({ctx_var}, {cipher}, NULL, {key_var}, {iv_var}) <= 0) {{
        printf("[ERROR] EVP_DecryptInit_ex failed.\\n");
        EVP_CIPHER_CTX_free({ctx_var});
        return 2;
    }}

    if (EVP_CIPHER_CTX_set_padding({ctx_var}, 1) <= 0) {{
        printf("[ERROR] EVP_CIPHER_CTX_set_padding failed.\\n");
        EVP_CIPHER_CTX_free({ctx_var});
        return 2;
    }}

    if (EVP_DecryptUpdate({ctx_var}, {output_buffer}, &{update_len_var}, {input_var}, {input_len_var}) <= 0) {{
        printf("[ERROR] EVP_DecryptUpdate failed.\\n");
        EVP_CIPHER_CTX_free({ctx_var});
        return 2;
    }}

    {final_len_var} = 0;
    {ret_var} = EVP_DecryptFinal_ex({ctx_var}, {output_buffer} + {update_len_var}, &{final_len_var});

    printf("template_mutation PADDING_BYTE=%02x\\n", (unsigned) PADDING_BYTE_VALUE);
    printf("template_mutation INPUT_LEN=%d\\n", BLOCK_SIZE);
    printf("EVP_DecryptFinal_ex ret=%d\\n", {ret_var});
    printf("update_len=%d\\n", {update_len_var});
    printf("final_len=%d\\n", {final_len_var});

    if ({ret_var} <= 0 && {final_len_var} == 0) {{
        printf("[OK] target rejected invalid padding and final_len remained zero. ret=%d final_len=%d\\n",
               {ret_var}, {final_len_var});
        EVP_CIPHER_CTX_free({ctx_var});
        return 0;
    }}

    if ({ret_var} <= 0 && {final_len_var} != 0) {{
        printf("[BUG] target rejected invalid padding but final_len was polluted. ret=%d final_len=%d\\n",
               {ret_var}, {final_len_var});
        EVP_CIPHER_CTX_free({ctx_var});
        return 1;
    }}

    printf("[TRIAGE] target accepted invalid padding unexpectedly. ret=%d final_len=%d\\n",
           {ret_var}, {final_len_var});
    EVP_CIPHER_CTX_free({ctx_var});
    return 2;
}}
'''


def render_bignum_arithmetic_semantic_source_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    return r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/private/bignum.h"

#define A_LITERAL "[A_VALUE]"
#define B_LITERAL "[B_VALUE]"
#define A_BASE_VALUE [A_BASE]
#define B_BASE_VALUE [B_BASE]

int main(void)
{
    int ret = 0;
    int cmp = 0;
    mbedtls_mpi A;
    mbedtls_mpi B;
    mbedtls_mpi X;

    setbuf(stdout, NULL);

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&X);

    ret = mbedtls_mpi_read_string(&A, A_BASE_VALUE, A_LITERAL);
    if (ret != 0) {
        printf("[ERROR] source read A failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_read_string(&B, B_BASE_VALUE, B_LITERAL);
    if (ret != 0) {
        printf("[ERROR] source read B failed: %d\n", ret);
        goto cleanup;
    }

    cmp = mbedtls_mpi_cmp_abs(&A, &B);
    ret = mbedtls_mpi_sub_abs(&X, &A, &B);

    printf("template_mutation A_VALUE=%s\n", A_LITERAL);
    printf("template_mutation B_VALUE=%s\n", B_LITERAL);
    printf("template_mutation A_BASE=%d\n", A_BASE_VALUE);
    printf("template_mutation B_BASE=%d\n", B_BASE_VALUE);
    printf("source_cmp=%d\n", cmp);
    printf("ret=%d\n", ret);

    if (cmp < 0 && ret != 0) {
        printf("[OK] source rejected negative mbedTLS absolute subtraction. ret=%d\n", ret);
        ret = 0;
        goto cleanup;
    }

    if (cmp < 0 && ret == 0) {
        printf("[TRIAGE] source produced result for negative mbedTLS absolute subtraction; semantic projection needs review.\n");
        ret = 2;
        goto cleanup;
    }

    printf("[INFO] source lhs>=rhs normal mbedTLS sub_abs path. ret=%d\n", ret);
    ret = 0;

cleanup:
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    return ret;
}
'''


def render_bignum_arithmetic_semantic_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)

    if recipe.get("target_api") != "BN_usub":
        raise ValueError("bignum_arithmetic_semantic recipe renderer currently supports only BN_usub")
    if recipe.get("harness_family") != "bignum_arithmetic_semantic":
        raise ValueError("recipe harness_family must be bignum_arithmetic_semantic")
    if recipe.get("oracle_type") != "bignum_negative_result_rejection_oracle":
        raise ValueError("recipe oracle_type must be bignum_negative_result_rejection_oracle")

    lhs_var = c_identifier(slot(adapter, recipe, "lhs_variable"), "a")
    rhs_var = c_identifier(slot(adapter, recipe, "rhs_variable"), "b")
    result_var = c_identifier(slot(adapter, recipe, "result_variable"), "r")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")
    cmp_var = c_identifier(slot(adapter, recipe, "comparison_variable"), "cmp")
    ctx_var = c_identifier(slot(adapter, recipe, "context_variable"), "bn_ctx")

    include_lines = render_include_lines(
        {"include_headers": recipe.get("include_headers", [])},
        ["stdio.h", "stdlib.h", "string.h", "openssl/bn.h"],
    )

    return f'''{include_lines}

#define A_LITERAL "[A_VALUE]"
#define B_LITERAL "[B_VALUE]"
#define A_BASE_VALUE [A_BASE]
#define B_BASE_VALUE [B_BASE]

static int set_bn_from_string(BIGNUM **out, int base, const char *value)
{{
    if (out == NULL || value == NULL) {{
        return 0;
    }}

    if (base == 10) {{
        return BN_dec2bn(out, value) > 0;
    }}

    if (base == 16) {{
        return BN_hex2bn(out, value) > 0;
    }}

    return 0;
}}

int main(void)
{{
    BN_CTX *{ctx_var} = NULL;
    BIGNUM *{lhs_var} = NULL;
    BIGNUM *{rhs_var} = NULL;
    BIGNUM *{result_var} = NULL;
    int {ret_var} = 0;
    int {cmp_var} = 0;

    setbuf(stdout, NULL);

    {ctx_var} = BN_CTX_new();
    {lhs_var} = BN_new();
    {rhs_var} = BN_new();
    {result_var} = BN_new();

    if ({ctx_var} == NULL || {lhs_var} == NULL || {rhs_var} == NULL || {result_var} == NULL) {{
        printf("[ERROR] target BN allocation failed.\\n");
        {ret_var} = 2;
        goto cleanup;
    }}

    if (!set_bn_from_string(&{lhs_var}, A_BASE_VALUE, A_LITERAL)) {{
        printf("[ERROR] target read lhs failed.\\n");
        {ret_var} = 2;
        goto cleanup;
    }}

    if (!set_bn_from_string(&{rhs_var}, B_BASE_VALUE, B_LITERAL)) {{
        printf("[ERROR] target read rhs failed.\\n");
        {ret_var} = 2;
        goto cleanup;
    }}

    {cmp_var} = BN_ucmp({lhs_var}, {rhs_var});
    {ret_var} = BN_usub({result_var}, {lhs_var}, {rhs_var});

    printf("template_mutation A_VALUE=%s\\n", A_LITERAL);
    printf("template_mutation B_VALUE=%s\\n", B_LITERAL);
    printf("template_mutation A_BASE=%d\\n", A_BASE_VALUE);
    printf("template_mutation B_BASE=%d\\n", B_BASE_VALUE);
    printf("cmp=%d\\n", {cmp_var});
    printf("ret=%d\\n", {ret_var});

    if ({cmp_var} < 0 && {ret_var} == 0) {{
        printf("[OK] target rejected lhs<rhs unsigned subtraction or avoided producing result.\\n");
        {ret_var} = 0;
        goto cleanup;
    }}

    if ({cmp_var} < 0 && {ret_var} != 0) {{
        printf("[TRIAGE] target produced result for lhs<rhs unsigned subtraction; semantic projection needs review.\\n");
        {ret_var} = 2;
        goto cleanup;
    }}

    printf("[INFO] target lhs>=rhs normal unsigned subtraction path.\\n");
    {ret_var} = 0;

cleanup:
    BN_free({lhs_var});
    BN_free({rhs_var});
    BN_free({result_var});
    BN_CTX_free({ctx_var});
    return {ret_var};
}}
'''


def render_bignum_serialization_buffer_boundary_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)

    if recipe.get("target_api") != "BN_signed_bn2bin":
        raise ValueError("buffer_canary_boundary recipe renderer currently supports only BN_signed_bn2bin")
    if recipe.get("harness_family") != "buffer_canary_boundary":
        raise ValueError("recipe harness_family must be buffer_canary_boundary")
    if recipe.get("oracle_type") != "bignum_serialization_buffer_boundary_oracle":
        raise ValueError("recipe oracle_type must be bignum_serialization_buffer_boundary_oracle")

    value_var = c_identifier(slot(adapter, recipe, "value_variable"), "a")
    output_buffer = c_identifier(slot(adapter, recipe, "output_buffer"), "buf")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")
    signed_value_var = c_identifier(slot(adapter, recipe, "signed_value_variable"), "signed_value")
    magnitude_var = c_identifier(slot(adapter, recipe, "magnitude_variable"), "magnitude")

    include_lines = render_include_lines(
        {"include_headers": recipe.get("include_headers", [])},
        ["stdio.h", "stdlib.h", "string.h", "openssl/bn.h"],
    )

    return f'''{include_lines}

#define VALUE_LITERAL "[VALUE]"
#define TOLEN_VALUE [BUFLEN]
#define CANARY_SIZE_VALUE [CANARY_SIZE]
#define CANARY_BYTE 0xA5

static int parse_long_literal(const char *s, long *out)
{{
    char *end = NULL;
    long v;

    if (s == NULL || out == NULL) {{
        return 0;
    }}

    v = strtol(s, &end, 10);
    if (end == s || *end != '\\0') {{
        return 0;
    }}

    *out = v;
    return 1;
}}

static int canary_corrupted(const unsigned char *canary, size_t canary_size)
{{
    for (size_t i = 0; i < canary_size; i++) {{
        if (canary[i] != CANARY_BYTE) {{
            return 1;
        }}
    }}
    return 0;
}}

static void print_buffer_prefix(const unsigned char *buf, size_t len)
{{
    size_t limit = len < 16 ? len : 16;

    printf("output_prefix=");
    for (size_t i = 0; i < limit; i++) {{
        printf("%02x", (unsigned) buf[i]);
    }}
    printf("\\n");
}}

int main(void)
{{
    BIGNUM *{value_var} = NULL;
    unsigned char *{output_buffer} = NULL;
    unsigned char *canary = NULL;
    int {ret_var} = 0;
    long {signed_value_var} = 0;
    unsigned long {magnitude_var} = 0;
    size_t tolen = (size_t) TOLEN_VALUE;
    size_t canary_size = (size_t) CANARY_SIZE_VALUE;
    size_t total_len = tolen + canary_size;
    int exit_code = 0;

    setbuf(stdout, NULL);

    printf("OPENSSL_VERSION_TEXT=%s\\n", OPENSSL_VERSION_TEXT);
    printf("template_mutation VALUE=%s\\n", VALUE_LITERAL);
    printf("template_mutation BUFLEN=%zu\\n", tolen);
    printf("template_mutation CANARY_SIZE=%zu\\n", canary_size);

    if (!parse_long_literal(VALUE_LITERAL, &{signed_value_var})) {{
        printf("[ERROR] target VALUE parse failed.\\n");
        return 2;
    }}

    if ({signed_value_var} < 0) {{
        {magnitude_var} = (unsigned long) (-{signed_value_var});
    }} else {{
        {magnitude_var} = (unsigned long) {signed_value_var};
    }}

    if (canary_size == 0 || total_len < tolen) {{
        printf("[ERROR] invalid output/canary sizing.\\n");
        return 2;
    }}

    {output_buffer} = malloc(total_len);
    if ({output_buffer} == NULL) {{
        printf("[ERROR] output allocation failed.\\n");
        return 2;
    }}
    memset({output_buffer}, 0x42, total_len);
    canary = {output_buffer} + tolen;
    memset(canary, CANARY_BYTE, canary_size);

    {value_var} = BN_new();
    if ({value_var} == NULL) {{
        printf("[ERROR] BN_new failed.\\n");
        exit_code = 2;
        goto cleanup;
    }}

    if (!BN_set_word({value_var}, {magnitude_var})) {{
        printf("[ERROR] BN_set_word failed.\\n");
        exit_code = 2;
        goto cleanup;
    }}

    if ({signed_value_var} < 0) {{
        BN_set_negative({value_var}, 1);
    }}

    {ret_var} = BN_signed_bn2bin({value_var}, {output_buffer}, (int) tolen);

    printf("ret=%d\\n", {ret_var});
    print_buffer_prefix({output_buffer}, tolen);

    if (canary_corrupted(canary, canary_size)) {{
        printf("[BUG] target overwrote canary after output buffer.\\n");
        exit_code = 1;
        goto cleanup;
    }}

    if ({ret_var} < 0) {{
        printf("[OK] target rejected small output buffer and canary intact.\\n");
        exit_code = 0;
        goto cleanup;
    }}

    printf("[INFO] target serialized into provided buffer; canary intact.\\n");
    exit_code = 0;

cleanup:
    BN_free({value_var});
    free({output_buffer});
    return exit_code;
}}
'''


def normalize_der_init_block(block: str) -> str:
    block = strip_code_fence(block)
    # The DER pointer-consumption skeleton owns these common oracle variables.
    patterns = [
        r"^\s*const\s+unsigned\s+char\s+\*p\s*=\s*NULL\s*;\s*$",
        r"^\s*long\s+consumed_len\s*=\s*0\s*;\s*$",
        r"^\s*size_t\s+consumed_len\s*=\s*0\s*;\s*$",
    ]
    lines = []
    for line in block.splitlines():
        if any(re.match(pat, line) for pat in patterns):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def extract_static_function(source: str, name: str) -> str:
    marker = f"{name}("
    idx = source.find(marker)
    if idx < 0:
        return ""

    start = source.rfind("static ", 0, idx)
    if start < 0:
        return ""

    brace = source.find("{", idx)
    if brace < 0:
        return ""

    depth = 0
    for pos in range(brace, len(source)):
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1].strip()

    return ""


def der_helper_fallback() -> str:
    return r'''static int hexval(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_to_bin(const char *hex,
                      unsigned char *out,
                      size_t out_size,
                      size_t *out_len)
{
    size_t n = 0;
    int hi = -1;

    while (*hex != '\0') {
        int v;

        if (isspace((unsigned char) *hex)) {
            hex++;
            continue;
        }

        v = hexval((unsigned char) *hex);
        if (v < 0) {
            return -1;
        }

        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_size) {
                return -2;
            }
            out[n++] = (unsigned char) ((hi << 4) | v);
            hi = -1;
        }

        hex++;
    }

    if (hi >= 0) {
        return -3;
    }

    *out_len = n;
    return 0;
}

static const char *select_base_der_hex(const char *der_kind)
{
    static const char *private_base_hex =
        "3063020100021100cc8ab070369ede72920e5a51523c8571"
        "02030100010211009a6318982a7231de1894c54aa4909201"
        "020900f3058fd8dc484d61020900d7770dbd8b78a2110209"
        "009471f14c26428401020813425f060c4b72210208052b93"
        "d01747a87c";
    static const char *public_base_hex =
        "308189028181009f091e6968b474f76f0e9c237c1d895996"
        "ae704b4f6d706acec8d2daac6209bf524aa3f658d0283a"
        "dba1077f6cbe92e425dcde52290b239cade91be86c884254"
        "34986806e85734e159768f3dfea932baaa9409d25bace8ee"
        "9dce0cdde0903207299de575ae60feccf0daf82334ab836"
        "38539b0da74072f253acea8afc8e66bb70203010001";

    if (strcmp(der_kind, "private") == 0) {
        return private_base_hex;
    }
    if (strcmp(der_kind, "public") == 0) {
        return public_base_hex;
    }
    return NULL;
}

static int build_der_with_trailing_garbage(const char *base_hex,
                                           const char *trailing_hex,
                                           unsigned char *der,
                                           size_t der_size,
                                           size_t *der_len,
                                           size_t *trailing_len)
{
    int ret;
    size_t base_len = 0;

    ret = hex_to_bin(base_hex, der, der_size, &base_len);
    if (ret != 0) {
        return ret;
    }

    ret = hex_to_bin(trailing_hex,
                     der + base_len,
                     der_size - base_len,
                     trailing_len);
    if (ret != 0) {
        return ret;
    }

    *der_len = base_len + *trailing_len;
    return 0;
}'''


def extract_der_helpers(source_template_dir: Path) -> str:
    source_path = source_template_dir / "tmpl_mbedtls.c"
    source = source_path.read_text(encoding="utf-8", errors="ignore") if source_path.exists() else ""
    names = [
        "hexval",
        "hex_to_bin",
        "select_base_der_hex",
        "build_der_with_trailing_garbage",
    ]
    helpers = [extract_static_function(source, name) for name in names]
    if all(helpers):
        return "\n\n".join(helpers)
    return der_helper_fallback()


def x509_malformed_der_helper_fallback() -> str:
    return r'''static const unsigned char *select_malformed_der(const char *structure_id,
                                                 size_t *der_len)
{
    static const unsigned char issuer_two_empty_atv_der[] = {
        0x30, 0x24, 0x30, 0x22,
        0xa0, 0x03, 0x02, 0x01, 0x02,
        0x82, 0x04, 0xde, 0xad, 0xbe, 0xef,
        0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00,
        0x30, 0x06,
        0x31, 0x04,
        0x30, 0x00,
        0x30, 0x00
    };

    if (der_len == NULL) {
        return NULL;
    }

    if (strcmp(structure_id, "issuer_two_empty_atv") == 0 ||
        strcmp(structure_id, "default") == 0) {
        *der_len = sizeof(issuer_two_empty_atv_der);
        return issuer_two_empty_atv_der;
    }

    *der_len = sizeof(issuer_two_empty_atv_der);
    return issuer_two_empty_atv_der;
}'''


def extract_x509_malformed_der_helper(source_template_dir: Path) -> str:
    source_path = source_template_dir / "tmpl_mbedtls.c"
    source = source_path.read_text(encoding="utf-8", errors="ignore") if source_path.exists() else ""
    helper = extract_static_function(source, "select_malformed_der")
    return helper or x509_malformed_der_helper_fallback()


def render_der_pointer_consumption_harness(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    extra_headers = []
    if adapter.get("target_api") in {"d2i_RSA_PUBKEY", "d2i_PUBKEY"}:
        extra_headers.append("openssl/x509.h")

    adapter_for_includes = dict(adapter)
    adapter_for_includes["include_headers"] = list(adapter.get("include_headers") or []) + extra_headers
    include_lines = render_include_lines(adapter_for_includes, [])
    helpers = extract_der_helpers(source_template_dir)

    init_block = normalize_der_init_block(adapter.get("init_block", ""))
    input_block = strip_code_fence(adapter.get("input_construction_block", ""))
    trigger_block = strip_code_fence(adapter.get("trigger_block", ""))
    cleanup_block = strip_code_fence(adapter.get("cleanup_block", ""))
    target_api = adapter.get("target_api", "unknown_target_api")

    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

{include_lines}

#define MAX_DER_SIZE 1024
#define TRAILING_GARBAGE_HEX "[TRAILING_GARBAGE_BYTES]"
#define TRAILING_GARBAGE_EXPECTED_LEN ((size_t) [TRAILING_GARBAGE_LEN])

{helpers}

int main(void)
{{
    const char *der_kind = "[DER_KIND]";
    const char *base_hex = NULL;
    unsigned char der[MAX_DER_SIZE];
    size_t der_len = 0;
    size_t trailing_len = 0;
    const unsigned char *p = NULL;
    long consumed_len = 0;
    int ret = 0;

    setbuf(stdout, NULL);
    memset(der, 0, sizeof(der));

    base_hex = select_base_der_hex(der_kind);
    if (base_hex == NULL) {{
        printf("[ERROR] unsupported DER_KIND: %s\\n", der_kind);
        return 2;
    }}

    ret = build_der_with_trailing_garbage(base_hex,
                                          TRAILING_GARBAGE_HEX,
                                          der,
                                          sizeof(der),
                                          &der_len,
                                          &trailing_len);
    if (ret != 0) {{
        printf("[ERROR] DER construction failed: %d\\n", ret);
        return 2;
    }}

    if (trailing_len != TRAILING_GARBAGE_EXPECTED_LEN) {{
        printf("[ERROR] trailing garbage length mismatch: got=%zu expected=%zu\\n",
               trailing_len, TRAILING_GARBAGE_EXPECTED_LEN);
        return 2;
    }}

    /*
     * Adapter-generated initialization.
     */
{indent_block(init_block, 4)}

    /*
     * Adapter-generated input construction.
     */
{indent_block(input_block, 4)}

    /*
     * Adapter-generated trigger call.
     * target_api: {target_api}
     */
{indent_block(trigger_block, 4)}

    printf("ret=%d\\n", ret);
    printf("der_len=%zu\\n", der_len);
    printf("consumed_len=%ld\\n", consumed_len);

    if (ret == 0 && consumed_len < (long) der_len) {{
        printf("[BUG] target decoded first DER object but left trailing garbage unconsumed.\\n");
{indent_block(cleanup_block, 8)}
        return 1;
    }}

    if (ret == 0 && consumed_len == (long) der_len) {{
        printf("[OK] target decoded and consumed full input exactly.\\n");
{indent_block(cleanup_block, 8)}
        return 0;
    }}

    printf("[OK] target rejected trailing-garbage input.\\n");
{indent_block(cleanup_block, 4)}
    return 0;
}}
'''



def render_der_pointer_consumption_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)

    if recipe.get("harness_family") != "der_pointer_consumption":
        raise ValueError("recipe harness_family must be der_pointer_consumption")
    if recipe.get("oracle_type") != "pointer_consumption_semantic_oracle":
        raise ValueError("recipe oracle_type must be pointer_consumption_semantic_oracle")

    target_api = recipe.get("target_api")
    if target_api not in {"d2i_PrivateKey", "d2i_RSAPrivateKey", "d2i_RSA_PUBKEY"}:
        raise ValueError(
            "der_pointer_consumption recipe renderer currently supports only "
            "d2i_PrivateKey, d2i_RSAPrivateKey, d2i_RSA_PUBKEY"
        )

    pointer_var = c_identifier(slot(adapter, recipe, "pointer_variable"), "p")
    consumed_var = c_identifier(slot(adapter, recipe, "consumed_len_variable"), "consumed_len")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")
    input_buffer = c_identifier(slot(adapter, recipe, "input_buffer"), "der")
    input_len = c_identifier(slot(adapter, recipe, "input_length"), "der_len")
    decoded_object = c_identifier(slot(adapter, recipe, "decoded_object"), "obj")

    include_headers = list(recipe.get("include_headers") or [])

    if target_api == "d2i_PrivateKey":
        init_block = f"EVP_PKEY *{decoded_object} = NULL;"
        trigger_block = (
            f"{decoded_object} = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &{pointer_var}, {input_len});\n"
            f"{ret_var} = ({decoded_object} != NULL) ? 0 : -1;\n"
            f"{consumed_var} = (long)({pointer_var} - {input_buffer});"
        )
        cleanup_block = f"EVP_PKEY_free({decoded_object});"
        include_headers.extend(["openssl/evp.h", "openssl/rsa.h"])

    elif target_api == "d2i_RSAPrivateKey":
        init_block = f"RSA *{decoded_object} = NULL;"
        trigger_block = (
            f"{decoded_object} = d2i_RSAPrivateKey(NULL, &{pointer_var}, {input_len});\n"
            f"{ret_var} = ({decoded_object} != NULL) ? 0 : -1;\n"
            f"{consumed_var} = (long)({pointer_var} - {input_buffer});"
        )
        cleanup_block = f"RSA_free({decoded_object});"
        include_headers.extend(["openssl/rsa.h", "openssl/evp.h"])

    else:
        init_block = f"RSA *{decoded_object} = NULL;"
        trigger_block = (
            f"{decoded_object} = d2i_RSA_PUBKEY(NULL, &{pointer_var}, {input_len});\n"
            f"{ret_var} = ({decoded_object} != NULL) ? 0 : -1;\n"
            f"{consumed_var} = (long)({pointer_var} - {input_buffer});"
        )
        cleanup_block = f"RSA_free({decoded_object});"
        include_headers.extend(["openssl/evp.h", "openssl/rsa.h", "openssl/x509.h"])

    recipe_adapter = dict(adapter)
    recipe_adapter["include_headers"] = include_headers
    recipe_adapter["init_block"] = init_block
    recipe_adapter["input_construction_block"] = (
        f"{pointer_var} = {input_buffer};\n"
        f"{consumed_var} = 0;"
    )
    recipe_adapter["trigger_block"] = trigger_block
    recipe_adapter["cleanup_block"] = cleanup_block
    recipe_adapter["target_api"] = target_api

    return render_der_pointer_consumption_harness(
        recipe_adapter,
        source_template_dir,
        source_meta,
        mask_report,
    )



def render_x509_asn1_inner_boundary_from_recipe(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    recipe = load_adapter_recipe(adapter)

    if recipe.get("target_api") != "d2i_X509":
        raise ValueError("x509_asn1_inner_boundary recipe renderer currently supports only d2i_X509")
    if recipe.get("harness_family") not in {"x509_asn1_inner_boundary", "asn1_inner_boundary"}:
        raise ValueError("recipe harness_family must be x509_asn1_inner_boundary")
    if recipe.get("oracle_type") != "inner_asn1_boundary_semantic_oracle":
        raise ValueError("recipe oracle_type must be inner_asn1_boundary_semantic_oracle")

    input_buffer = c_identifier(slot(adapter, recipe, "input_buffer"), "der")
    input_len = c_identifier(slot(adapter, recipe, "input_length"), "der_len")
    pointer_var = c_identifier(slot(adapter, recipe, "pointer_variable"), "p")
    consumed_var = c_identifier(slot(adapter, recipe, "consumed_len_variable"), "consumed_len")
    ret_var = c_identifier(slot(adapter, recipe, "return_code_variable"), "ret")
    decoded_object = c_identifier(slot(adapter, recipe, "decoded_object"), "x509")

    recipe_adapter = dict(adapter)
    recipe_adapter["include_headers"] = list(recipe.get("include_headers") or [])
    recipe_adapter["target_api"] = "d2i_X509"
    recipe_adapter["init_block"] = (
        f"X509 *{decoded_object} = NULL;\n"
        f"const unsigned char *{pointer_var} = NULL;\n"
        f"long {consumed_var} = 0;"
    )
    recipe_adapter["input_construction_block"] = (
        f"{pointer_var} = {input_buffer};\n"
        f"{consumed_var} = 0;"
    )
    recipe_adapter["trigger_block"] = (
        f"{decoded_object} = d2i_X509(NULL, &{pointer_var}, {input_len});\n"
        f"{ret_var} = ({decoded_object} != NULL) ? 0 : -1;\n"
        f"{consumed_var} = (long)({pointer_var} - {input_buffer});"
    )
    recipe_adapter["cleanup_block"] = f"X509_free({decoded_object});"

    return render_x509_asn1_inner_boundary_harness(
        recipe_adapter,
        source_template_dir,
        source_meta,
        mask_report,
    )


def render_x509_asn1_inner_boundary_harness(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    target_api = adapter.get("target_api", "unknown_target_api")
    if target_api != "d2i_X509":
        raise ValueError(
            "x509_asn1_inner_boundary renderer currently supports only target_api=d2i_X509"
        )

    include_lines = render_include_lines(adapter, ["openssl/x509.h", "openssl/err.h"])
    helper = extract_x509_malformed_der_helper(source_template_dir)

    init_block = strip_code_fence(adapter.get("init_block", ""))
    input_block = strip_code_fence(adapter.get("input_construction_block", ""))
    trigger_block = strip_code_fence(adapter.get("trigger_block", ""))
    cleanup_block = strip_code_fence(adapter.get("cleanup_block", "X509_free(x509);"))

    expected_buggy = (
        source_meta.get("expected_buggy_behavior", {}).get("return_code")
        or mask_report.get("oracle", {}).get("bug_signals", [""])[0]
    )
    expected_fixed = (
        source_meta.get("expected_fixed_behavior", {}).get("return_code")
        or mask_report.get("oracle", {}).get("fixed_or_safe_signals", [""])[0]
    )

    return f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

{include_lines}

#define MALFORMED_DER_STRUCTURE_MODE "[MALFORMED_DER_STRUCTURE]"

/*
 * Cross-library harness for MBEDTLS-POC-0017.
 *
 * Source mbedTLS oracle:
 * - buggy signal: ret={expected_buggy}
 * - fixed signal: ret={expected_fixed}
 *
 * OpenSSL d2i_X509 does not expose the same internal mbedTLS error codes.
 * This harness observes return-code and input-pointer consumption semantics.
 */

{helper}

int main(void)
{{
    const unsigned char *der = NULL;
    size_t der_len = 0;
    int ret = 0;

    setbuf(stdout, NULL);

    der = select_malformed_der(MALFORMED_DER_STRUCTURE_MODE, &der_len);
    if (der == NULL || der_len == 0) {{
        printf("[ERROR] malformed DER construction failed.\\n");
        return 2;
    }}

    printf("template_mutation MALFORMED_DER_STRUCTURE=%s\\n", MALFORMED_DER_STRUCTURE_MODE);
    printf("calling d2i_X509...\\n");
    printf("der_len=%zu\\n", der_len);

    /*
     * Adapter-generated initialization.
     */
{indent_block(init_block, 4)}

    /*
     * Adapter-generated input construction.
     */
{indent_block(input_block, 4)}

    /*
     * Adapter-generated trigger call.
     * target_api: {target_api}
     */
{indent_block(trigger_block, 4)}

    printf("ret=%d\\n", ret);
    printf("consumed_len=%ld\\n", consumed_len);
    printf("der_len=%zu\\n", der_len);

    if (ret == 0) {{
        printf("[BUG] target accepted malformed X509/ASN1 inner-boundary input. consumed_len=%ld der_len=%zu\\n",
               consumed_len, der_len);
{indent_block(cleanup_block, 8)}
        return 1;
    }}

    printf("[OK] target rejected malformed X509/ASN1 inner-boundary input.\\n");
{indent_block(cleanup_block, 4)}
    return 0;
}}
'''


RENDERERS: Dict[str, Callable[[Dict[str, Any], Path, Dict[str, Any], Dict[str, Any]], str]] = {
    "buffer_canary_boundary": render_buffer_canary_harness,
    "der_pointer_consumption": render_der_pointer_consumption_harness,
    "x509_asn1_inner_boundary": render_x509_asn1_inner_boundary_harness,
    "asn1_inner_boundary": render_x509_asn1_inner_boundary_harness,
}


def render_target_c_from_adapter(
    adapter: Dict[str, Any],
    source_template_dir: Path,
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
) -> str:
    if is_recipe_adapter(adapter):
        recipe = load_adapter_recipe(adapter)
        harness_family = recipe.get("harness_family") or adapter.get("harness_family")
        if harness_family == "bignum_arithmetic_semantic":
            return render_bignum_arithmetic_semantic_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if harness_family == "return_code_outlen_semantic":
            return render_return_code_outlen_semantic_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family == "buffer_canary_boundary"
            and is_bignum_serialization_buffer_boundary_recipe(adapter, recipe)
        ):
            return render_bignum_serialization_buffer_boundary_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family == "der_pointer_consumption"
            and is_der_pointer_consumption_recipe(adapter, recipe)
        ):
            return render_der_pointer_consumption_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family in {"x509_asn1_inner_boundary", "asn1_inner_boundary"}
            and is_x509_asn1_inner_boundary_recipe(adapter, recipe)
        ):
            return render_x509_asn1_inner_boundary_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family == "null_deref_dispatch"
            and is_null_deref_dispatch_recipe(adapter, recipe)
        ):
            return render_null_deref_dispatch_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family == "crash_sanitizer_oracle"
            and is_crash_sanitizer_oracle_recipe(adapter, recipe)
        ):
            return render_crash_sanitizer_oracle_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family == "invalid_parameter_setup_oracle"
            and is_invalid_parameter_setup_oracle_recipe(adapter, recipe)
        ):
            return render_invalid_parameter_setup_oracle_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family == "object_state_lifecycle"
            and is_object_state_lifecycle_recipe(adapter, recipe)
        ):
            return render_object_state_lifecycle_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        if (
            harness_family == "pkey_capability_mismatch_oracle"
            and is_pkey_capability_mismatch_oracle_recipe(adapter, recipe)
        ):
            return render_pkey_capability_mismatch_oracle_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            )
        raise ValueError(f"unknown recipe harness_family={harness_family!r}")

    harness_family = source_meta.get("harness_family") or "buffer_canary_boundary"
    renderer = RENDERERS.get(harness_family)
    if renderer is None:
        known = ", ".join(sorted(RENDERERS))
        raise ValueError(f"unknown harness_family={harness_family!r}; known: {known}")
    return renderer(adapter, source_template_dir, source_meta, mask_report)


def build_cross_meta(source_meta: Dict[str, Any], adapter: Dict[str, Any]) -> Dict[str, Any]:
    cross_meta = copy.deepcopy(source_meta)
    cross_meta["status"] = "cross_generated_from_llm_adapter"

    target_lib = adapter.get("target_library")
    target_api = adapter.get("target_api")

    base_template_id = source_meta.get("template_id", "UNKNOWN_TEMPLATE")
    target_suffix = sanitize_name(f"{target_lib}_{target_api}").upper()
    cross_meta["source_template_id"] = base_template_id
    cross_meta["template_id"] = f"{base_template_id}__{target_suffix}"

    cross_meta.setdefault("cross_library", {})
    cross_meta["cross_library"][target_lib] = {
        "target_api": target_api,
        "target_template": f"tmpl_{target_lib}.c",
        "adapter_source": "recipe_slot_bindings" if is_recipe_adapter(adapter) else "llm_adapter_yaml",
        "applicability": adapter.get("applicability"),
        "preserved_features": adapter.get("preserved_features", []),
        "lost_or_weakened_features": adapter.get("lost_or_weakened_features", []),
        "llm_status": adapter.get("_llm_status"),
    }

    if is_recipe_adapter(adapter):
        cross_meta["cross_library"][target_lib]["adapter_recipe"] = adapter.get("adapter_recipe")
        cross_meta["cross_library"][target_lib]["slot_bindings"] = adapter.get("slot_bindings", {})
        recipe = load_adapter_recipe(adapter)
        if recipe.get("harness_family"):
            cross_meta["harness_family"] = recipe.get("harness_family")
        if recipe.get("oracle_type"):
            cross_meta["oracle_type"] = recipe.get("oracle_type")

    return cross_meta


def build_cross_mapping(
    source_meta: Dict[str, Any],
    mask_report: Dict[str, Any],
    adapter: Dict[str, Any],
    adapter_meta: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "source": {
            "library": source_meta.get("poc_source", {}).get("library"),
            "api": source_meta.get("poc_source", {}).get("api"),
            "template_id": source_meta.get("template_id"),
            "semantic_operation": source_meta.get("operation", {}).get("abstract"),
            "bug_class": source_meta.get("operation", {}).get("bug_class", []),
            "poc_pattern": mask_report.get("poc_pattern", {}),
        },
        "target": {
            "library": adapter.get("target_library"),
            "candidate_api": adapter.get("target_api"),
        },
        "adapter": {
            "adapter_recipe": adapter.get("adapter_recipe", ""),
            "slot_bindings": adapter.get("slot_bindings", {}),
            "adapter_mode": adapter.get("_adapter_mode", ""),
            "include_headers": adapter.get("include_headers", []),
            "type_mapping": adapter.get("type_mapping", {}),
            "constant_mapping": adapter.get("constant_mapping", {}),
            "init_block": adapter.get("init_block", ""),
            "input_construction_block": adapter.get("input_construction_block", ""),
            "trigger_block": adapter.get("trigger_block", ""),
            "return_value_semantics": adapter.get("return_value_semantics", ""),
            "oracle_strategy": adapter.get("oracle_strategy", {}),
            "cleanup_block": adapter.get("cleanup_block", ""),
            "llm_status": adapter.get("_llm_status"),
        },
        "candidate": adapter_meta.get("candidate", {}),
        "preserved_vulnerability_features": adapter.get("preserved_features", []),
        "lost_or_weakened_features": adapter.get("lost_or_weakened_features", []),
        "source_expected_behavior": {
            "buggy": source_meta.get("expected_buggy_behavior", {}),
            "fixed": source_meta.get("expected_fixed_behavior", {}),
            "note": (
                "The target API is not expected to reproduce exact mbedTLS numeric "
                "error codes; cross-library validation uses the oracle semantics "
                "defined by the migrated harness family."
            ),
        },
        "notes": [
            "Generated from LLM-filled structured adapter YAML.",
            "The C harness skeleton is fixed; the target-specific blocks come from adapter.yaml.",
            "This is vulnerability-path migration, not strict full API semantic equivalence.",
        ],
    }


def generate_one(adapter_file: Path, adapter_root: Path, out_root: Path) -> bool:
    adapter = load_yaml(adapter_file)
    adapter_meta = load_or_infer_adapter_meta(adapter, adapter_file, adapter_root)
    recipe = load_adapter_recipe(adapter) if is_recipe_adapter(adapter) else {}
    is_bignum_projection = is_bignum_arithmetic_semantic_recipe(adapter, recipe) if recipe else False

    source_files = adapter_meta.get("source_files", {})
    template_meta_path = optional_path(source_files.get("template_meta"))
    mask_report_path = optional_path(source_files.get("mask_report"))

    if mask_report_path is None or not mask_report_path.exists():
        print(f"[FAIL] missing mask_report for adapter: {adapter_file}")
        return False

    if template_meta_path is not None and template_meta_path.exists():
        source_template_dir = template_meta_path.parent
        source_meta = load_yaml(template_meta_path)
    else:
        source_template_dir = mask_report_path.parent
        source_meta = load_yaml(source_template_dir / "template_meta.yaml")
    mask_report = load_yaml(mask_report_path)

    rel = adapter_file.parent.relative_to(adapter_root)
    out_dir = out_root / rel
    out_dir.mkdir(parents=True, exist_ok=True)

    copy_names = [
        "poc_original.c",
        "tmpl_mbedtls.c",
        "mask_report.yaml",
        "rag_context.json",
        "llm_updates.json",
        "normalization_report.json",
    ]
    if is_bignum_projection:
        copy_names = []

    copy_if_exists(source_template_dir, out_dir, copy_names)

    if recipe and is_bignum_serialization_buffer_boundary_recipe(adapter, recipe):
        source_out = out_dir / "tmpl_mbedtls.c"
        if source_out.exists():
            source_text = source_out.read_text(encoding="utf-8")
            source_text = source_text.replace(
                '#include "mbedtls/bignum.h"',
                '#include "mbedtls/private/bignum.h"',
            )
            write_text(source_out, source_text)

    if recipe and is_null_deref_dispatch_recipe(adapter, recipe):
        source_out = out_dir / "tmpl_mbedtls.c"
        write_text(source_out, render_null_deref_dispatch_mbedtls_harness(source_meta))

    if is_bignum_projection:
        write_text(
            out_dir / "tmpl_mbedtls.c",
            render_bignum_arithmetic_semantic_source_from_recipe(
                adapter,
                source_template_dir,
                source_meta,
                mask_report,
            ),
        )
        dump_yaml(out_dir / "mask_report.yaml", bignum_semantic_projection_mask_report(source_meta, adapter))

    target_lib = adapter.get("target_library", "target")

    cross_meta = build_cross_meta(source_meta, adapter)
    if is_bignum_projection:
        cross_meta = bignum_semantic_projection_meta(cross_meta, adapter)
    dump_yaml(out_dir / "template_meta.yaml", cross_meta)

    write_text(
        out_dir / f"tmpl_{target_lib}.c",
        render_target_c_from_adapter(adapter, source_template_dir, source_meta, mask_report),
    )

    cross_mapping = build_cross_mapping(source_meta, mask_report, adapter, adapter_meta)
    if is_bignum_projection:
        cross_mapping = scrub_forbidden_tokens(cross_mapping)
    elif is_bignum_serialization_buffer_boundary_recipe(adapter, recipe) if recipe else False:
        cross_mapping = scrub_cross_family_tokens(cross_mapping, BUFFER_CANARY_RECIPE_FORBIDDEN_TOKENS)
    dump_yaml(out_dir / "cross_mapping.yaml", cross_mapping)

    harness_family = source_meta.get("harness_family") or "buffer_canary_boundary"
    if is_recipe_adapter(adapter):
        recipe = load_adapter_recipe(adapter)
        harness_family = recipe.get("harness_family") or adapter.get("harness_family") or harness_family

    if harness_family == "bignum_arithmetic_semantic":
        oracle_text = """The migrated harness uses a bignum arithmetic semantic projection oracle.

This is not a full memory-boundary migration of the original mbedTLS limb-storage bug. OpenSSL 3.x BIGNUM storage is opaque through the public API, so the direct canary-after-limbs oracle is intentionally not modeled here.

Safe behavior:

- for `lhs < rhs`, the target rejects or avoids producing a result for unsigned subtraction.

Triage behavior:

- for `lhs < rhs`, the target produces a result; this is a semantic-projection mismatch and requires review, not an automatic memory-corruption bug.

Normal behavior:

- for `lhs >= rhs`, unsigned subtraction is treated as the ordinary non-vulnerable arithmetic path.
"""
    elif harness_family == "return_code_outlen_semantic":
        oracle_text = """The migrated harness uses a return-code plus output-length semantic oracle for invalid padding finalization.

Bug candidate behavior:

- target finalization API reports invalid padding failure;
- the caller-visible final output length is non-zero after that failure.

Safe behavior:

- target finalization API reports invalid padding failure;
- the caller-visible final output length remains zero.

Unexpected success is treated as a triage result because the input is constructed to contain invalid padding.
"""
    elif (
        harness_family == "buffer_canary_boundary"
        and is_bignum_serialization_buffer_boundary_recipe(adapter, recipe) if recipe else False
    ):
        oracle_text = """The migrated harness uses a bignum serialization buffer-boundary oracle.

Bug candidate behavior:

- target serialization overwrites the canary after the caller-provided output buffer;
- sanitizer output reports a memory-safety failure.

Safe behavior:

- target serialization rejects a too-small output buffer and the canary remains intact.

Triage behavior:

- target serialization succeeds into the caller-provided buffer and the canary remains intact. This is a normal serialization path that does not reproduce the original mbedTLS bug by itself.
"""
    elif harness_family == "der_pointer_consumption":
        oracle_text = """The migrated harness uses a pointer-consumption semantic oracle for DER parsing.

Bug candidate behavior:

- target decoder returns success;
- `consumed_len < der_len`, meaning the first DER object was decoded while trailing garbage remained unconsumed.

Safe behavior:

- target decoder rejects the trailing-garbage input; or
- target decoder succeeds and `consumed_len == der_len`.
"""
    elif harness_family in {"x509_asn1_inner_boundary", "asn1_inner_boundary"}:
        oracle_text = """The migrated harness uses an X.509 / ASN.1 inner-boundary semantic oracle.

Bug candidate behavior:

- `d2i_X509()` returns a non-NULL X509 object;
- the harness maps this to `ret == 0`, meaning the target accepted malformed inner-boundary DER.

Safe behavior:

- `d2i_X509()` returns NULL;
- the harness maps this to `ret != 0`, meaning the target rejected the malformed DER.

The harness also records `consumed_len` for pointer-consumption analysis, but it does not require OpenSSL to reproduce mbedTLS numeric error codes.
"""
    else:
        oracle_text = """The migrated harness uses a memory-safety oracle inherited from the source PoC pattern. The target API is executed with a caller-provided output buffer followed by a canary region.

Bug candidate behavior:

- canary corruption;
- sanitizer crash;
- out-of-bounds write signal.

Safe behavior:

- canary region remains intact;
- no sanitizer crash is observed.
"""

    adapter_mode_text = "recipe slot bindings" if is_recipe_adapter(adapter) else "LLM adapter blocks"

    readme = f"""# Cross-Library Template Generated from LLM Adapter

## Source

- Source template: `{source_meta.get("template_id")}`
- Source API: `{source_meta.get("poc_source", {}).get("api")}`
- Source library: `{source_meta.get("poc_source", {}).get("library")}`
- Harness family: `{harness_family}`

## Target API

- Target library: `{adapter.get("target_library")}`
- Target API: `{adapter.get("target_api")}`
- LLM status: `{adapter.get("_llm_status")}`
- Adapter mode: `{adapter_mode_text}`

## Vulnerability

This template migrates the source vulnerability path using a structured adapter generated from RAG evidence and candidate scoring.

## Oracle

{oracle_text}

## Adapter

The target-specific include, input-construction, trigger-call, return-semantics, oracle strategy, and cleanup blocks are stored in `cross_mapping.yaml`.

## Files

- `tmpl_mbedtls.c`
- `tmpl_{target_lib}.c`
- `template_meta.yaml`
- `cross_mapping.yaml`
- `mask_report.yaml`
"""
    write_text(out_dir / "README.md", readme)

    print(f"[OK] generated {out_dir}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate cross-library templates from LLM adapter YAML.")
    parser.add_argument("--adapter-root", default="adapters")
    parser.add_argument("--out-root", default="cross_templates_from_adapters")
    args = parser.parse_args()

    adapter_root = Path(args.adapter_root)
    out_root = Path(args.out_root)

    out_root.mkdir(parents=True, exist_ok=True)

    count = 0

    adapter_files = sorted(adapter_root.rglob("adapter.yaml"))
    if not adapter_files:
        print(f"[ERROR] no adapter.yaml found under {adapter_root}")
        return 1

    for af in adapter_files:
        try:
            if generate_one(af, adapter_root, out_root):
                count += 1
        except Exception as e:
            print(f"[FAIL] {af}: {e}")

    print("=" * 80)
    print(f"[SUMMARY] generated cross templates from adapters: {count}")
    print(f"[SUMMARY] output root: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

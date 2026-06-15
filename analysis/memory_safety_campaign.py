"""Run a local memory-safety focused OpenSSL ASAN campaign.

This campaign intentionally ignores ordinary API semantic observations. It
only promotes sanitizer reports, crash signals, hangs, or explicit canary
corruption to candidates.
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from runner.sanitizer_env import lib_dir_for_install, matched_keywords, run_env, sanitizer_kinds, signal_name


TASK_V1 = "memory_safety_focused_campaign_v1"
TASK_V2 = "memory_safety_focused_campaign_v2_remaining_boundaries"
TASK_FIX_CONTINUE = "memory_safety_v2_oracle_fix_continue_canary_null_v1"
TASK_DECODEBLOCK_NULL = "decodeblock_oracle_fix_and_null_deref_dispatch_v1"
TASK_VALID_CONTRACT = "memory_candidate_closure_and_valid_contract_campaign_v1"
TASK_STRUCTURED_PARSER = "structured_parser_memory_campaign_v1"
DEFAULT_OUT_DIR = f"artifacts/campaigns/{TASK_V1}"
DEFAULT_OPENSSL_INSTALL = "/home/wen/work/install-openssl-3.5.5-asan"
DEFAULT_INVENTORY = "artifacts/reports/family_inventory_registry_reconcile_v2"
PRIORITY_V1 = [
    "asn1_nested_boundary",
    "x509_asn1_inner_boundary",
    "ossl_store_decoder_boundary_deep",
    "bignum_serialization_boundary_deep",
    "memory_length_boundary",
    "buffer_canary_boundary",
    "null_deref_dispatch",
]
PRIORITY_V2 = [
    "memory_length_boundary",
    "buffer_canary_boundary",
    "null_deref_dispatch",
]
PRIORITY_FIX_CONTINUE = [
    "buffer_canary_boundary",
    "null_deref_dispatch",
]
PRIORITY_DECODEBLOCK_NULL = [
    "null_deref_dispatch",
]
PRIORITY_VALID_CONTRACT = [
    "valid_decode_boundary",
    "valid_evp_mac_boundary",
    "valid_bio_boundary",
]
PRIORITY_STRUCTURED_PARSER = [
    "asn1_nested_boundary_structured",
    "x509_inner_boundary_structured",
    "pkcs_container_inner_boundary_structured",
]
V1_COMPLETED = [
    "asn1_nested_boundary",
    "x509_asn1_inner_boundary",
    "ossl_store_decoder_boundary_deep",
    "bignum_serialization_boundary_deep",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--openssl-install", default=DEFAULT_OPENSSL_INSTALL)
    parser.add_argument("--inventory-root", default=DEFAULT_INVENTORY)
    parser.add_argument("--previous-memory-campaign", default=f"artifacts/campaigns/{TASK_V1}")
    parser.add_argument("--candidate-triage-root", default="artifacts/triage/memlen_null_input_nonzero_triage_v1")
    parser.add_argument("--campaign-version", choices=["v1", "v2", "fix_continue", "decodeblock_null", "valid_contract", "structured_parser"], default="")
    parser.add_argument("--max-families", type=int, default=4)
    parser.add_argument("--cases-per-family", type=int, default=20)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def c_array(data: bytes) -> str:
    if not data:
        return "0"
    return ", ".join(f"0x{b:02x}" for b in data)


def byte_cases() -> list[tuple[str, bytes]]:
    return [
        ("empty_input", b""),
        ("single_tag_only", b"\x30"),
        ("length_longer_than_buffer", b"\x30\x10\x02\x01\x01"),
        ("indefinite_length_form", b"\x30\x80\x02\x01\x01"),
        ("nested_sequence_depth_8", b"\x30\x10" * 8 + b"\x05\x00"),
        ("nested_sequence_depth_32", b"\x30\x40" * 32 + b"\x05\x00"),
        ("nested_sequence_depth_128", b"\x30\x81\x80" * 40 + b"\x05\x00"),
        ("nested_set_sequence_mixed", b"\x31\x0a\x30\x08\x31\x06\x30\x04\x05\x00"),
        ("constructed_octet_missing_eoc", b"\x24\x80\x04\x01A"),
        ("huge_length_short_buffer", b"\x30\x84\x7f\xff\xff\xff\x02\x01\x01"),
        ("negative_integer_malformed_length", b"\x02\x82\x00\x04\xff"),
        ("zero_length_integer", b"\x02\x00"),
        ("bit_string_invalid_unused_bits", b"\x03\x02\x08\x00"),
        ("high_tag_number_malformed", b"\x1f\xff\xff\x7f\x01\x00"),
        ("random_structured_der_like", b"\x30\x0c\x02\x01\x01\x04\x03abc\x06\x02\x2a\x03"),
        ("boundary_truncation", b"\x30\x0a\x02\x01\x01\x04"),
        ("long_form_length_leading_zero", b"\x04\x82\x00\x03abc"),
        ("excessive_null_nesting", b"\x30\x08\x30\x06\x30\x04\x05\x00"),
        ("object_malformed_length", b"\x06\x05\x2a\x86\x48"),
        ("malformed_random_corpus_sample", bytes([0x30, 0x13, 0xa0, 0x80, 0x02, 0xff, 0x00, 0x00])),
    ]


def asn1_case_source(case_id: str, data: bytes) -> str:
    return f"""#include <stdio.h>
#include <openssl/asn1.h>
int main(void) {{
    const unsigned char data[] = {{{c_array(data)}}};
    const unsigned char *p = data;
    long len = {len(data)};
    ASN1_TYPE *obj = d2i_ASN1_TYPE(NULL, &p, len);
    const char *actual = obj != NULL ? "success" : "error";
    printf("ORACLE_EVENT family=asn1_nested_boundary\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual);
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=0\\n");
    printf("ORACLE_EVENT contract_boundary=0\\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\\n");
    ASN1_TYPE_free(obj);
    return 0;
}}
"""


def x509_case_source(case_id: str, data: bytes, api: str) -> str:
    free_call = {"d2i_X509": "X509_free", "d2i_X509_REQ": "X509_REQ_free", "d2i_X509_CRL": "X509_CRL_free"}[api]
    typ = {"d2i_X509": "X509", "d2i_X509_REQ": "X509_REQ", "d2i_X509_CRL": "X509_CRL"}[api]
    return f"""#include <stdio.h>
#include <openssl/x509.h>
int main(void) {{
    const unsigned char data[] = {{{c_array(data)}}};
    const unsigned char *p = data;
    long len = {len(data)};
    {typ} *obj = {api}(NULL, &p, len);
    const char *actual = obj != NULL ? "success" : "error";
    printf("ORACLE_EVENT family=x509_asn1_inner_boundary\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual);
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=0\\n");
    printf("ORACLE_EVENT contract_boundary=0\\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\\n");
    {free_call}(obj);
    return 0;
}}
"""


def decoder_case_source(case_id: str, data: bytes, input_type: str) -> str:
    return f"""#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
int main(void) {{
    const unsigned char data[] = {{{c_array(data)}}};
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(data, {len(data)});
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "{input_type}", NULL, NULL, 0, NULL, NULL);
    int ret = 0;
    if (bio != NULL && ctx != NULL)
        ret = OSSL_DECODER_from_bio(ctx, bio);
    printf("ORACLE_EVENT family=ossl_store_decoder_boundary_deep\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", ret == 1 ? "success" : "error");
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=0\\n");
    printf("ORACLE_EVENT contract_boundary=0\\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\\n");
    OSSL_DECODER_CTX_free(ctx);
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return 0;
}}
"""


def bn_case_source(case_id: str, strategy: str) -> str:
    bodies = {
        "zero_length_bin2bn": "a = BN_bin2bn(buf, 0, NULL); ret = (a != NULL);",
        "null_input_zero_length": "a = BN_bin2bn(NULL, 0, NULL); ret = (a != NULL);",
        "large_bounded_binary": "for (int i=0;i<256;i++) buf[i]=(unsigned char)i; a=BN_bin2bn(buf,256,NULL); ret=(a!=NULL);",
        "leading_zeros_large": "for (int i=32;i<128;i++) buf[i]=(unsigned char)i; a=BN_bin2bn(buf,128,NULL); ret=(a!=NULL);",
        "bn2binpad_exact": "BN_hex2bn(&a,\"01020304\"); ret=BN_bn2binpad(a,out+8,4);",
        "bn2binpad_small": "BN_hex2bn(&a,\"01020304\"); ret=BN_bn2binpad(a,out+8,3);",
        "bn2binpad_zero": "BN_hex2bn(&a,\"01\"); ret=BN_bn2binpad(a,out+8,0);",
        "negative_serialization": "BN_set_word(a,7); BN_set_negative(a,1); s=BN_bn2hex(a); ret=(s!=NULL);",
        "negative_zero": "BN_zero(a); BN_set_negative(a,1); ret=BN_is_negative(a);",
        "invalid_hex": "ret=BN_hex2bn(&a,\"nothex\");",
        "long_hex": "for(int i=0;i<240;i++) hex[i]=(i%2)?'a':'f'; hex[240]=0; ret=BN_hex2bn(&a,hex);",
        "invalid_decimal": "ret=BN_dec2bn(&a,\"12no34\");",
        "long_decimal": "for(int i=0;i<240;i++) hex[i]=(char)('0'+(i%10)); hex[240]=0; ret=BN_dec2bn(&a,hex);",
        "alternating_ff00": "for(int i=0;i<128;i++) buf[i]=(i%2)?0x00:0xff; a=BN_bin2bn(buf,128,NULL); ret=(a!=NULL);",
        "all_ff": "for(int i=0;i<128;i++) buf[i]=0xff; a=BN_bin2bn(buf,128,NULL); ret=(a!=NULL);",
        "all_00": "for(int i=0;i<128;i++) buf[i]=0x00; a=BN_bin2bn(buf,128,NULL); ret=(a!=NULL);",
        "canary_bn2binpad": "BN_hex2bn(&a,\"01020304\"); ret=BN_bn2binpad(a,out+8,4);",
        "length_consistency": "BN_hex2bn(&a,\"0102030405\"); ret=(BN_num_bytes(a)==5);",
        "repeated_loop": "BN_hex2bn(&a,\"01020304\"); for(int i=0;i<1000;i++) ret=BN_bn2binpad(a,out+8,4);",
        "random_bounded": "for(int i=0;i<96;i++) buf[i]=(unsigned char)((i*37+11)&255); a=BN_bin2bn(buf,96,NULL); ret=(a!=NULL);",
    }
    body = bodies[strategy]
    return f"""#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
int main(void) {{
    unsigned char buf[512] = {{0}};
    unsigned char out[64];
    char hex[512] = {{0}};
    BIGNUM *a = BN_new();
    char *s = NULL;
    int ret = 0;
    memset(out, 0xcc, sizeof(out));
    {body}
    int canary_corrupted = 0;
    for (int i=0;i<8;i++) if (out[i] != 0xcc) canary_corrupted = 1;
    for (int i=12;i<64;i++) if (out[i] != 0xcc) canary_corrupted = 1;
    printf("ORACLE_EVENT family=bignum_serialization_boundary_deep\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT expected_behavior=memory_safety_watch\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", ret >= 0 ? "success" : "error");
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=%d\\n", canary_corrupted);
    printf("ORACLE_EVENT contract_boundary=0\\n");
    printf("ORACLE_EVENT candidate_label=%s\\n", canary_corrupted ? "memory_safety_candidate" : "no_candidate");
    OPENSSL_free(s);
    BN_free(a);
    return 0;
}}
"""


def memory_length_case_source(case_id: str, strategy: str) -> str:
    bodies = {
        "zero_length_input": "ret = EVP_EncodeBlock(out + 16, in, 0); actual = ret >= 0 ? \"success\" : \"error\";",
        "null_input_zero_length": "ret = EVP_EncodeBlock(out + 16, NULL, 0); actual = ret >= 0 ? \"success\" : \"error\";",
        "null_input_nonzero": "ret = EVP_EncodeBlock(out + 16, NULL, 4); actual = ret >= 0 ? \"success\" : \"error\";",
        "encode_exact_output": "ret = EVP_EncodeBlock(out + 16, in, 3); actual = ret >= 0 ? \"success\" : \"error\";",
        "encode_one_byte_short": "ret = EVP_EncodeBlock(out + 16, in, 6); actual = ret >= 0 ? \"success\" : \"error\";",
        "decode_zero_size": "ret = EVP_DecodeBlock(out + 16, b64, 0); actual = ret >= 0 ? \"success\" : \"error\";",
        "decode_malformed_short_output": "ret = EVP_DecodeBlock(out + 16, bad64, 8); actual = ret >= 0 ? \"success\" : \"error\";",
        "decode_padding_edge": "ret = EVP_DecodeBlock(out + 16, pad64, 8); actual = ret >= 0 ? \"success\" : \"error\";",
        "digest_null_input_zero": "md = EVP_MD_CTX_new(); ret = EVP_DigestInit_ex(md, EVP_sha256(), NULL); if (ret == 1) ret = EVP_DigestUpdate(md, NULL, 0); actual = ret == 1 ? \"success\" : \"error\"; EVP_MD_CTX_free(md);",
        "digest_null_input_nonzero": "md = EVP_MD_CTX_new(); ret = EVP_DigestInit_ex(md, EVP_sha256(), NULL); if (ret == 1) ret = EVP_DigestUpdate(md, NULL, 4); actual = ret == 1 ? \"success\" : \"error\"; EVP_MD_CTX_free(md);",
        "hmac_null_key_zero": "hmacp = HMAC(EVP_sha256(), NULL, 0, in, 8, out + 16, &hmac_len); actual = hmacp != NULL ? \"success\" : \"error\";",
        "hmac_null_data_zero": "hmacp = HMAC(EVP_sha256(), in, 8, NULL, 0, out + 16, &hmac_len); actual = hmacp != NULL ? \"success\" : \"error\";",
        "hmac_null_output_disabled": "actual = \"disabled\"; ret = 0;",
        "bn_bn2binpad_too_small_canary": "bn = BN_new(); BN_hex2bn(&bn, \"01020304\"); ret = BN_bn2binpad(bn, out + 16, 3); actual = ret >= 0 ? \"success\" : \"error\"; BN_free(bn);",
        "bn_bn2binpad_exact_canary": "bn = BN_new(); BN_hex2bn(&bn, \"01020304\"); ret = BN_bn2binpad(bn, out + 16, 4); actual = ret >= 0 ? \"success\" : \"error\"; BN_free(bn);",
        "bio_read_short_buffer": "bio = BIO_new_mem_buf(in, 32); ret = BIO_read(bio, out + 16, 4); actual = ret >= 0 ? \"success\" : \"error\"; BIO_free(bio);",
        "bio_write_larger_len_disabled": "actual = \"disabled\"; ret = 0;",
        "encrypt_update_short_output": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL); if (ret == 1) ret = EVP_CIPHER_CTX_set_padding(cipher, 0); if (ret == 1) ret = EVP_EncryptUpdate(cipher, out + 16, &outl, in, 16); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "decrypt_update_short_output": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_DecryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL); if (ret == 1) ret = EVP_CIPHER_CTX_set_padding(cipher, 0); if (ret == 1) ret = EVP_DecryptUpdate(cipher, out + 16, &outl, in, 16); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "overlapping_encode_observation": "ret = EVP_EncodeBlock(in, in, 6); actual = ret >= 0 ? \"success\" : \"error\";",
        "repeated_update_small_chunks": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL); if (ret == 1) ret = EVP_CIPHER_CTX_set_padding(cipher, 0); for (int i = 0; ret == 1 && i < 4; i++) ret = EVP_EncryptUpdate(cipher, out + 16, &outl, in + i * 4, 4); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "update_len_zero_after_normal": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL); if (ret == 1) ret = EVP_EncryptUpdate(cipher, out + 16, &outl, in, 16); if (ret == 1) ret = EVP_EncryptUpdate(cipher, out + 16, &outl, in, 0); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "max_bounded_len": "ret = EVP_EncodeBlock(out + 16, large, 192); actual = ret >= 0 ? \"success\" : \"error\";",
        "length_mismatch_actual_buffer": "ret = EVP_EncodeBlock(out + 16, in, 64); actual = ret >= 0 ? \"success\" : \"error\";",
        "output_len_pointer_null_disabled": "actual = \"disabled\"; ret = 0;",
        "output_len_pointer_valid_short_buffer": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, key, NULL); if (ret == 1) ret = EVP_EncryptUpdate(cipher, out + 16, &outl, in, 16); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "off_by_one_length": "ret = EVP_EncodeBlock(out + 16, in, 7); actual = ret >= 0 ? \"success\" : \"error\";",
        "off_by_many_length": "ret = EVP_EncodeBlock(out + 16, in, 31); actual = ret >= 0 ? \"success\" : \"error\";",
        "repeated_length_boundary_loop": "for (int i = 0; i < 64; i++) ret = EVP_EncodeBlock(out + 16, in, (i % 12)); actual = ret >= 0 ? \"success\" : \"error\";",
        "randomized_bounded_lengths": "for (int i = 1; i < 20; i++) ret = EVP_EncodeBlock(out + 16, in, (i * 7) % 32); actual = ret >= 0 ? \"success\" : \"error\";",
        "canary_protected_output": "ret = EVP_EncodeBlock(out + 16, in, 12); actual = ret >= 0 ? \"success\" : \"error\";",
    }
    body = bodies[strategy]
    return f"""#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
int main(void) {{
    unsigned char arena[320];
    unsigned char *out = arena;
    unsigned char in[96];
    unsigned char large[256];
    unsigned char key[16];
    unsigned char b64[] = "QUJDRA==";
    unsigned char bad64[] = "!!!!====";
    unsigned char pad64[] = "QQ======";
    const char *actual = "error";
    int ret = 0, outl = 0;
    unsigned int hmac_len = 0;
    unsigned char *hmacp = NULL;
    EVP_MD_CTX *md = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    BIO *bio = NULL;
    BIGNUM *bn = NULL;
    memset(arena, 0xa5, sizeof(arena));
    memset(in, 0x41, sizeof(in));
    memset(large, 0x42, sizeof(large));
    memset(key, 0x11, sizeof(key));
    {body}
    int canary_corrupted = 0;
    for (int i = 0; i < 16; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    for (int i = 48; i < 80; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    printf("ORACLE_EVENT family=memory_length_boundary\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT expected_behavior=memory_safety_watch\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual);
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=%d\\n", canary_corrupted);
    printf("ORACLE_EVENT contract_boundary=0\\n");
    printf("ORACLE_EVENT candidate_label=%s\\n", canary_corrupted ? "memory_safety_candidate" : "no_candidate");
    return 0;
}}
"""


def buffer_canary_case_source(case_id: str, strategy: str) -> str:
    bodies = {
        "bn_exact": "bn = BN_new(); BN_hex2bn(&bn, \"01020304\"); ret = BN_bn2binpad(bn, payload, 4); actual = ret >= 0 ? \"success\" : \"error\"; BN_free(bn);",
        "bn_one_short": "bn = BN_new(); BN_hex2bn(&bn, \"01020304\"); ret = BN_bn2binpad(bn, payload, 3); actual = ret >= 0 ? \"success\" : \"error\"; BN_free(bn);",
        "bn_zero_output": "bn = BN_new(); BN_hex2bn(&bn, \"01\"); ret = BN_bn2binpad(bn, payload, 0); actual = ret >= 0 ? \"success\" : \"error\"; BN_free(bn);",
        "bn_negative": "bn = BN_new(); BN_set_word(bn, 7); BN_set_negative(bn, 1); ret = BN_bn2binpad(bn, payload, 4); actual = ret >= 0 ? \"success\" : \"error\"; BN_free(bn);",
        "bn_large": "bn = BN_new(); BN_hex2bn(&bn, \"ffffffffffffffffffffffffffffffff\"); ret = BN_bn2binpad(bn, payload, 8); actual = ret >= 0 ? \"success\" : \"error\"; BN_free(bn);",
        "encode_exact_formula": "ret = EVP_EncodeBlock(payload, in, 6); actual = ret >= 0 ? \"success\" : \"error\";",
        "encode_one_short": "ret = EVP_EncodeBlock(payload, in, 12); actual = ret >= 0 ? \"success\" : \"error\";",
        "decode_malformed": "ret = EVP_DecodeBlock(payload, bad64, 8); actual = ret >= 0 ? \"success\" : \"error\";",
        "decode_short_output": "ret = EVP_DecodeBlock(payload, b64, 16); actual = ret >= 0 ? \"success\" : \"error\";",
        "encrypt_gcm_short": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_EncryptInit_ex(cipher, EVP_aes_128_gcm(), NULL, NULL, NULL); if (ret == 1) ret = EVP_EncryptInit_ex(cipher, NULL, NULL, key, iv); if (ret == 1) ret = EVP_EncryptUpdate(cipher, payload, &outl, in, 16); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "decrypt_gcm_short": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_DecryptInit_ex(cipher, EVP_aes_128_gcm(), NULL, NULL, NULL); if (ret == 1) ret = EVP_DecryptInit_ex(cipher, NULL, NULL, key, iv); if (ret == 1) ret = EVP_DecryptUpdate(cipher, payload, &outl, in, 16); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "digest_final_short": "md = EVP_MD_CTX_new(); ret = EVP_DigestInit_ex(md, EVP_sha256(), NULL); if (ret == 1) ret = EVP_DigestUpdate(md, in, 16); if (ret == 1) ret = EVP_DigestFinal_ex(md, payload, &md_len); actual = ret == 1 ? \"success\" : \"error\"; EVP_MD_CTX_free(md);",
        "mac_final_small": "mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); macctx = EVP_MAC_CTX_new(mac); params[0] = OSSL_PARAM_construct_utf8_string(\"digest\", \"SHA256\", 0); params[1] = OSSL_PARAM_construct_end(); ret = EVP_MAC_init(macctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(macctx, in, 16); if (ret == 1) ret = EVP_MAC_final(macctx, payload, &mac_len, 8); actual = ret == 1 ? \"success\" : \"error\"; EVP_MAC_CTX_free(macctx); EVP_MAC_free(mac);",
        "rand_zero_length": "ret = RAND_bytes(payload, 0); actual = ret == 1 ? \"success\" : \"error\";",
        "rand_small_buffer": "ret = RAND_bytes(payload, 8); actual = ret == 1 ? \"success\" : \"error\";",
        "rand_null_disabled": "actual = \"disabled\"; ret = 0;",
        "repeated_writes_same": "for (int i = 0; i < 8; i++) ret = EVP_EncodeBlock(payload, in, 3 + (i % 3)); actual = ret >= 0 ? \"success\" : \"error\";",
        "alternating_sizes": "for (int i = 0; i < 8; i++) ret = EVP_EncodeBlock(payload, in, i + 1); actual = ret >= 0 ? \"success\" : \"error\";",
        "randomized_sizes": "for (int i = 0; i < 12; i++) ret = EVP_EncodeBlock(payload, in, (i * 5) % 16); actual = ret >= 0 ? \"success\" : \"error\";",
    }
    generated_len = (sum(ord(ch) for ch in strategy) % 16) + 1
    body = bodies.get(strategy, f"ret = EVP_EncodeBlock(payload, in, {generated_len}); actual = ret >= 0 ? \"success\" : \"error\";")
    return f"""#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
int main(void) {{
    unsigned char arena[96];
    unsigned char *payload = arena + 16;
    unsigned char in[64];
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char b64[] = "QUJDREVGR0g=";
    unsigned char bad64[] = "!!!!====";
    const char *actual = "error";
    int ret = 0, outl = 0;
    unsigned int md_len = 0;
    size_t mac_len = 0;
    BIGNUM *bn = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    EVP_MD_CTX *md = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *macctx = NULL;
    OSSL_PARAM params[2];
    memset(arena, 0xa5, sizeof(arena));
    memset(in, 0x33, sizeof(in));
    memset(key, 0x44, sizeof(key));
    memset(iv, 0x55, sizeof(iv));
    {body}
    int canary_corrupted = 0;
    for (int i = 0; i < 16; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    for (int i = 32; i < 48; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    printf("ORACLE_EVENT family=buffer_canary_boundary\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT expected_behavior=memory_safety_watch\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual);
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=%d\\n", canary_corrupted);
    printf("ORACLE_EVENT contract_boundary=0\\n");
    printf("ORACLE_EVENT candidate_label=%s\\n", canary_corrupted ? "memory_safety_candidate" : "no_candidate");
    return 0;
}}
"""


def null_deref_case_source(case_id: str, strategy: str) -> str:
    bodies = {
        "null_md_ctx_update": "ret = EVP_DigestUpdate(NULL, in, 4); actual = ret == 1 ? \"success\" : \"error\";",
        "null_md_ctx_final": "ret = EVP_DigestFinal_ex(NULL, out, &outl_u); actual = ret == 1 ? \"success\" : \"error\";",
        "null_algorithm_init": "md = EVP_MD_CTX_new(); ret = EVP_DigestInit_ex(md, NULL, NULL); actual = ret == 1 ? \"success\" : \"error\"; EVP_MD_CTX_free(md);",
        "null_output_zero_len": "ret = EVP_EncodeBlock(NULL, in, 0); actual = ret >= 0 ? \"success\" : \"error\";",
        "null_output_nonzero_len": "ret = EVP_EncodeBlock(NULL, in, 4); actual = ret >= 0 ? \"success\" : \"error\";",
        "null_input_zero_len": "ret = EVP_EncodeBlock(out, NULL, 0); actual = ret >= 0 ? \"success\" : \"error\";",
        "null_input_nonzero_len": "ret = EVP_EncodeBlock(out, NULL, 4); actual = ret >= 0 ? \"success\" : \"error\";",
        "null_cipher_ctx_update": "ret = EVP_EncryptUpdate(NULL, out, &outl_i, in, 16); actual = ret == 1 ? \"success\" : \"error\";",
        "null_cipher_algorithm": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_EncryptInit_ex(cipher, NULL, NULL, key, NULL); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "null_mac_ctx_init": "ret = EVP_MAC_init(NULL, key, 16, NULL); actual = ret == 1 ? \"success\" : \"error\";",
        "null_mac_update": "ret = EVP_MAC_update(NULL, in, 4); actual = ret == 1 ? \"success\" : \"error\";",
        "null_mac_final": "ret = EVP_MAC_final(NULL, out, &mac_len, sizeof(out)); actual = ret == 1 ? \"success\" : \"error\";",
        "null_bn_bin2bn_zero": "bn = BN_bin2bn(NULL, 0, NULL); actual = bn != NULL ? \"success\" : \"error\"; BN_free(bn);",
        "null_bn_bin2bn_nonzero": "bn = BN_bin2bn(NULL, 4, NULL); actual = bn != NULL ? \"success\" : \"error\"; BN_free(bn);",
        "null_bn_bn2binpad": "ret = BN_bn2binpad(NULL, out, 4); actual = ret >= 0 ? \"success\" : \"error\";",
        "null_store_open_path": "store = OSSL_STORE_open(NULL, NULL, NULL, NULL, NULL); actual = store != NULL ? \"success\" : \"error\"; OSSL_STORE_close(store);",
        "null_store_close": "ret = OSSL_STORE_close(NULL); actual = ret == 1 ? \"success\" : \"error\";",
        "failed_init_then_update": "md = EVP_MD_CTX_new(); ret = EVP_DigestInit_ex(md, NULL, NULL); ret = EVP_DigestUpdate(md, in, 4); actual = ret == 1 ? \"success\" : \"error\"; EVP_MD_CTX_free(md);",
        "partial_cipher_ctx": "cipher = EVP_CIPHER_CTX_new(); ret = EVP_EncryptUpdate(cipher, out, &outl_i, in, 16); actual = ret == 1 ? \"success\" : \"error\"; EVP_CIPHER_CTX_free(cipher);",
        "pkey_keygen_before_init": "pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); ret = EVP_PKEY_keygen(pctx, &pkey); actual = ret == 1 ? \"success\" : \"error\"; EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(pctx);",
        "pkey_keygen_null_output": "pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); if (pctx != NULL) ret = EVP_PKEY_keygen_init(pctx); if (ret == 1) ret = EVP_PKEY_keygen(pctx, NULL); actual = ret == 1 ? \"success\" : \"error\"; EVP_PKEY_CTX_free(pctx);",
        "pkey_keygen_init_null_ctx": "ret = EVP_PKEY_keygen_init(NULL); actual = ret == 1 ? \"success\" : \"error\";",
        "pkey_ctx_invalid_id": "pctx = EVP_PKEY_CTX_new_id(-1, NULL); actual = pctx != NULL ? \"success\" : \"error\"; EVP_PKEY_CTX_free(pctx);",
        "bio_new_null_zero": "bio = BIO_new_mem_buf(NULL, 0); actual = bio != NULL ? \"success\" : \"error\"; BIO_free(bio);",
        "bio_new_null_nonzero": "bio = BIO_new_mem_buf(NULL, 4); actual = bio != NULL ? \"success\" : \"error\"; BIO_free(bio);",
        "bio_read_null_bio": "ret = BIO_read(NULL, out, 4); actual = ret > 0 ? \"success\" : \"error\";",
        "bio_write_null_bio": "ret = BIO_write(NULL, in, 4); actual = ret > 0 ? \"success\" : \"error\";",
        "bio_read_null_out_zero": "bio = BIO_new_mem_buf(in, 4); ret = BIO_read(bio, NULL, 0); actual = ret >= 0 ? \"success\" : \"error\"; BIO_free(bio);",
        "bio_read_null_out_nonzero": "bio = BIO_new_mem_buf(in, 4); ret = BIO_read(bio, NULL, 4); actual = ret > 0 ? \"success\" : \"error\"; BIO_free(bio);",
        "store_load_null_ctx": "void *loaded = OSSL_STORE_load(NULL); actual = loaded != NULL ? \"success\" : \"error\";",
        "store_eof_null_ctx": "ret = OSSL_STORE_eof(NULL); actual = ret == 1 ? \"success\" : \"error\";",
        "store_error_null_ctx": "ret = OSSL_STORE_error(NULL); actual = ret == 1 ? \"success\" : \"error\";",
        "freed_ctx_disabled": "actual = \"disabled\"; ret = 0;",
        "double_free_disabled": "actual = \"disabled\"; ret = 0;",
        "use_after_close_disabled": "actual = \"disabled\"; ret = 0;",
    }
    body = bodies.get(strategy, "actual = \"disabled\"; ret = 0;")
    return f"""#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/store.h>
int main(void) {{
    unsigned char in[32];
    unsigned char out[64];
    unsigned char key[16];
    const char *actual = "error";
    int ret = 0, outl_i = 0;
    unsigned int outl_u = 0;
    size_t mac_len = 0;
    BIGNUM *bn = NULL;
    BIO *bio = NULL;
    EVP_MD_CTX *md = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_STORE_CTX *store = NULL;
    memset(in, 0x66, sizeof(in));
    memset(out, 0, sizeof(out));
    memset(key, 0x77, sizeof(key));
    {body}
    printf("ORACLE_EVENT family=null_deref_dispatch\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual);
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=0\\n");
    printf("ORACLE_EVENT contract_boundary=0\\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\\n");
    return 0;
}}
"""


def valid_event_source(family: str, case_id: str, trigger_api: str, body: str, extra_includes: str = "") -> str:
    return f"""#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
{extra_includes}
int main(void) {{
    unsigned char arena[1024];
    unsigned char *out = arena + 64;
    unsigned char in[512];
    unsigned char key[32];
    char text[256];
    const char *actual = "error";
    const char *label = "no_candidate";
    const char *expected = "success_or_no_crash";
    const char *api = "{trigger_api}";
    int ret = 0;
    int outl = 0;
    int tmplen = 0;
    int contract_valid = 1;
    int canary_corrupted = 0;
    size_t outlen = 0;
    EVP_ENCODE_CTX *ectx = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    OSSL_PARAM params[2];
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    memset(arena, 0xa5, sizeof(arena));
    memset(in, 0x41, sizeof(in));
    memset(key, 0x33, sizeof(key));
    strcpy(text, "QUJDREVGR0g=");
    {body}
    for (int i = 0; i < 64; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    for (int i = 576; i < 640; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    if (contract_valid && canary_corrupted) label = "memory_safety_candidate";
    printf("ORACLE_EVENT family={family}\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT trigger_api=%s\\n", api);
    printf("ORACLE_EVENT contract_valid=%d\\n", contract_valid);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual);
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=%d\\n", canary_corrupted);
    printf("ORACLE_EVENT candidate_label=%s\\n", label);
    EVP_ENCODE_CTX_free(ectx);
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    BIO_free(bio);
    return 0;
}}
"""


def valid_decode_case_source(case_id: str, strategy: str) -> str:
    bodies = {
        "decodeblock_valid_exact": "unsigned char b64[] = \"QUJDREVGR0g=\"; ret = EVP_DecodeBlock(out, b64, 12); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeblock_valid_larger": "unsigned char b64[] = \"QUJDREVGR0g=\"; ret = EVP_DecodeBlock(out, b64, 12); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeblock_malformed_sufficient": "unsigned char b64[] = \"QUJD!!!!R0g=\"; expected = \"reject_or_no_crash\"; ret = EVP_DecodeBlock(out, b64, 12); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeblock_padding_edge": "unsigned char b64[] = \"QQ======\"; expected = \"reject_or_no_crash\"; ret = EVP_DecodeBlock(out, b64, 8); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeblock_newline_whitespace": "unsigned char b64[] = \"QUJD\\nREVG\\r\\nR0g=\"; ret = EVP_DecodeBlock(out, b64, sizeof(b64) - 1); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeblock_all_alphabet": "unsigned char b64[] = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\"; ret = EVP_DecodeBlock(out, b64, 64); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeblock_invalid_middle": "unsigned char b64[] = \"QUJD@EVGR0g=\"; expected = \"reject_or_no_crash\"; ret = EVP_DecodeBlock(out, b64, 12); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeblock_mod4_variant": "unsigned char b64[] = \"QUJDREV\"; expected = \"reject_or_no_crash\"; ret = EVP_DecodeBlock(out, b64, 7); actual = ret >= 0 ? \"success\" : \"error\";",
        "encodeblock_exact": "ret = EVP_EncodeBlock(out, in, 12); actual = ret >= 0 ? \"success\" : \"error\";",
        "encodeblock_larger": "ret = EVP_EncodeBlock(out, in, 24); actual = ret >= 0 ? \"success\" : \"error\";",
        "encodeblock_zero_nonnull": "ret = EVP_EncodeBlock(out, in, 0); actual = ret >= 0 ? \"success\" : \"error\";",
        "encodeblock_large_bounded": "ret = EVP_EncodeBlock(out, in, 192); actual = ret >= 0 ? \"success\" : \"error\";",
        "decodeupdate_stream_valid": "unsigned char b64[] = \"QUJDREVGR0g=\\n\"; ectx = EVP_ENCODE_CTX_new(); EVP_DecodeInit(ectx); ret = EVP_DecodeUpdate(ectx, out, &outl, b64, sizeof(b64)-1); if (ret >= 0) ret = EVP_DecodeFinal(ectx, out + outl, &tmplen); actual = ret >= 0 ? \"success\" : \"error\"; api = \"EVP_DecodeUpdate\";",
        "decodeupdate_stream_malformed": "unsigned char b64[] = \"QUJD!!!!\\n\"; expected = \"reject_or_no_crash\"; ectx = EVP_ENCODE_CTX_new(); EVP_DecodeInit(ectx); ret = EVP_DecodeUpdate(ectx, out, &outl, b64, sizeof(b64)-1); actual = ret >= 0 ? \"success\" : \"error\"; api = \"EVP_DecodeUpdate\";",
        "decodefinal_after_malformed": "unsigned char b64[] = \"!!!!\\n\"; expected = \"reject_or_no_crash\"; ectx = EVP_ENCODE_CTX_new(); EVP_DecodeInit(ectx); ret = EVP_DecodeUpdate(ectx, out, &outl, b64, sizeof(b64)-1); ret = EVP_DecodeFinal(ectx, out + (outl > 0 ? outl : 0), &tmplen); actual = ret >= 0 ? \"success\" : \"error\"; api = \"EVP_DecodeFinal\";",
        "decodefinal_without_update": "ectx = EVP_ENCODE_CTX_new(); EVP_DecodeInit(ectx); ret = EVP_DecodeFinal(ectx, out, &tmplen); actual = ret >= 0 ? \"success\" : \"error\"; api = \"EVP_DecodeFinal\";",
        "decodeupdate_newline_boundaries": "unsigned char b64[] = \"QUJD\\nREVG\\n\"; ectx = EVP_ENCODE_CTX_new(); EVP_DecodeInit(ectx); ret = EVP_DecodeUpdate(ectx, out, &outl, b64, sizeof(b64)-1); actual = ret >= 0 ? \"success\" : \"error\"; api = \"EVP_DecodeUpdate\";",
        "decodeupdate_repeated_small": "unsigned char b64[] = \"QUJDREVGR0g=\\n\"; ectx = EVP_ENCODE_CTX_new(); EVP_DecodeInit(ectx); for (int i = 0; i < 12 && ret >= 0; i += 4) ret = EVP_DecodeUpdate(ectx, out + outl, &tmplen, b64 + i, 4); actual = ret >= 0 ? \"success\" : \"error\"; api = \"EVP_DecodeUpdate\";",
        "encodeupdate_stream_valid": "ectx = EVP_ENCODE_CTX_new(); EVP_EncodeInit(ectx); EVP_EncodeUpdate(ectx, out, &outl, in, 48); EVP_EncodeFinal(ectx, out + outl, &tmplen); actual = \"success\"; api = \"EVP_EncodeUpdate\";",
        "encodefinal_after_update": "ectx = EVP_ENCODE_CTX_new(); EVP_EncodeInit(ectx); EVP_EncodeUpdate(ectx, out, &outl, in, 16); EVP_EncodeFinal(ectx, out + outl, &tmplen); actual = \"success\"; api = \"EVP_EncodeFinal\";",
        "encodefinal_without_update": "ectx = EVP_ENCODE_CTX_new(); EVP_EncodeInit(ectx); EVP_EncodeFinal(ectx, out, &tmplen); actual = \"success\"; api = \"EVP_EncodeFinal\";",
        "encodeupdate_repeated_small": "ectx = EVP_ENCODE_CTX_new(); EVP_EncodeInit(ectx); for (int i = 0; i < 8; i++) EVP_EncodeUpdate(ectx, out + outl, &tmplen, in + i * 3, 3); EVP_EncodeFinal(ectx, out + outl, &tmplen); actual = \"success\"; api = \"EVP_EncodeUpdate\";",
    }
    if strategy.startswith("generated_decode_variant_"):
        n = (sum(ord(c) for c in strategy) % 64) + 4
        body = f"ret = EVP_EncodeBlock(out, in, {n}); actual = ret >= 0 ? \"success\" : \"error\"; api = \"EVP_EncodeBlock\";"
    else:
        body = bodies[strategy]
    return valid_event_source("valid_decode_boundary", case_id, "EVP_DecodeBlock", body)


def valid_mac_case_source(case_id: str, strategy: str) -> str:
    common_params = "params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, \"SHA256\", 0); params[1] = OSSL_PARAM_construct_end();"
    bodies = {
        "hmac_sha256_control": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 32); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 64); actual = ret == 1 ? \"success\" : \"error\";",
        "null_key_zero_keylen": f"{common_params} expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, NULL, 0, params); actual = ret == 1 ? \"success\" : \"error\";",
        "nonnull_key_zero_keylen": f"{common_params} expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 0, params); actual = ret == 1 ? \"success\" : \"error\";",
        "normal_key_data": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); ret = ret == 1 ? EVP_MAC_update(mctx, in, 48) : ret; ret = ret == 1 ? EVP_MAC_final(mctx, out, &outlen, 64) : ret; actual = ret == 1 ? \"success\" : \"error\";",
        "null_data_zero": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, NULL, 0); actual = ret == 1 ? \"success\" : \"error\";",
        "nonnull_data_zero": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 0); actual = ret == 1 ? \"success\" : \"error\";",
        "bounded_large_data": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 256); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 64); actual = ret == 1 ? \"success\" : \"error\";",
        "update_before_init": f"{common_params} expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_update(mctx, in, 16); actual = ret == 1 ? \"success\" : \"error\";",
        "final_before_update": f"{common_params} expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 64); actual = ret == 1 ? \"success\" : \"error\";",
        "final_repeated": f"{common_params} expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 16); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 64); ret = EVP_MAC_final(mctx, out, &outlen, 64); actual = ret == 1 ? \"success\" : \"error\";",
        "final_outsize_exact": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 16); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 32); actual = ret == 1 ? \"success\" : \"error\";",
        "final_outsize_larger": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 16); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 64); actual = ret == 1 ? \"success\" : \"error\";",
        "final_outsize_zero_nonnull": f"{common_params} expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 0); actual = ret == 1 ? \"success\" : \"error\";",
        "final_null_output_zero": f"{common_params} expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_final(mctx, NULL, &outlen, 0); actual = ret == 1 ? \"success\" : \"error\";",
        "final_outlen_valid": f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 16); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, sizeof(arena) - 64); actual = ret == 1 ? \"success\" : \"error\";",
        "cmac_fetch_init": "params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, \"AES-128-CBC\", 0); params[1] = OSSL_PARAM_construct_end(); expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"CMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); if (mctx != NULL) ret = EVP_MAC_init(mctx, key, 16, params); actual = ret == 1 ? \"success\" : \"error\";",
        "gmac_fetch_init": "params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, \"AES-128-GCM\", 0); params[1] = OSSL_PARAM_construct_end(); expected = \"reject_or_no_crash\"; mac = EVP_MAC_fetch(NULL, \"GMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); if (mctx != NULL) ret = EVP_MAC_init(mctx, key, 16, params); actual = ret == 1 ? \"success\" : \"error\";",
        "fetch_nonexistent": "expected = \"reject_or_no_crash\"; api = \"EVP_MAC_fetch\"; mac = EVP_MAC_fetch(NULL, \"NO_SUCH_MAC\", NULL); actual = mac != NULL ? \"success\" : \"error\";",
        "fetch_null_name_observation": "expected = \"reject_or_no_crash\"; api = \"EVP_MAC_fetch\"; contract_valid = 0; label = \"contract_boundary_observation\"; mac = EVP_MAC_fetch(NULL, NULL, NULL); actual = mac != NULL ? \"success\" : \"error\";",
    }
    if strategy.startswith("generated_mac_variant_"):
        body = f"{common_params} mac = EVP_MAC_fetch(NULL, \"HMAC\", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, {(sum(ord(c) for c in strategy) % 128)}); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 64); actual = ret == 1 ? \"success\" : \"error\";"
    else:
        body = bodies[strategy]
    return valid_event_source("valid_evp_mac_boundary", case_id, "EVP_MAC_init", body)


def valid_bio_case_source(case_id: str, strategy: str) -> str:
    bodies = {
        "mem_buf_exact": "bio = BIO_new_mem_buf(in, 32); actual = bio != NULL ? \"success\" : \"error\"; api = \"BIO_new_mem_buf\";",
        "mem_buf_zero_nonnull": "bio = BIO_new_mem_buf(in, 0); actual = bio != NULL ? \"success\" : \"error\"; api = \"BIO_new_mem_buf\";",
        "mem_buf_len_minus_one": "strcpy(text, \"hello valid bio\"); bio = BIO_new_mem_buf(text, -1); actual = bio != NULL ? \"success\" : \"error\"; api = \"BIO_new_mem_buf\";",
        "read_exact_output": "bio = BIO_new_mem_buf(in, 32); ret = BIO_read(bio, out, 32); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_read\";",
        "read_smaller": "bio = BIO_new_mem_buf(in, 32); ret = BIO_read(bio, out, 8); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_read\";",
        "read_larger": "bio = BIO_new_mem_buf(in, 32); ret = BIO_read(bio, out, 128); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_read\";",
        "read_zero": "bio = BIO_new_mem_buf(in, 32); ret = BIO_read(bio, out, 0); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_read\";",
        "write_exact": "bio = BIO_new(BIO_s_mem()); ret = BIO_write(bio, in, 32); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_write\";",
        "write_zero": "bio = BIO_new(BIO_s_mem()); ret = BIO_write(bio, in, 0); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_write\";",
        "write_repeated": "bio = BIO_new(BIO_s_mem()); for (int i = 0; i < 8; i++) ret = BIO_write(bio, in + i, 4); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_write\";",
        "get_mem_data_after_writes": "bio = BIO_new(BIO_s_mem()); BIO_write(bio, in, 16); ret = (int)BIO_get_mem_data(bio, &bptr); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_get_mem_data\";",
        "get_mem_data_empty": "bio = BIO_new(BIO_s_mem()); ret = (int)BIO_get_mem_data(bio, &bptr); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_get_mem_data\";",
        "read_after_eof": "bio = BIO_new_mem_buf(in, 4); BIO_read(bio, out, 4); ret = BIO_read(bio, out, 4); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_read\"; expected = \"reject_or_no_crash\";",
        "write_after_read": "bio = BIO_new(BIO_s_mem()); BIO_write(bio, in, 16); BIO_read(bio, out, 8); ret = BIO_write(bio, in, 4); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_write\";",
        "alternating_read_write": "bio = BIO_new(BIO_s_mem()); for (int i = 0; i < 4; i++) { BIO_write(bio, in + i, 8); BIO_read(bio, out + i, 4); } actual = \"success\"; api = \"BIO_write\";",
    }
    if strategy.startswith("generated_bio_variant_"):
        n = (sum(ord(c) for c in strategy) % 64) + 1
        body = f"bio = BIO_new(BIO_s_mem()); ret = BIO_write(bio, in, {n}); if (ret >= 0) ret = BIO_read(bio, out, {n}); actual = ret >= 0 ? \"success\" : \"error\"; api = \"BIO_write\";"
    else:
        body = bodies[strategy]
    return valid_event_source("valid_bio_boundary", case_id, "BIO_new_mem_buf", body)


def structured_blob(seed: int, family: str) -> bytes:
    patterns = [
        b"\x30\x10\x02\x01\x01",
        b"\x30\x81\x80\x02\x01\x01",
        b"\x30\x84\x7f\xff\xff\xff\x05\x00",
        b"\x24\x80\x04\x01A",
        b"\x1f\xff\xff\x7f\x01\x00",
        b"\x03\x02\x08\x00",
        b"\x06\x05\x2a\x86\x48",
        b"\x02\x00",
        b"\x02\x02\x00\x80",
        b"\x31\x0a\x30\x08\x31\x06\x30\x04\x05\x00",
        b"\x30\x20\xa0\x1e\x30\x1c\x04\x82\x01\x00abc",
        b"\x30\x0c\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01",
    ]
    base = patterns[seed % len(patterns)]
    if seed % 7 == 0:
        base = b"\x30\x10" * (16 + (seed % 4) * 16) + b"\x05\x00"
    elif seed % 7 == 1:
        base = b"\x31\x80" * (8 + seed % 8) + b"\x04\x01A"
    elif seed % 7 == 2:
        base = b"\x30\x82\x10\x00" + bytes([(seed * 17) & 0xff, 0x02, 0x01])
    elif seed % 7 == 3:
        base = bytes([0x30, 0x0a, 0xa0, 0x08, 0x30, (seed * 3) & 0x7f, 0x02, 0x01, seed & 0xff])
    if family.startswith("x509"):
        return b"\x30" + bytes([min(len(base) + 2, 126)]) + b"\x30" + bytes([min(len(base), 124)]) + base
    if family.startswith("pkcs"):
        return b"\x30" + bytes([min(len(base) + 4, 126)]) + b"\x06\x02\x2a\x03" + base[:120]
    return base[:240]


def structured_c_array(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data) if data else "0"


def structured_parser_case_source(family: str, case_id: str, api: str, data: bytes) -> str:
    type_decl = "void *obj = NULL;"
    call = "obj = d2i_ASN1_TYPE(NULL, &p, len); ASN1_TYPE_free((ASN1_TYPE *)obj);"
    includes = "#include <openssl/asn1.h>\n#include <openssl/x509.h>\n#include <openssl/pkcs7.h>\n#include <openssl/cms.h>"
    if api == "d2i_ASN1_SEQUENCE_ANY":
        type_decl = "STACK_OF(ASN1_TYPE) *obj = NULL;"
        call = "obj = d2i_ASN1_SEQUENCE_ANY(NULL, &p, len); sk_ASN1_TYPE_pop_free(obj, ASN1_TYPE_free);"
    elif api == "d2i_ASN1_OCTET_STRING":
        type_decl = "ASN1_OCTET_STRING *obj = NULL;"
        call = "obj = d2i_ASN1_OCTET_STRING(NULL, &p, len); ASN1_OCTET_STRING_free(obj);"
    elif api == "d2i_ASN1_INTEGER":
        type_decl = "ASN1_INTEGER *obj = NULL;"
        call = "obj = d2i_ASN1_INTEGER(NULL, &p, len); ASN1_INTEGER_free(obj);"
    elif api == "ASN1_item_d2i":
        type_decl = "ASN1_TYPE *obj = NULL;"
        call = "obj = (ASN1_TYPE *)ASN1_item_d2i(NULL, &p, len, ASN1_ITEM_rptr(ASN1_ANY)); ASN1_TYPE_free(obj);"
    elif api == "d2i_X509":
        type_decl = "X509 *obj = NULL;"
        call = "obj = d2i_X509(NULL, &p, len); X509_free(obj);"
    elif api == "d2i_X509_REQ":
        type_decl = "X509_REQ *obj = NULL;"
        call = "obj = d2i_X509_REQ(NULL, &p, len); X509_REQ_free(obj);"
    elif api == "d2i_X509_CRL":
        type_decl = "X509_CRL *obj = NULL;"
        call = "obj = d2i_X509_CRL(NULL, &p, len); X509_CRL_free(obj);"
    elif api == "d2i_PKCS7":
        type_decl = "PKCS7 *obj = NULL;"
        call = "obj = d2i_PKCS7(NULL, &p, len); PKCS7_free(obj);"
    elif api == "d2i_CMS_ContentInfo":
        type_decl = "CMS_ContentInfo *obj = NULL;"
        call = "obj = d2i_CMS_ContentInfo(NULL, &p, len); CMS_ContentInfo_free(obj);"
    elif api == "d2i_PKCS8_PRIV_KEY_INFO":
        type_decl = "PKCS8_PRIV_KEY_INFO *obj = NULL;"
        call = "obj = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len); PKCS8_PRIV_KEY_INFO_free(obj);"
    elif api == "d2i_X509_SIG":
        type_decl = "X509_SIG *obj = NULL;"
        call = "obj = d2i_X509_SIG(NULL, &p, len); X509_SIG_free(obj);"
    return f"""#include <stdio.h>
{includes}
int main(void) {{
    const unsigned char der[] = {{{structured_c_array(data)}}};
    const unsigned char *p = der;
    long len = {len(data)};
    {type_decl}
    {call}
    printf("ORACLE_EVENT family={family}\\n");
    printf("ORACLE_EVENT case_id={case_id}\\n");
    printf("ORACLE_EVENT trigger_api={api}\\n");
    printf("ORACLE_EVENT input_class=malformed_only_structured\\n");
    printf("ORACLE_EVENT uses_trailing_garbage=0\\n");
    printf("ORACLE_EVENT uses_full_consumption_oracle=0\\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\\n");
    printf("ORACLE_EVENT actual_behavior=%s\\n", obj != NULL ? "success" : "error");
    printf("ORACLE_EVENT asan_observed=0\\n");
    printf("ORACLE_EVENT ubsan_observed=0\\n");
    printf("ORACLE_EVENT crash_signal=none\\n");
    printf("ORACLE_EVENT canary_corrupted=0\\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\\n");
    return 0;
}}
"""


def cases_for_family(family: str, limit: int) -> list[dict[str, Any]]:
    data = byte_cases()
    if family == "asn1_nested_boundary_structured":
        apis = ["d2i_ASN1_TYPE", "d2i_ASN1_SEQUENCE_ANY", "d2i_ASN1_OCTET_STRING", "d2i_ASN1_INTEGER", "ASN1_item_d2i"]
        return [
            {
                "case_id": f"asn1_structured_{i:03d}",
                "family": family,
                "source": structured_parser_case_source(family, f"asn1_structured_{i:03d}", apis[i % len(apis)], structured_blob(i, family)),
            }
            for i in range(limit)
        ]
    if family == "x509_inner_boundary_structured":
        apis = ["d2i_X509", "d2i_X509_REQ", "d2i_X509_CRL"]
        return [
            {
                "case_id": f"x509_structured_{i:03d}",
                "family": family,
                "source": structured_parser_case_source(family, f"x509_structured_{i:03d}", apis[i % len(apis)], structured_blob(i, family)),
            }
            for i in range(limit)
        ]
    if family == "pkcs_container_inner_boundary_structured":
        apis = ["d2i_PKCS7", "d2i_CMS_ContentInfo", "d2i_PKCS8_PRIV_KEY_INFO", "d2i_X509_SIG"]
        return [
            {
                "case_id": f"pkcs_structured_{i:03d}",
                "family": family,
                "source": structured_parser_case_source(family, f"pkcs_structured_{i:03d}", apis[i % len(apis)], structured_blob(i, family)),
            }
            for i in range(limit)
        ]
    if family == "valid_decode_boundary":
        strategies = [
            "decodeblock_valid_exact", "decodeblock_valid_larger", "decodeblock_malformed_sufficient",
            "decodeblock_padding_edge", "decodeblock_newline_whitespace", "decodeblock_all_alphabet",
            "decodeblock_invalid_middle", "decodeblock_mod4_variant", "encodeblock_exact",
            "encodeblock_larger", "encodeblock_zero_nonnull", "encodeblock_large_bounded",
            "decodeupdate_stream_valid", "decodeupdate_stream_malformed", "decodefinal_after_malformed",
            "decodefinal_without_update", "decodeupdate_newline_boundaries", "decodeupdate_repeated_small",
            "encodeupdate_stream_valid", "encodefinal_after_update", "encodefinal_without_update",
            "encodeupdate_repeated_small",
        ] + [f"generated_decode_variant_{i:02d}" for i in range(1, 16)]
        return [
            {"case_id": f"validdecode_{name}", "family": family, "source": valid_decode_case_source(f"validdecode_{name}", name)}
            for name in strategies[:limit]
        ]
    if family == "valid_evp_mac_boundary":
        strategies = [
            "hmac_sha256_control", "null_key_zero_keylen", "nonnull_key_zero_keylen",
            "normal_key_data", "null_data_zero", "nonnull_data_zero", "bounded_large_data",
            "update_before_init", "final_before_update", "final_repeated", "final_outsize_exact",
            "final_outsize_larger", "final_outsize_zero_nonnull", "final_null_output_zero",
            "final_outlen_valid", "cmac_fetch_init", "gmac_fetch_init", "fetch_nonexistent",
            "fetch_null_name_observation",
        ] + [f"generated_mac_variant_{i:02d}" for i in range(1, 16)]
        return [
            {"case_id": f"validmac_{name}", "family": family, "source": valid_mac_case_source(f"validmac_{name}", name)}
            for name in strategies[:limit]
        ]
    if family == "valid_bio_boundary":
        strategies = [
            "mem_buf_exact", "mem_buf_zero_nonnull", "mem_buf_len_minus_one", "read_exact_output",
            "read_smaller", "read_larger", "read_zero", "write_exact", "write_zero",
            "write_repeated", "get_mem_data_after_writes", "get_mem_data_empty",
            "read_after_eof", "write_after_read", "alternating_read_write",
        ] + [f"generated_bio_variant_{i:02d}" for i in range(1, 20)]
        return [
            {"case_id": f"validbio_{name}", "family": family, "source": valid_bio_case_source(f"validbio_{name}", name)}
            for name in strategies[:limit]
        ]
    if family == "asn1_nested_boundary":
        return [
            {"case_id": f"asn1_{name}", "family": family, "source": asn1_case_source(f"asn1_{name}", blob)}
            for name, blob in data[:limit]
        ]
    if family == "x509_asn1_inner_boundary":
        apis = ["d2i_X509", "d2i_X509_REQ", "d2i_X509_CRL"]
        return [
            {"case_id": f"x509_{name}", "family": family, "source": x509_case_source(f"x509_{name}", blob, apis[i % 3])}
            for i, (name, blob) in enumerate(data[:limit])
        ]
    if family == "ossl_store_decoder_boundary_deep":
        return [
            {"case_id": f"decoder_{name}", "family": family, "source": decoder_case_source(f"decoder_{name}", blob, "DER" if i % 2 else "PEM")}
            for i, (name, blob) in enumerate(data[:limit])
        ]
    if family == "memory_length_boundary":
        strategies = [
            "zero_length_input", "null_input_zero_length", "encode_exact_output",
            "decode_zero_size", "decode_malformed_short_output", "decode_padding_edge",
            "digest_null_input_zero", "hmac_null_key_zero", "hmac_null_data_zero", "hmac_null_output_disabled",
            "bn_bn2binpad_too_small_canary", "bn_bn2binpad_exact_canary", "bio_read_short_buffer",
            "bio_write_larger_len_disabled", "encrypt_update_short_output", "decrypt_update_short_output",
            "repeated_update_small_chunks", "update_len_zero_after_normal", "null_input_nonzero",
            "digest_null_input_nonzero", "overlapping_encode_observation",
            "max_bounded_len", "length_mismatch_actual_buffer", "output_len_pointer_null_disabled",
            "output_len_pointer_valid_short_buffer", "off_by_one_length", "off_by_many_length",
            "repeated_length_boundary_loop", "randomized_bounded_lengths", "canary_protected_output",
        ]
        return [
            {"case_id": f"memlen_{name}", "family": family, "source": memory_length_case_source(f"memlen_{name}", name)}
            for name in strategies[:limit]
        ]
    if family == "buffer_canary_boundary":
        strategies = [
            "bn_exact", "bn_one_short", "bn_zero_output", "bn_negative", "bn_large",
            "encode_exact_formula", "decode_malformed", "rand_zero_length", "rand_small_buffer",
            "rand_null_disabled", "repeated_writes_same", "alternating_sizes", "randomized_sizes",
        ] + [f"generated_size_boundary_variant_{i:02d}" for i in range(1, 18)] + [
            "encode_one_short", "decode_short_output", "encrypt_gcm_short", "decrypt_gcm_short",
            "digest_final_short", "mac_final_small",
        ] + [f"generated_size_boundary_variant_late_{i:02d}" for i in range(1, 8)]
        return [
            {"case_id": f"canary_{name}", "family": family, "source": buffer_canary_case_source(f"canary_{name}", name)}
            for name in strategies[:limit]
        ]
    if family == "null_deref_dispatch":
        strategies = [
            "null_algorithm_init", "null_input_zero_len", "null_bn_bin2bn_zero",
            "null_store_open_path", "pkey_ctx_invalid_id", "bio_new_null_zero",
            "freed_ctx_disabled", "double_free_disabled", "use_after_close_disabled",
            "failed_init_disabled", "partial_cipher_ctx_disabled", "null_mac_ctx_init_disabled",
        ] + [f"generated_null_matrix_{i:02d}" for i in range(1, 31)] + [
            "null_mac_ctx_init",
            "null_bn_bin2bn_zero", "null_store_close", "null_store_open_path",
            "failed_init_then_update", "partial_cipher_ctx", "pkey_ctx_invalid_id",
            "bio_new_null_zero", "store_eof_null_ctx", "store_error_null_ctx",
            "null_md_ctx_update", "null_md_ctx_final", "null_output_zero_len",
            "null_output_nonzero_len", "null_input_nonzero_len", "null_cipher_ctx_update",
            "null_cipher_algorithm", "null_mac_update", "null_mac_final",
            "null_bn_bin2bn_nonzero", "null_bn_bn2binpad", "pkey_keygen_before_init",
            "pkey_keygen_null_output", "pkey_keygen_init_null_ctx", "bio_new_null_nonzero",
            "bio_read_null_bio", "bio_write_null_bio", "bio_read_null_out_zero",
            "bio_read_null_out_nonzero", "store_load_null_ctx",
        ] + [f"generated_null_matrix_late_{i:02d}" for i in range(1, 11)]
        return [
            {"case_id": f"nullderef_{name}", "family": family, "source": null_deref_case_source(f"nullderef_{name}", name)}
            for name in strategies[:limit]
        ]
    strategies = [
        "zero_length_bin2bn", "null_input_zero_length", "large_bounded_binary", "leading_zeros_large",
        "bn2binpad_exact", "bn2binpad_small", "bn2binpad_zero", "negative_serialization",
        "negative_zero", "invalid_hex", "long_hex", "invalid_decimal", "long_decimal",
        "alternating_ff00", "all_ff", "all_00", "canary_bn2binpad", "length_consistency",
        "repeated_loop", "random_bounded",
    ]
    return [
        {"case_id": f"bn_{name}", "family": family, "source": bn_case_source(f"bn_{name}", name)}
        for name in strategies[:limit]
    ]


def command_for(harness: Path, binary: Path, openssl_install: Path) -> list[str]:
    lib_dir = lib_dir_for_install(openssl_install)
    return [
        "gcc", "-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
        f"-I{openssl_install / 'include'}", harness.as_posix(), f"-L{lib_dir}", f"-Wl,-rpath,{lib_dir}",
        "-lssl", "-lcrypto", "-ldl", "-pthread", "-o", binary.as_posix(),
    ]


def parse_oracle(stdout: str, case: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        if line.startswith("ORACLE_EVENT "):
            payload = line[len("ORACLE_EVENT ") :]
            if "=" in payload:
                k, v = payload.split("=", 1)
                values[k] = v
    label = values.get("candidate_label", "no_candidate")
    contract_valid = values.get("contract_valid", "1") != "0"
    if run.get("timeout"):
        label = "hang_candidate" if contract_valid else "contract_boundary_observation"
    elif run.get("sanitizer_observed"):
        if values.get("contract_boundary") == "1" or not contract_valid:
            label = "contract_boundary_observation"
        else:
            label = "sanitizer_candidate"
    elif run.get("signal") in {"SIGSEGV", "SIGABRT"}:
        label = "crash_candidate" if contract_valid else "contract_boundary_observation"
    elif values.get("canary_corrupted") == "1":
        label = "memory_safety_candidate" if contract_valid else "contract_boundary_observation"
    return {
        "schema": "memory_safety_oracle_event_v1",
        "family": case["family"],
        "case_id": case["case_id"],
        "trigger_api": values.get("trigger_api", ""),
        "contract_valid": contract_valid,
        "input_class": values.get("input_class", ""),
        "uses_trailing_garbage": values.get("uses_trailing_garbage") == "1",
        "uses_full_consumption_oracle": values.get("uses_full_consumption_oracle") == "1",
        "expected_behavior": values.get("expected_behavior", "reject_or_no_crash"),
        "actual_behavior": "timeout" if run.get("timeout") else ("crash" if run.get("signal") else values.get("actual_behavior", "error")),
        "asan_observed": "asan" in (run.get("sanitizer_kinds") or []),
        "ubsan_observed": "ubsan" in (run.get("sanitizer_kinds") or []),
        "crash_signal": run.get("signal") or "none",
        "canary_corrupted": values.get("canary_corrupted") == "1",
        "contract_boundary": values.get("contract_boundary") == "1",
        "candidate_label": label,
    }


def should_stop_on_event(event: dict[str, Any], stop_on_crash_or_sanitizer: bool) -> bool:
    if not stop_on_crash_or_sanitizer:
        return event["candidate_label"] != "no_candidate"
    return event["candidate_label"] in {"crash_candidate", "sanitizer_candidate", "hang_candidate"}


def compile_and_run_cases(cases: list[dict[str, Any]], family_root: Path, openssl_install: Path, timeout: int, stop_on_crash_or_sanitizer: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    compile_records = []
    run_records = []
    events = []
    for case in cases:
        path = family_root / "cases" / f"{case['case_id']}.c"
        write_text(path, case["source"])
    for case in cases:
        path = family_root / "cases" / f"{case['case_id']}.c"
        work = family_root / "work" / case["case_id"]
        binary = work / "case.bin"
        work.mkdir(parents=True, exist_ok=True)
        cmd = command_for(path, binary, openssl_install)
        proc = subprocess.run(cmd, text=True, capture_output=True)
        write_text(work / "compile.stdout.log", proc.stdout)
        write_text(work / "compile.stderr.log", proc.stderr)
        ok = proc.returncode == 0 and binary.exists()
        compile_records.append({"case_id": case["case_id"], "family": case["family"], "compile_status": "compile_success" if ok else "compile_failed", "return_code": proc.returncode, "harness_c": path.as_posix(), "binary_path": binary.as_posix(), "stderr_log": (work / "compile.stderr.log").as_posix()})
        if not ok:
            run = {"case_id": case["case_id"], "family": case["family"], "run_status": "not_run_compile_failed", "timeout": False, "signal": "", "sanitizer_observed": False, "sanitizer_kinds": []}
            run_records.append(run)
            continue
        try:
            start = time.monotonic()
            lib_dir = lib_dir_for_install(openssl_install)
            env = run_env(openssl_install, lib_dir)
            env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1"
            env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
            rp = subprocess.run([binary.as_posix()], text=True, capture_output=True, timeout=timeout, env=env)
            write_text(work / "run.stdout.log", rp.stdout)
            write_text(work / "run.stderr.log", rp.stderr)
            combined = rp.stdout + "\n" + rp.stderr
            sig = signal_name(rp.returncode)
            kinds = sanitizer_kinds(combined)
            keywords = matched_keywords(combined)
            run = {"case_id": case["case_id"], "family": case["family"], "run_status": "signaled" if sig else "exited", "exit_code": rp.returncode if rp.returncode >= 0 else None, "signal": sig, "timeout": False, "duration_seconds": round(time.monotonic() - start, 6), "sanitizer_observed": bool(kinds or keywords), "sanitizer_kinds": kinds, "matched_keywords": keywords, "stdout_log": (work / "run.stdout.log").as_posix(), "stderr_log": (work / "run.stderr.log").as_posix()}
        except subprocess.TimeoutExpired as exc:
            write_text(work / "run.stdout.log", exc.stdout or "")
            write_text(work / "run.stderr.log", (exc.stderr or "") + "\ntimeout\n")
            run = {"case_id": case["case_id"], "family": case["family"], "run_status": "timeout", "exit_code": None, "signal": "", "timeout": True, "sanitizer_observed": False, "sanitizer_kinds": [], "stdout_log": (work / "run.stdout.log").as_posix(), "stderr_log": (work / "run.stderr.log").as_posix()}
        run_records.append(run)
        stdout = Path(run.get("stdout_log", "")).read_text(encoding="utf-8", errors="replace") if run.get("stdout_log") else ""
        events.append(parse_oracle(stdout, case, run))
        if should_stop_on_event(events[-1], stop_on_crash_or_sanitizer):
            break
    return compile_records, run_records, events


def infer_track(family: str) -> str:
    if family.startswith("valid_"):
        return "valid_contract_memory"
    if "x509" in family or "asn1" in family or "decoder" in family:
        return "boundary"
    if "null" in family:
        return "null_dispatch"
    if "canary" in family:
        return "canary_boundary"
    if "length" in family:
        return "length_boundary"
    return "memory_boundary"


def infer_archetype(family: str) -> str:
    mapping = {
        "memory_length_boundary": "integer_or_length_boundary_issue",
        "buffer_canary_boundary": "caller_buffer_canary_corruption_watch",
        "null_deref_dispatch": "null_parameter_dispatch_crash_watch",
        "valid_decode_boundary": "valid_contract_encode_decode_boundary_watch",
        "valid_evp_mac_boundary": "valid_contract_mac_boundary_watch",
        "valid_bio_boundary": "valid_contract_bio_boundary_watch",
    }
    return mapping.get(family, family)


def detect_campaign_version(args: argparse.Namespace) -> str:
    if args.campaign_version:
        return args.campaign_version
    if TASK_STRUCTURED_PARSER in args.out_dir:
        return "structured_parser"
    if TASK_VALID_CONTRACT in args.out_dir:
        return "valid_contract"
    if TASK_DECODEBLOCK_NULL in args.out_dir:
        return "decodeblock_null"
    if TASK_FIX_CONTINUE in args.out_dir:
        return "fix_continue"
    if TASK_V2 in args.out_dir:
        return "v2"
    return "v1"


def promoted_candidates(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    labels = {"crash_candidate", "sanitizer_candidate", "memory_safety_candidate", "hang_candidate"}
    return [e for e in events if e.get("candidate_label") in labels]


def write_memory_length_oracle_fix_artifacts(repo_root: Path, out_dir: Path, triage_root: Path) -> dict[str, Any]:
    decision = load_yaml(triage_root / "candidate/triage_decision.yaml")
    oracle_adjustment = load_yaml(triage_root / "feedback_to_pipeline/oracle_adjustment_recommendation.yaml")
    mutation_adjustment = load_yaml(triage_root / "feedback_to_pipeline/mutation_rule_adjustment.yaml")
    loaded = bool(decision)
    applied = {
        "schema": "memory_length_oracle_adjustment_applied_v1",
        "source_triage": triage_root.as_posix(),
        "family": "memory_length_boundary",
        "trigger_api": "EVP_EncodeBlock",
        "case_id": "memlen_null_input_nonzero",
        "rule": "EVP_EncodeBlock(NULL, nonzero length) is contract_boundary_observation, not a promoted sanitizer_candidate.",
        "evp_encodeblock_null_nonzero_downgraded": decision.get("decision") == "downgrade_to_contract_observation",
        "candidate_blocking": False,
    }
    mutation_applied = {
        "schema": "memory_length_mutation_rule_adjustment_applied_v1",
        "source_triage": triage_root.as_posix(),
        "family": "memory_length_boundary",
        "rule": "NULL input with nonzero length defaults to invalid-contract observation unless API docs explicitly allow NULL input.",
        "null_zero_length_policy": "observation_no_candidate",
        "short_input_claimed_larger_length_policy": "sanitizer_candidate_needs_separate_triage_if_internal",
    }
    dump_yaml(out_dir / "memory_length_oracle_fix/triage_decision_snapshot.yaml", decision)
    dump_yaml(out_dir / "memory_length_oracle_fix/oracle_adjustment_applied.yaml", applied)
    dump_yaml(out_dir / "memory_length_oracle_fix/mutation_rule_adjustment_applied.yaml", mutation_applied)
    dump_yaml(repo_root / "knowledge/oracle_adjustments/memory_length_boundary.yaml", {
        "schema": "oracle_adjustment_v1",
        "family": "memory_length_boundary",
        "source_task": TASK_FIX_CONTINUE,
        "source_triage": triage_root.as_posix(),
        "adjustments": [applied, mutation_applied],
        "main_feedback_written": False,
        "pattern_bank_modified": False,
    })
    return {
        "previous_candidate_triage_loaded": loaded,
        "evp_encodeblock_null_nonzero_downgraded": applied["evp_encodeblock_null_nonzero_downgraded"],
        "memory_length_oracle_adjustment_applied": bool(oracle_adjustment) and applied["evp_encodeblock_null_nonzero_downgraded"],
        "memory_length_mutation_rule_adjustment_applied": bool(mutation_adjustment),
    }


def write_decodeblock_oracle_fix_artifacts(repo_root: Path, out_dir: Path, triage_root: Path) -> dict[str, Any]:
    decision = load_yaml(triage_root / "candidate/triage_decision.yaml")
    oracle_adjustment = load_yaml(triage_root / "feedback_to_pipeline/oracle_adjustment_recommendation.yaml")
    mutation_adjustment = load_yaml(triage_root / "feedback_to_pipeline/mutation_rule_adjustment.yaml")
    loaded = bool(decision)
    applied = {
        "schema": "decodeblock_oracle_adjustment_applied_v1",
        "source_triage": triage_root.as_posix(),
        "family": "buffer_canary_boundary",
        "trigger_api": "EVP_DecodeBlock",
        "case_id": decision.get("case_id", "canary_decode_short_output"),
        "rule": "EVP_DecodeBlock short-output and overclaimed-input-length cases are contract-boundary observations unless exact-size controls still show sanitizer/canary evidence.",
        "short_output_policy": "contract_boundary_observation",
        "input_len_mismatch_policy": "harness_fault_or_invalid_contract_observation",
        "exact_output_valid_input_policy": "control",
        "candidate_promotion_requires": [
            "output buffer capacity is sufficient for the decoded output",
            "input_len matches readable input bytes",
            "ASAN, UBSAN, crash, hang, or canary evidence remains after valid-contract controls",
        ],
        "evp_decodeblock_short_output_downgraded": decision.get("decision") == "downgrade_to_contract_observation" and bool(decision.get("short_output_only_failure")),
        "evp_decodeblock_input_len_mismatch_downgraded": bool(decision.get("harness_fault")),
        "candidate_blocking": False,
    }
    mutation_applied = {
        "schema": "decodeblock_mutation_rule_adjustment_applied_v1",
        "source_triage": triage_root.as_posix(),
        "family": "buffer_canary_boundary",
        "trigger_api": "EVP_DecodeBlock",
        "rule": "Generate EVP_DecodeBlock candidate-promotable mutations only when readable input length equals the API length argument and output capacity is sufficient.",
        "short_output_buffer_policy": "contract_boundary_observation",
        "overclaimed_input_len_policy": "harness_fault_or_invalid_contract_observation",
        "malformed_input_policy": "candidate_only_if_output_sufficient_and_memory_evidence_present",
    }
    dump_yaml(out_dir / "decodeblock_oracle_fix/triage_decision_snapshot.yaml", decision)
    dump_yaml(out_dir / "decodeblock_oracle_fix/oracle_adjustment_applied.yaml", applied)
    dump_yaml(out_dir / "decodeblock_oracle_fix/mutation_rule_adjustment_applied.yaml", mutation_applied)
    dump_yaml(repo_root / "knowledge/oracle_adjustments/evp_decodeblock_boundary.yaml", {
        "schema": "oracle_adjustment_v1",
        "family": "buffer_canary_boundary",
        "trigger_api": "EVP_DecodeBlock",
        "source_task": TASK_DECODEBLOCK_NULL,
        "source_triage": triage_root.as_posix(),
        "adjustments": [applied, mutation_applied],
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "confirmed_vulnerability_claim": False,
    })
    return {
        "previous_canary_triage_loaded": loaded,
        "evp_decodeblock_short_output_downgraded": applied["evp_decodeblock_short_output_downgraded"],
        "evp_decodeblock_input_len_mismatch_downgraded": applied["evp_decodeblock_input_len_mismatch_downgraded"],
        "decodeblock_oracle_adjustment_applied": bool(oracle_adjustment) and applied["evp_decodeblock_short_output_downgraded"],
        "decodeblock_mutation_rule_adjustment_applied": bool(mutation_adjustment),
    }


def write_valid_contract_closure_artifacts(repo_root: Path, out_dir: Path) -> dict[str, Any]:
    triages = {
        "memlen_null_input_nonzero": repo_root / "artifacts/triage/memlen_null_input_nonzero_triage_v1/candidate/triage_decision.yaml",
        "canary_decode_short_output": repo_root / "artifacts/triage/canary_decode_short_output_triage_v1/candidate/triage_decision.yaml",
        "nullderef_null_mac_ctx_init": repo_root / "artifacts/triage/nullderef_null_mac_ctx_init_triage_v1/candidate/triage_decision.yaml",
    }
    decisions = {name: load_yaml(path) for name, path in triages.items()}
    closed = [
        {
            "family": "memory_length_boundary",
            "case_id": "memlen_null_input_nonzero",
            "trigger_api": "EVP_EncodeBlock",
            "original_label": decisions["memlen_null_input_nonzero"].get("original_label", "sanitizer_candidate"),
            "decision": decisions["memlen_null_input_nonzero"].get("decision", "downgrade_to_contract_observation"),
            "reason": "NULL input with nonzero length is invalid API use.",
            "source_triage": triages["memlen_null_input_nonzero"].as_posix(),
        },
        {
            "family": "buffer_canary_boundary",
            "case_id": "canary_decode_short_output",
            "trigger_api": "EVP_DecodeBlock",
            "original_label": decisions["canary_decode_short_output"].get("original_label", "sanitizer_candidate"),
            "decision": decisions["canary_decode_short_output"].get("decision", "downgrade_to_contract_observation"),
            "reason": "Short output buffer and input_len mismatch are invalid contract / harness-fault observations.",
            "source_triage": triages["canary_decode_short_output"].as_posix(),
        },
        {
            "family": "null_deref_dispatch",
            "case_id": "nullderef_null_mac_ctx_init",
            "trigger_api": "EVP_MAC_init",
            "original_label": decisions["nullderef_null_mac_ctx_init"].get("original_label", "sanitizer_candidate"),
            "decision": decisions["nullderef_null_mac_ctx_init"].get("decision", "downgrade_to_contract_observation"),
            "reason": "EVP_MAC_init(NULL, ...) is outside the documented MAC context lifecycle.",
            "source_triage": triages["nullderef_null_mac_ctx_init"].as_posix(),
        },
    ]
    rules = {
        "schema": "memory_candidate_oracle_downgrade_rules_v1",
        "rules": [
            {"api": "EVP_EncodeBlock", "condition": "input == NULL && length > 0", "label": "contract_boundary_observation", "promote": False},
            {"api": "EVP_DecodeBlock", "condition": "short output buffer", "label": "contract_boundary_observation", "promote": False},
            {"api": "EVP_DecodeBlock", "condition": "input_len > actual readable input length", "label": "harness_fault_or_invalid_contract_observation", "promote": False},
            {"api": "EVP_MAC_init", "condition": "ctx == NULL", "label": "contract_boundary_observation", "promote": False},
            {"api": "*", "condition": "NULL ctx passed to API requiring allocated ctx", "label": "invalid_contract_observation", "promote": False, "unless": "documentation explicitly promises safe reject"},
        ],
    }
    blocklist = {
        "schema": "memory_candidate_mutation_blocklist_v1",
        "blocked_by_default": [
            "NULL ctx for APIs requiring allocated ctx",
            "NULL input plus nonzero length where API requires valid pointer",
            "short output buffer where API lacks output-size parameter",
            "input_len larger than readable buffer",
            "use-after-free",
            "double-free",
            "use-after-close",
        ],
        "valid_contract_campaign_allowed": [
            "valid input pointer with bounded length",
            "sufficient output buffer",
            "valid allocated context lifecycle",
            "documented safe NULL boundary with contract_valid=1",
        ],
    }
    dump_yaml(out_dir / "candidate_closure/closed_candidates.yaml", {"schema": "memory_candidate_closed_candidates_v1", "closed_candidates": closed})
    dump_yaml(out_dir / "candidate_closure/oracle_downgrade_rules.yaml", rules)
    dump_yaml(out_dir / "candidate_closure/mutation_blocklist.yaml", blocklist)
    write_text(out_dir / "candidate_closure/observation_summary.md", """# Candidate Closure Summary

Three earlier memory-safety candidates are closed as contract-boundary observations:

- `EVP_EncodeBlock(NULL, nonzero length)` is invalid API use.
- `EVP_DecodeBlock` short output and input length mismatch are invalid contract / harness faults.
- `EVP_MAC_init(NULL, ...)` is outside the documented MAC context lifecycle.

The next campaign only promotes valid-contract crash, sanitizer, canary, or hang evidence.
""")
    dump_yaml(repo_root / "knowledge/oracle_adjustments/null_deref_dispatch.yaml", {
        "schema": "oracle_adjustment_v1",
        "family": "null_deref_dispatch",
        "source_task": TASK_VALID_CONTRACT,
        "rules": [rules["rules"][3], rules["rules"][4]],
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "confirmed_vulnerability_claim": False,
    })
    return {
        "previous_triages_loaded": all(bool(v) for v in decisions.values()),
        "closed_candidate_count": len(closed),
        "oracle_downgrade_rules_generated": True,
        "mutation_blocklist_generated": True,
    }


def write_structured_parser_closure_artifacts(repo_root: Path, out_dir: Path) -> dict[str, Any]:
    valid_campaign = repo_root / f"artifacts/campaigns/{TASK_VALID_CONTRACT}"
    closed_src = load_yaml(valid_campaign / "candidate_closure/closed_candidates.yaml")
    qc = load_yaml(valid_campaign / "validation/memory_candidate_closure_valid_contract_quality_checks.yaml")
    closed = closed_src.get("closed_candidates", [])
    completed = [
        {"family": "valid_decode_boundary", "status": "completed_no_candidate"},
        {"family": "valid_evp_mac_boundary", "status": "completed_no_candidate"},
        {"family": "valid_bio_boundary", "status": "completed_no_candidate"},
    ]
    rules = {
        "schema": "structured_parser_do_not_repeat_rules_v1",
        "rules": [
            "Do not use valid DER plus trailing garbage.",
            "Do not use DER full-consumption oracle.",
            "Do not replay x509/pkey/pkcs8 app-level trailing-garbage cases.",
            "Do not treat normal malformed reject as candidate.",
            "Do not treat nonzero exit without sanitizer or signal as crash.",
            "Do not repeat invalid-contract API misuse closures from memory candidates.",
        ],
    }
    dump_yaml(out_dir / "candidate_closure/closed_invalid_contract_observations.yaml", {
        "schema": "structured_parser_closed_invalid_contract_observations_v1",
        "source_campaign": valid_campaign.as_posix(),
        "closed_observations": closed,
    })
    dump_yaml(out_dir / "candidate_closure/completed_valid_contract_families.yaml", {
        "schema": "structured_parser_completed_valid_contract_families_v1",
        "source_campaign": valid_campaign.as_posix(),
        "completed_families": completed,
        "source_quality_status": qc.get("quality_status", ""),
    })
    dump_yaml(out_dir / "candidate_closure/do_not_repeat_rules.yaml", rules)
    return {
        "candidate_closure_loaded": bool(closed),
        "invalid_contract_rules_loaded": bool(rules["rules"]),
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    inventory_root = repo_root / args.inventory_root
    openssl_install = Path(args.openssl_install)
    campaign_version = detect_campaign_version(args)
    if campaign_version == "structured_parser":
        priority = PRIORITY_STRUCTURED_PARSER
    elif campaign_version == "valid_contract":
        priority = PRIORITY_VALID_CONTRACT
    elif campaign_version == "decodeblock_null":
        priority = PRIORITY_DECODEBLOCK_NULL
    elif campaign_version == "fix_continue":
        priority = PRIORITY_FIX_CONTINUE
    elif campaign_version == "v2":
        priority = PRIORITY_V2
    else:
        priority = PRIORITY_V1
    if campaign_version == "structured_parser" and args.out_dir == DEFAULT_OUT_DIR:
        out_dir = (repo_root / f"artifacts/campaigns/{TASK_STRUCTURED_PARSER}").resolve()
    if campaign_version == "valid_contract" and args.out_dir == DEFAULT_OUT_DIR:
        out_dir = (repo_root / f"artifacts/campaigns/{TASK_VALID_CONTRACT}").resolve()
    if campaign_version == "decodeblock_null" and args.out_dir == DEFAULT_OUT_DIR:
        out_dir = (repo_root / f"artifacts/campaigns/{TASK_DECODEBLOCK_NULL}").resolve()
    if campaign_version == "v2" and args.out_dir == DEFAULT_OUT_DIR:
        out_dir = (repo_root / f"artifacts/campaigns/{TASK_V2}").resolve()
    if campaign_version == "fix_continue" and args.out_dir == DEFAULT_OUT_DIR:
        out_dir = (repo_root / f"artifacts/campaigns/{TASK_FIX_CONTINUE}").resolve()
    selected = priority[: args.max_families]
    queue = [{"rank": i + 1, "family": f, "track": infer_track(f), "archetype": infer_archetype(f)} for i, f in enumerate(priority)]
    filtered = queue[: args.max_families]
    previous_campaign = repo_root / args.previous_memory_campaign
    triage_root = repo_root / args.candidate_triage_root
    previous_loaded = (previous_campaign / "validation/memory_safety_focused_campaign_quality_checks.yaml").exists() or (previous_campaign / "validation/memory_safety_focused_campaign_v2_quality_checks.yaml").exists()
    fix_status = {
        "previous_candidate_triage_loaded": False,
        "evp_encodeblock_null_nonzero_downgraded": False,
        "memory_length_oracle_adjustment_applied": False,
        "memory_length_mutation_rule_adjustment_applied": False,
    }
    decodeblock_status = {
        "previous_canary_triage_loaded": False,
        "evp_decodeblock_short_output_downgraded": False,
        "evp_decodeblock_input_len_mismatch_downgraded": False,
        "decodeblock_oracle_adjustment_applied": False,
        "decodeblock_mutation_rule_adjustment_applied": False,
    }
    closure_status = {
        "previous_triages_loaded": False,
        "closed_candidate_count": 0,
        "oracle_downgrade_rules_generated": False,
        "mutation_blocklist_generated": False,
    }
    structured_status = {
        "candidate_closure_loaded": False,
        "invalid_contract_rules_loaded": False,
    }
    if campaign_version == "fix_continue":
        fix_status = write_memory_length_oracle_fix_artifacts(repo_root, out_dir, triage_root)
    if campaign_version == "decodeblock_null":
        triage_root = repo_root / args.candidate_triage_root
        decodeblock_status = write_decodeblock_oracle_fix_artifacts(repo_root, out_dir, triage_root)
    if campaign_version == "valid_contract":
        closure_status = write_valid_contract_closure_artifacts(repo_root, out_dir)
    if campaign_version == "structured_parser":
        structured_status = write_structured_parser_closure_artifacts(repo_root, out_dir)
    candidate_only_policy = "crash/sanitizer/hang only" if campaign_version == "structured_parser" else ("valid-contract crash/sanitizer/canary/hang only" if campaign_version == "valid_contract" else ("crash/sanitizer/hang only" if campaign_version == "decodeblock_null" else "crash/sanitizer/canary/hang only"))
    dump_yaml(out_dir / "campaign_config.yaml", {"schema": "memory_safety_campaign_config_v1", "generated_at": now_iso(), "campaign_version": campaign_version, "max_families": args.max_families, "cases_per_family": args.cases_per_family, "stop_on_first_crash_or_sanitizer": True, "candidate_only_policy": candidate_only_policy, "openssl_install": openssl_install.as_posix(), "previous_memory_campaign": previous_campaign.as_posix(), "previous_memory_campaign_loaded": previous_loaded, "candidate_triage_root": triage_root.as_posix(), **fix_status, **decodeblock_status, **closure_status, **structured_status})
    dump_yaml(out_dir / "family_queue.yaml", {"schema": "memory_safety_family_queue_v1", "families": queue})
    dump_yaml(out_dir / "family_queue_after_filter.yaml", {"schema": "memory_safety_family_queue_after_filter_v1", "families": filtered})
    if campaign_version == "structured_parser":
        dump_yaml(out_dir / "structured_parser_strategy.yaml", {"schema": "structured_parser_strategy_v1", "candidate_labels_only": ["crash_candidate", "sanitizer_candidate", "hang_candidate"], "input_class": "malformed_only_structured", "uses_der_trailing_garbage": False, "uses_full_consumption_oracle": False, "normal_reject_candidate": False, "api_semantic_mode_disabled": True})
    candidate_labels_only = ["crash_candidate", "sanitizer_candidate", "memory_safety_candidate", "hang_candidate"] if campaign_version == "valid_contract" else (["crash_candidate", "sanitizer_candidate", "hang_candidate"] if campaign_version == "decodeblock_null" else ["crash_candidate", "sanitizer_candidate", "memory_safety_candidate", "hang_candidate"])
    dump_yaml(out_dir / "memory_safety_strategy.yaml", {"schema": "memory_safety_strategy_v1", "candidate_labels_only": candidate_labels_only, "valid_contract_mode_enabled": campaign_version == "valid_contract", "invalid_contract_candidate_blocked": True, "normal_reject_candidate": False, "nonzero_exit_without_evidence_is_crash": False, "api_semantic_mode_disabled": True, "uses_der_trailing_garbage": False, "uses_full_consumption_oracle": False})
    qualities = []
    all_candidates = []
    stop_reason = {"schema": "memory_safety_stop_reason_v1", "stop_reason": "max_family_budget_reached", "stopped_on_candidate": False, "candidate_family": ""}
    for family in selected:
        family_root = out_dir / "per_family" / family
        cases = cases_for_family(family, args.cases_per_family)
        dump_yaml(family_root / "seed_discovery/seed_manifest.yaml", {"schema": "memory_safety_seed_manifest_v1", "family": family, "seed_ready": True, "seed_count": len(cases), "seeds": [{"case_id": c["case_id"]} for c in cases]})
        dump_yaml(family_root / "mutation/mutation_plan.yaml", {"schema": "memory_safety_mutation_plan_v1", "family": family, "mutation_case_count": len(cases), "uses_der_trailing_garbage": False, "uses_full_consumption_oracle": False})
        compile_records, run_records, events = compile_and_run_cases(cases, family_root, openssl_install, args.timeout_seconds, stop_on_crash_or_sanitizer=True)
        candidates = promoted_candidates(events)
        contract_observations = [e for e in events if e["candidate_label"] == "contract_boundary_observation"]
        contract_valid_events = [e for e in events if e.get("contract_valid", True)]
        invalid_contract_events = [e for e in events if not e.get("contract_valid", True)]
        invalid_contract_promoted = [
            e for e in invalid_contract_events
            if e.get("candidate_label") in {"crash_candidate", "sanitizer_candidate", "memory_safety_candidate", "hang_candidate"}
        ]
        compile_success = len([r for r in compile_records if r["compile_status"] == "compile_success"])
        run_attempted = len([r for r in run_records if r["run_status"] != "not_run_compile_failed"])
        dump_yaml(family_root / "compile/compile_summary.yaml", {"schema": "memory_safety_compile_summary_v1", "compile_success": compile_success, "compile_failed": len(compile_records) - compile_success})
        dump_yaml(family_root / "run/run_records.yaml", {"schema": "memory_safety_run_records_v1", "run_records": run_records})
        dump_yaml(family_root / "run/run_summary.yaml", {"schema": "memory_safety_run_summary_v1", "run_attempted": run_attempted, "asan": len([e for e in events if e["asan_observed"]]), "ubsan": len([e for e in events if e["ubsan_observed"]]), "crash": len([e for e in events if e["crash_signal"] != "none"]), "timeout": len([e for e in events if e["candidate_label"] == "hang_candidate"])})
        dump_yaml(family_root / "analyze/oracle_events.yaml", {"schema": "memory_safety_oracle_events_v1", "oracle_events": events})
        dump_yaml(family_root / "analyze/analyze_summary.yaml", {"schema": "memory_safety_analyze_summary_v1", "oracle_event_count": len(events), "candidate_count": len(candidates), "contract_boundary_observation_count": len(contract_observations), "contract_valid_events": len(contract_valid_events), "invalid_contract_events": len(invalid_contract_events), "invalid_contract_promoted_to_candidate": bool(invalid_contract_promoted)})
        dump_yaml(family_root / "candidate_queue/candidates.yaml", {"schema": "memory_safety_candidates_v1", "candidates": candidates, "contract_boundary_observations": contract_observations, "all_events": events})
        summary = {"schema": "memory_safety_candidate_summary_v1", "candidate_count": len(candidates), "crash_candidate_count": len([e for e in candidates if e["candidate_label"] == "crash_candidate"]), "sanitizer_candidate_count": len([e for e in candidates if e["candidate_label"] == "sanitizer_candidate"]), "memory_safety_candidate_count": len([e for e in candidates if e["candidate_label"] == "memory_safety_candidate"]), "hang_candidate_count": len([e for e in candidates if e["candidate_label"] == "hang_candidate"]), "contract_boundary_observation_count": len(contract_observations)}
        dump_yaml(family_root / "candidate_queue/candidate_summary.yaml", summary)
        family_quality_status = "pass_no_candidate"
        if any(e["candidate_label"] in {"crash_candidate", "sanitizer_candidate", "hang_candidate"} for e in candidates):
            family_quality_status = "pass_crash_or_sanitizer_candidate_found"
        elif candidates:
            family_quality_status = "pass_memory_candidate_found"
        q = {"family": family, "track": infer_track(family), "archetype": infer_archetype(family), "cases_generated": len(cases), "compile_success": compile_success, "run_attempted": run_attempted, "oracle_events": len(events), "contract_valid_events": len(contract_valid_events), "invalid_contract_events": len(invalid_contract_events), "invalid_contract_promoted_to_candidate": bool(invalid_contract_promoted), "asan": len([e for e in events if e["asan_observed"]]), "ubsan": len([e for e in events if e["ubsan_observed"]]), "crash": len([e for e in events if e["crash_signal"] != "none"]), "timeout": len([e for e in events if e["candidate_label"] == "hang_candidate"]), "canary_corruption": len([e for e in events if e["canary_corrupted"]]), "contract_observations": len(contract_observations), "candidate_count": len(candidates), "quality_status": family_quality_status}
        qualities.append(q)
        all_candidates.extend(candidates)
        if any(c["candidate_label"] in {"crash_candidate", "sanitizer_candidate", "hang_candidate"} for c in candidates):
            stop_reason = {"schema": "memory_safety_stop_reason_v1", "stop_reason": "candidate_found", "stopped_on_candidate": True, "candidate_family": family}
            write_candidate_package(out_dir, family_root, candidates[0], compile_records, run_records)
            break
    candidate_found = bool(all_candidates)
    if candidate_found and not (out_dir / "candidate_triage_package/candidate_metadata.yaml").exists():
        first = all_candidates[0]
        first_family_root = out_dir / "per_family" / first["family"]
        first_run_records = load_yaml(first_family_root / "run/run_records.yaml").get("run_records", [])
        first_compile_records = []
        write_candidate_package(out_dir, first_family_root, first, first_compile_records, first_run_records)
    if not candidate_found:
        write_text(out_dir / "candidate_triage_package/triage_next_steps.md", "# Candidate Triage Package\n\nNo memory-safety candidate was found.\n")
    dump_yaml(out_dir / "stop_reason.yaml", stop_reason)
    dump_yaml(out_dir / "campaign_candidate_summary.yaml", {"schema": "memory_safety_campaign_candidate_summary_v1", "candidate_found": candidate_found, "candidate_family": all_candidates[0]["family"] if all_candidates else "", "candidate_count": len(all_candidates)})
    remaining = [f for f in priority if f not in [q["family"] for q in qualities]]
    dump_yaml(out_dir / "remaining_family_status.yaml", {"schema": "memory_safety_remaining_family_status_v1", "completed_without_candidate_prior": V1_COMPLETED if campaign_version == "v2" else [], "remaining_memory_safety_targets": remaining, "blocked": [], "external_pending": ["asn1_nested_boundary", "pkcs_container_parsing", "x509_parsing"]})
    dump_yaml(out_dir / "feedback_to_pipeline/integration_backlog.yaml", {
        "schema": "memory_safety_integration_backlog_v1",
        "main_feedback_written": False,
        "items": [
            {
                "family": "memory_length_boundary",
                "source": "memlen_null_input_nonzero_triage_v1",
                "recommendation": "Treat EVP_EncodeBlock(NULL, nonzero length) as contract_boundary_observation, not as a promoted sanitizer_candidate.",
                "status": "applied_in_campaign_artifacts",
            }
        ] if campaign_version == "fix_continue" else [
            {
                "family": "buffer_canary_boundary",
                "source": "canary_decode_short_output_triage_v1",
                "recommendation": "Treat EVP_DecodeBlock short-output and overclaimed-input-length cases as contract-boundary or harness-fault observations unless valid-contract controls still show memory-safety evidence.",
                "status": "applied_in_campaign_artifacts",
            }
        ] if campaign_version == "decodeblock_null" else [
            {
                "family": "valid_contract_memory_campaign",
                "source": TASK_VALID_CONTRACT,
                "recommendation": "Promote only contract_valid=1 crash/sanitizer/canary/hang evidence; keep closed invalid-contract cases as observations.",
                "status": "applied_in_campaign_artifacts",
            }
        ] if campaign_version == "valid_contract" else [],
    })
    counts = {label: len([e for e in all_candidates if e["candidate_label"] == label]) for label in ["crash_candidate", "sanitizer_candidate", "memory_safety_candidate", "hang_candidate"]}
    contract_boundary_observation_count = sum(q.get("contract_observations", 0) for q in qualities)
    invalid_contract_promoted_to_candidate = any(q.get("invalid_contract_promoted_to_candidate") for q in qualities)
    if campaign_version == "structured_parser":
        if counts["crash_candidate"] or counts["sanitizer_candidate"] or counts["hang_candidate"]:
            quality_status = "pass_structured_parser_candidate_found"
        elif not qualities:
            quality_status = "blocked_no_ready_structured_parser_family"
        elif sum(q["compile_success"] for q in qualities) < 30:
            quality_status = "blocked_compile_failure"
        elif len(qualities) < args.max_families:
            quality_status = "pass_no_candidate_some_blocked"
        else:
            quality_status = "pass_no_candidate_structured_parser_completed"
    elif campaign_version == "valid_contract":
        if invalid_contract_promoted_to_candidate:
            quality_status = "failed_invalid_contract_promoted"
        elif counts["crash_candidate"] or counts["sanitizer_candidate"] or counts["memory_safety_candidate"] or counts["hang_candidate"]:
            quality_status = "pass_valid_contract_candidate_found"
        elif not qualities:
            quality_status = "blocked_no_ready_valid_contract_family"
        elif sum(q["compile_success"] for q in qualities) < 20:
            quality_status = "blocked_compile_failure"
        elif len(qualities) < args.max_families:
            quality_status = "pass_no_candidate_some_blocked"
        else:
            quality_status = "pass_no_candidate_valid_contract_completed"
    elif campaign_version == "decodeblock_null":
        if counts["crash_candidate"] or counts["sanitizer_candidate"] or counts["hang_candidate"]:
            quality_status = "pass_crash_or_sanitizer_candidate_found"
        elif qualities and sum(q["run_attempted"] for q in qualities) >= 25:
            quality_status = "pass_no_candidate_null_deref_completed"
        elif qualities:
            quality_status = "pass_no_candidate_some_blocked"
        else:
            quality_status = "blocked_no_ready_null_deref"
    else:
        quality_status = "pass_crash_or_sanitizer_candidate_found" if counts["crash_candidate"] or counts["sanitizer_candidate"] else ("pass_memory_candidate_found" if counts["memory_safety_candidate"] or counts["hang_candidate"] else "pass_no_candidate_memory_campaign_completed")
    if campaign_version == "structured_parser":
        schema = "structured_parser_memory_campaign_quality_checks_v1"
    elif campaign_version == "valid_contract":
        schema = "memory_candidate_closure_valid_contract_quality_checks_v1"
    elif campaign_version == "decodeblock_null":
        schema = "decodeblock_oracle_fix_null_deref_quality_checks_v1"
    elif campaign_version == "fix_continue":
        schema = "memory_safety_v2_oracle_fix_continue_quality_checks_v1"
    elif campaign_version == "v2":
        schema = "memory_safety_focused_campaign_v2_quality_checks"
    else:
        schema = "memory_safety_focused_campaign_quality_checks_v1"
    qc = {
        "schema": schema,
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        **fix_status,
        **decodeblock_status,
        **closure_status,
        **structured_status,
        "structured_parser_mode_enabled": campaign_version == "structured_parser",
        "valid_contract_mode_enabled": campaign_version == "valid_contract",
        "invalid_contract_candidate_blocked": True,
        "memory_safety_mode_enabled": True,
        "api_semantic_mode_disabled": True,
        "previous_memory_campaign_loaded": previous_loaded,
        "inventory_loaded": bool(load_yaml(inventory_root / "family_status_matrix.yaml")),
        "family_queue_generated": True,
        "max_families": args.max_families,
        "cases_per_family": args.cases_per_family,
        "families_attempted": len(qualities),
        "buffer_canary_attempted": any(q["family"] == "buffer_canary_boundary" for q in qualities),
        "null_deref_dispatch_attempted": any(q["family"] == "null_deref_dispatch" for q in qualities),
        "cases_generated_total": sum(q["cases_generated"] for q in qualities),
        "compile_success_total": sum(q["compile_success"] for q in qualities),
        "run_attempted_total": sum(q["run_attempted"] for q in qualities),
        "oracle_events_total": sum(q["oracle_events"] for q in qualities),
        "contract_valid_events": sum(q.get("contract_valid_events", 0) for q in qualities),
        "invalid_contract_events": sum(q.get("invalid_contract_events", 0) for q in qualities),
        "invalid_contract_promoted_to_candidate": invalid_contract_promoted_to_candidate,
        "candidate_found": candidate_found,
        "candidate_family": all_candidates[0]["family"] if all_candidates else "",
        "crash_candidate_count": counts["crash_candidate"],
        "sanitizer_candidate_count": counts["sanitizer_candidate"],
        "memory_safety_candidate_count": counts["memory_safety_candidate"],
        "hang_candidate_count": counts["hang_candidate"],
        "contract_boundary_observation_count": contract_boundary_observation_count,
        "canary_cases_executed": sum(q["run_attempted"] for q in qualities if q["family"] == "buffer_canary_boundary"),
        "null_dispatch_cases_executed": sum(q["run_attempted"] for q in qualities if q["family"] == "null_deref_dispatch"),
        "length_boundary_cases_executed": sum(q["run_attempted"] for q in qualities if q["family"] == "memory_length_boundary"),
        "normal_reject_treated_as_candidate": False,
        "nonzero_exit_treated_as_crash_without_evidence": False,
        "uses_der_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "public_target_access": False,
        "exploit_chain_generated": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "knowledge_modified": campaign_version in {"decodeblock_null", "valid_contract"},
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status,
    }
    if campaign_version == "structured_parser":
        qc_name = "structured_parser_memory_campaign_quality_checks.yaml"
    elif campaign_version == "valid_contract":
        qc_name = "memory_candidate_closure_valid_contract_quality_checks.yaml"
    elif campaign_version == "decodeblock_null":
        qc_name = "decodeblock_oracle_fix_null_deref_quality_checks.yaml"
    elif campaign_version == "fix_continue":
        qc_name = "memory_safety_v2_oracle_fix_continue_quality_checks.yaml"
    elif campaign_version == "v2":
        qc_name = "memory_safety_focused_campaign_v2_quality_checks.yaml"
    else:
        qc_name = "memory_safety_focused_campaign_quality_checks.yaml"
    dump_yaml(out_dir / "validation" / qc_name, qc)
    write_report(out_dir, qc, qualities, all_candidates, campaign_version)
    print(f"wrote {out_dir}")
    print(f"quality_status: {quality_status}")
    print(f"families_attempted: {len(qualities)}")
    return 0


def write_candidate_package(out_dir: Path, family_root: Path, candidate: dict[str, Any], compile_records: list[dict[str, Any]], run_records: list[dict[str, Any]]) -> None:
    case_id = candidate["case_id"]
    source = family_root / "cases" / f"{case_id}.c"
    if source.exists():
        write_text(out_dir / "candidate_triage_package/min_repro.c", source.read_text(encoding="utf-8"))
    write_text(out_dir / "candidate_triage_package/reproduce.sh", "#!/usr/bin/env bash\nset -euo pipefail\ncc min_repro.c -lssl -lcrypto\n")
    run = next((r for r in run_records if r["case_id"] == case_id), {})
    stderr = Path(run.get("stderr_log", "")).read_text(encoding="utf-8", errors="replace") if run.get("stderr_log") else ""
    write_text(out_dir / "candidate_triage_package/asan_or_crash_excerpt.txt", "\n".join(stderr.splitlines()[:80]))
    dump_yaml(out_dir / "candidate_triage_package/candidate_metadata.yaml", {"schema": "memory_safety_candidate_metadata_v1", "candidate": candidate})
    write_text(out_dir / "candidate_triage_package/triage_next_steps.md", "# Triage Next Steps\n\nRe-run min_repro under the same local ASAN OpenSSL build and inspect sanitizer/crash evidence.\n")


def write_report(out_dir: Path, qc: dict[str, Any], qualities: list[dict[str, Any]], candidates: list[dict[str, Any]], campaign_version: str) -> None:
    rows = "\n".join(f"- {q['family']}: {q['quality_status']} cases={q['cases_generated']} compile={q['compile_success']} run={q['run_attempted']} asan={q.get('asan', 0)} ubsan={q.get('ubsan', 0)} crash={q.get('crash', 0)} timeout={q.get('timeout', 0)} canary={q.get('canary_corruption', 0)} candidates={q['candidate_count']}" for q in qualities)
    if campaign_version == "structured_parser":
        title = TASK_STRUCTURED_PARSER
        report_name = "structured_parser_memory_campaign_v1_report.md"
    elif campaign_version == "valid_contract":
        title = TASK_VALID_CONTRACT
        report_name = "memory_candidate_closure_and_valid_contract_campaign_v1_report.md"
    elif campaign_version == "decodeblock_null":
        title = TASK_DECODEBLOCK_NULL
        report_name = "decodeblock_oracle_fix_and_null_deref_dispatch_v1_report.md"
    elif campaign_version == "fix_continue":
        title = TASK_FIX_CONTINUE
        report_name = "memory_safety_v2_oracle_fix_continue_canary_null_v1_report.md"
    elif campaign_version == "v2":
        title = "memory_safety_focused_campaign_v2_remaining_boundaries"
        report_name = "memory_safety_focused_campaign_v2_remaining_boundaries_report.md"
    else:
        title = "memory_safety_focused_campaign_v1"
        report_name = "memory_safety_focused_campaign_v1_report.md"
    if campaign_version == "structured_parser":
        policy = "Only malformed-only structured parser sanitizer, crash, or hang signals are candidates; trailing-garbage and full-consumption oracle patterns are not used."
    elif campaign_version == "valid_contract":
        policy = "Only contract-valid sanitizer, crash, hang, or canary corruption signals are candidates; invalid-contract observations are blocked from candidate promotion."
    elif campaign_version == "decodeblock_null":
        policy = "Only sanitizer, crash, or hang signals are candidates in this null-deref dispatch pass."
    else:
        policy = "Only sanitizer, crash, hang, or canary corruption signals are candidates."
    report = f"""# memory_safety_focused_campaign_v1 Report

## Summary

- quality_status: {qc['quality_status']}
- families_attempted: {qc['families_attempted']}
- candidate_found: {qc['candidate_found']}
- run_attempted_total: {qc['run_attempted_total']}

## Families

{rows}

## Policy

{policy} Normal malformed-input rejects are not candidates. No public target, exploit chain, pattern-bank write, git operation, DER trailing-garbage replay, or full-consumption oracle was used.
"""
    report = report.replace("memory_safety_focused_campaign_v1", title, 1)
    write_text(out_dir / "reports" / report_name, report)


if __name__ == "__main__":
    raise SystemExit(main())

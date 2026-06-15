#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

int main(void) {
    unsigned char arena[1024];
    unsigned char *out = arena + 64;
    unsigned char in[512];
    unsigned char key[32];
    char text[256];
    const char *actual = "error";
    const char *label = "no_candidate";
    const char *expected = "success_or_no_crash";
    const char *api = "EVP_MAC_init";
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
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0); params[1] = OSSL_PARAM_construct_end(); mac = EVP_MAC_fetch(NULL, "HMAC", NULL); mctx = EVP_MAC_CTX_new(mac); ret = EVP_MAC_init(mctx, key, 16, params); if (ret == 1) ret = EVP_MAC_update(mctx, in, 91); if (ret == 1) ret = EVP_MAC_final(mctx, out, &outlen, 64); actual = ret == 1 ? "success" : "error";
    for (int i = 0; i < 64; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    for (int i = 576; i < 640; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    if (contract_valid && canary_corrupted) label = "memory_safety_candidate";
    printf("ORACLE_EVENT family=valid_evp_mac_boundary\n");
    printf("ORACLE_EVENT case_id=validmac_generated_mac_variant_09\n");
    printf("ORACLE_EVENT trigger_api=%s\n", api);
    printf("ORACLE_EVENT contract_valid=%d\n", contract_valid);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=%d\n", canary_corrupted);
    printf("ORACLE_EVENT candidate_label=%s\n", label);
    EVP_ENCODE_CTX_free(ectx);
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    BIO_free(bio);
    return 0;
}

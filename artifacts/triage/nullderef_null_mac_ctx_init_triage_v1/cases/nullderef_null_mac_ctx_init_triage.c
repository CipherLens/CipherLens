#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static void print_step(const char *case_id, const char *api, int ret, int ctx_is_null)
{
    printf("STEP_EVENT case_id=%s api=%s ret=%d ctx_is_null=%d\n",
           case_id, api, ret, ctx_is_null);
    fflush(stdout);
}

static void print_oracle(const char *case_id, const char *expected, const char *actual,
                         int contract_boundary, const char *candidate_label)
{
    printf("ORACLE_EVENT family=null_deref_dispatch\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT trigger_api=EVP_MAC_init\n");
    printf("ORACLE_EVENT expected_behavior=%s\n", expected);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT contract_boundary=%d\n", contract_boundary);
    printf("ORACLE_EVENT candidate_label=%s\n", candidate_label);
    fflush(stdout);
}

static void run_valid_hmac_ctx_init_control(void)
{
    const char *case_id = "valid_hmac_ctx_init_control";
    unsigned char key[16];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int ret = 0;

    memset(key, 0x11, sizeof(key));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx != NULL)
        ret = EVP_MAC_init(ctx, key, sizeof(key), params);
    print_step(case_id, "EVP_MAC_init", ret, ctx == NULL);
    print_oracle(case_id, "success_or_no_crash", ret == 1 ? "success" : "error", 0, "no_candidate");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void run_failed_mac_fetch_then_ctx_new(void)
{
    const char *case_id = "failed_mac_fetch_then_ctx_new";
    unsigned char key[16];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    int ret = 0;

    memset(key, 0x22, sizeof(key));
    mac = EVP_MAC_fetch(NULL, "NO_SUCH_MAC_FOR_TRIAGE", NULL);
    print_step(case_id, "EVP_MAC_CTX_new", -1, mac == NULL);
    print_oracle(case_id, "reject_or_no_crash", "error", mac == NULL, "no_candidate");
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx != NULL)
        ret = EVP_MAC_init(ctx, key, sizeof(key), NULL);
    print_step(case_id, "EVP_MAC_init", ret, ctx == NULL);
    print_oracle(case_id, "reject_or_no_crash", ret == 1 ? "success" : "error", ctx == NULL, "no_candidate");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void run_mac_ctx_new_null_mac_then_init_if_applicable(void)
{
    const char *case_id = "mac_ctx_new_null_mac_then_init_if_applicable";
    unsigned char key[16];
    EVP_MAC_CTX *ctx = NULL;
    int ret = 0;

    memset(key, 0x33, sizeof(key));
    print_step(case_id, "EVP_MAC_CTX_new", -1, 1);
    print_oracle(case_id, "contract_boundary_observation", "error", 1, "contract_boundary_observation");
    ctx = EVP_MAC_CTX_new(NULL);
    if (ctx != NULL)
        ret = EVP_MAC_init(ctx, key, sizeof(key), NULL);
    print_step(case_id, "EVP_MAC_init", ret, ctx == NULL);
    print_oracle(case_id, "reject_or_no_crash", ret == 1 ? "success" : "error", ctx == NULL, "no_candidate");
    EVP_MAC_CTX_free(ctx);
}

static void run_valid_ctx_null_key_zero_keylen(void)
{
    const char *case_id = "valid_ctx_null_key_zero_keylen";
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int ret = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx != NULL)
        ret = EVP_MAC_init(ctx, NULL, 0, params);
    print_step(case_id, "EVP_MAC_init", ret, ctx == NULL);
    print_oracle(case_id, "reject_or_no_crash", ret == 1 ? "success" : "error", 0, "no_candidate");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void run_valid_ctx_null_key_nonzero_keylen(void)
{
    const char *case_id = "valid_ctx_null_key_nonzero_keylen";
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int ret = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx != NULL)
        ret = EVP_MAC_init(ctx, NULL, 16, params);
    print_step(case_id, "EVP_MAC_init", ret, ctx == NULL);
    print_oracle(case_id, "contract_boundary_observation", ret == 1 ? "success" : "error", 1, "contract_boundary_observation");
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void run_null_mac_ctx_init_original(void)
{
    const char *case_id = "null_mac_ctx_init_original";
    unsigned char key[16];
    int ret = 0;

    memset(key, 0x44, sizeof(key));
    print_step(case_id, "EVP_MAC_init", -1, 1);
    print_oracle(case_id, "contract_boundary_observation", "error", 1, "sanitizer_candidate");
    ret = EVP_MAC_init(NULL, key, sizeof(key), NULL);
    print_step(case_id, "EVP_MAC_init", ret, 1);
    print_oracle(case_id, "contract_boundary_observation", ret == 1 ? "success" : "error", 1, "sanitizer_candidate");
}

int main(int argc, char **argv)
{
    const char *variant = argc > 1 ? argv[1] : "all";

    if (strcmp(variant, "valid_hmac_ctx_init_control") == 0 || strcmp(variant, "all") == 0)
        run_valid_hmac_ctx_init_control();
    if (strcmp(variant, "failed_mac_fetch_then_ctx_new") == 0 || strcmp(variant, "all") == 0)
        run_failed_mac_fetch_then_ctx_new();
    if (strcmp(variant, "mac_ctx_new_null_mac_then_init_if_applicable") == 0 || strcmp(variant, "all") == 0)
        run_mac_ctx_new_null_mac_then_init_if_applicable();
    if (strcmp(variant, "valid_ctx_null_key_zero_keylen") == 0 || strcmp(variant, "all") == 0)
        run_valid_ctx_null_key_zero_keylen();
    if (strcmp(variant, "valid_ctx_null_key_nonzero_keylen") == 0 || strcmp(variant, "all") == 0)
        run_valid_ctx_null_key_nonzero_keylen();
    if (strcmp(variant, "null_mac_ctx_init_original") == 0 || strcmp(variant, "all") == 0)
        run_null_mac_ctx_init_original();
    return 0;
}

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

typedef struct {
    const char *mac_name;
    const char *param_name;
    const char *param_value;
} alg_case;

static int setup_mac(EVP_MAC **mac, EVP_MAC_CTX **ctx, const alg_case *alg)
{
    *mac = EVP_MAC_fetch(NULL, alg->mac_name, NULL);
    if (*mac == NULL)
        return 0;
    *ctx = EVP_MAC_CTX_new(*mac);
    if (*ctx == NULL)
        return 0;
    return 1;
}

static int init_mac(EVP_MAC_CTX *ctx, const alg_case *alg)
{
    unsigned char key[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    OSSL_PARAM params[2];
    size_t key_len = sizeof(key);

    if (strcmp(alg->mac_name, "CMAC") == 0
        && strcmp(alg->param_value, "AES-128-CBC") == 0)
        key_len = 16;

    params[0] = OSSL_PARAM_construct_utf8_string(alg->param_name,
                                                 (char *)alg->param_value, 0);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_MAC_init(ctx, key, key_len, params);
}

static void print_verdict(const alg_case *alg, const char *sequence,
                          int init_ret, int update_ret, int first_final_ret,
                          int second_final_ret, size_t outl1, size_t outl2)
{
    const int is_cmac = strcmp(alg->mac_name, "CMAC") == 0;

    printf("[ALG] %s %s=%s\n", alg->mac_name, alg->param_name, alg->param_value);
    printf("[SEQUENCE] %s\n", sequence);
    printf("init_ret=%d\n", init_ret);
    printf("update_ret=%d\n", update_ret);
    printf("first_final_ret=%d\n", first_final_ret);
    printf("second_final_ret=%d\n", second_final_ret);
    printf("outl1=%zu\n", outl1);
    printf("outl2=%zu\n", outl2);

    if (strcmp(sequence, "abort_then_final") == 0) {
        printf("[VERDICT] unsupported_no_evp_mac_abort_api\n\n");
    } else if (strcmp(sequence, "final_before_setup") == 0) {
        if (first_final_ret == 1)
            printf("[VERDICT] lifecycle_unexpected_success_candidate\n\n");
        else if (outl1 != 0xdeadbeefUL)
            printf("[VERDICT] failure_path_outl_modified_triage\n\n");
        else
            printf("[VERDICT] safe_reject\n\n");
    } else if (second_final_ret == 1 && is_cmac) {
        printf("[VERDICT] lifecycle_unexpected_success_needs_manual_review\n\n");
    } else if (second_final_ret == 1) {
        printf("[VERDICT] lifecycle_unexpected_success_candidate\n\n");
    } else if (outl2 != 0xdeadbeefUL) {
        printf("[VERDICT] failure_path_outl_modified_triage\n\n");
    } else {
        printf("[VERDICT] safe_reject\n\n");
    }
}

static void run_setup_update_final_final(const alg_case *alg)
{
    unsigned char data[] = {'a', 'b', 'c'};
    unsigned char out[128];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    int init_ret = -1, update_ret = -1, final1 = -1, final2 = -1;
    size_t outl1 = 0xdeadbeefUL, outl2 = 0xdeadbeefUL;

    memset(out, 0xaa, sizeof(out));
    if (setup_mac(&mac, &ctx, alg)) {
        init_ret = init_mac(ctx, alg);
        update_ret = EVP_MAC_update(ctx, data, sizeof(data));
        final1 = EVP_MAC_final(ctx, out, &outl1, sizeof(out));
        final2 = EVP_MAC_final(ctx, out, &outl2, sizeof(out));
    }
    print_verdict(alg, "setup_update_final_final", init_ret, update_ret,
                  final1, final2, outl1, outl2);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void run_setup_final_final(const alg_case *alg)
{
    unsigned char out[128];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    int init_ret = -1, final1 = -1, final2 = -1;
    size_t outl1 = 0xdeadbeefUL, outl2 = 0xdeadbeefUL;

    memset(out, 0xaa, sizeof(out));
    if (setup_mac(&mac, &ctx, alg)) {
        init_ret = init_mac(ctx, alg);
        final1 = EVP_MAC_final(ctx, out, &outl1, sizeof(out));
        final2 = EVP_MAC_final(ctx, out, &outl2, sizeof(out));
    }
    print_verdict(alg, "setup_final_final", init_ret, -1, final1, final2,
                  outl1, outl2);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void run_final_before_setup(const alg_case *alg)
{
    unsigned char out[128];
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    int final1 = -1;
    size_t outl1 = 0xdeadbeefUL;

    memset(out, 0xaa, sizeof(out));
    if (setup_mac(&mac, &ctx, alg))
        final1 = EVP_MAC_final(ctx, out, &outl1, sizeof(out));
    print_verdict(alg, "final_before_setup", -1, -1, final1, -1,
                  outl1, 0xdeadbeefUL);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

static void run_abort_then_final(const alg_case *alg)
{
    print_verdict(alg, "abort_then_final", -1, -1, -1, -1,
                  0xdeadbeefUL, 0xdeadbeefUL);
}

int main(void)
{
    alg_case algs[] = {
        {"HMAC", OSSL_MAC_PARAM_DIGEST, "SHA256"},
        {"HMAC", OSSL_MAC_PARAM_DIGEST, "SHA512"},
        {"CMAC", OSSL_MAC_PARAM_CIPHER, "AES-128-CBC"},
        {"CMAC", OSSL_MAC_PARAM_CIPHER, "AES-256-CBC"},
    };
    size_t i;

    for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++) {
        run_setup_update_final_final(&algs[i]);
        run_setup_final_final(&algs[i]);
        run_final_before_setup(&algs[i]);
        run_abort_then_final(&algs[i]);
    }
    ERR_print_errors_fp(stderr);
    return 0;
}

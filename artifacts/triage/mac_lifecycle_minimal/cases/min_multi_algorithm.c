#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static int run_one(const char *mac_name, const char *param_name, const char *param_value)
{
    unsigned char key[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char data[] = {'a', 'b', 'c'};
    unsigned char out[128];
    size_t outl_pre = 0xdeadbeefUL;
    size_t outl1 = 0xdeadbeefUL;
    size_t outl2 = 0xdeadbeefUL;
    int pre_ret = -1;
    int init_ret = -1;
    int update_ret = -1;
    int final1_ret = -1;
    int final2_ret = -1;
    int triage = 0;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, mac_name, NULL);
    EVP_MAC_CTX *ctx_pre = NULL;
    EVP_MAC_CTX *ctx_double = NULL;
    OSSL_PARAM params[2];

    printf("=== mac=%s param=%s value=%s ===\n", mac_name, param_name, param_value);
    if (mac == NULL) {
        printf("[VERDICT] setup_failed\n");
        ERR_print_errors_fp(stderr);
        return 2;
    }

    memset(out, 0xaa, sizeof(out));
    ctx_pre = EVP_MAC_CTX_new(mac);
    if (ctx_pre == NULL) {
        printf("[VERDICT] setup_failed\n");
        EVP_MAC_free(mac);
        return 2;
    }
    pre_ret = EVP_MAC_final(ctx_pre, out, &outl_pre, sizeof(out));
    printf("finish_before_setup_ret=%d outl=%zu\n", pre_ret, outl_pre);
    if (pre_ret == 1) {
        printf("[VERDICT] unexpected_success finish_before_setup\n");
        triage = 1;
    } else if (outl_pre != 0xdeadbeefUL) {
        printf("[VERDICT] failure_path_outl_modified_triage finish_before_setup\n");
        triage = 1;
    } else {
        printf("[VERDICT] safe_failure_outl_unchanged finish_before_setup\n");
    }
    EVP_MAC_CTX_free(ctx_pre);

    memset(out, 0xaa, sizeof(out));
    ctx_double = EVP_MAC_CTX_new(mac);
    if (ctx_double == NULL) {
        printf("[VERDICT] setup_failed\n");
        EVP_MAC_free(mac);
        return 2;
    }
    params[0] = OSSL_PARAM_construct_utf8_string(param_name, (char *)param_value, 0);
    params[1] = OSSL_PARAM_construct_end();
    init_ret = EVP_MAC_init(ctx_double, key, sizeof(key), params);
    update_ret = EVP_MAC_update(ctx_double, data, sizeof(data));
    final1_ret = EVP_MAC_final(ctx_double, out, &outl1, sizeof(out));
    final2_ret = EVP_MAC_final(ctx_double, out, &outl2, sizeof(out));
    printf("init_ret=%d update_ret=%d final1_ret=%d final2_ret=%d outl1=%zu outl2=%zu\n",
           init_ret, update_ret, final1_ret, final2_ret, outl1, outl2);
    if (final2_ret == 1) {
        printf("[VERDICT] unexpected_second_final_success\n");
        triage = 1;
    } else if (outl2 != 0xdeadbeefUL) {
        printf("[VERDICT] failure_path_outl_modified_triage double_finish\n");
        triage = 1;
    } else {
        printf("[VERDICT] safe_second_final_failure\n");
    }
    EVP_MAC_CTX_free(ctx_double);
    EVP_MAC_free(mac);
    return triage ? 1 : 0;
}

int main(void)
{
    int triage = 0;
    triage |= run_one("HMAC", OSSL_MAC_PARAM_DIGEST, "SHA256");
    triage |= run_one("HMAC", OSSL_MAC_PARAM_DIGEST, "SHA512");
    triage |= run_one("CMAC", OSSL_MAC_PARAM_CIPHER, "AES-128-CBC");
    ERR_print_errors_fp(stderr);
    return triage ? 1 : 0;
}

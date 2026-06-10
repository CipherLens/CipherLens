#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static void print_out_prefix(const unsigned char *out)
{
    printf("out_prefix=%02x %02x %02x %02x %02x %02x %02x %02x\n",
           out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
}

int main(void)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;
    unsigned char key[] = {'s', 'p', 'r', 'i', 'n', 't', '-', 'k', 'e', 'y'};
    unsigned char data[] = {'a', 'b', 'c'};
    unsigned char out[64];
    size_t outl1 = 0xdeadbeefUL;
    size_t outl2 = 0xdeadbeefUL;
    int init_ret = -1;
    int update_ret = -1;
    int final1_ret = -1;
    int final2_ret = -1;
    OSSL_PARAM params[2];

    memset(out, 0xaa, sizeof(out));
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (mac == NULL) {
        printf("[VERDICT] setup_failed\n");
        ERR_print_errors_fp(stderr);
        return 2;
    }
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        printf("[VERDICT] setup_failed\n");
        ERR_print_errors_fp(stderr);
        EVP_MAC_free(mac);
        return 2;
    }

    init_ret = EVP_MAC_init(ctx, key, sizeof(key), params);
    update_ret = EVP_MAC_update(ctx, data, sizeof(data));
    final1_ret = EVP_MAC_final(ctx, out, &outl1, sizeof(out));
    final2_ret = EVP_MAC_final(ctx, out, &outl2, sizeof(out));

    printf("init_ret=%d\n", init_ret);
    printf("update_ret=%d\n", update_ret);
    printf("final1_ret=%d\n", final1_ret);
    printf("final2_ret=%d\n", final2_ret);
    printf("outl1=%zu\n", outl1);
    printf("outl2=%zu\n", outl2);
    print_out_prefix(out);
    ERR_print_errors_fp(stderr);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    if (final2_ret == 1) {
        printf("[VERDICT] unexpected_second_final_success\n");
        return 1;
    }
    if (final2_ret == 0 && outl2 == 0xdeadbeefUL) {
        printf("[VERDICT] safe_second_final_failure\n");
        return 0;
    }
    printf("[VERDICT] failure_path_outl_modified_triage\n");
    return 1;
}

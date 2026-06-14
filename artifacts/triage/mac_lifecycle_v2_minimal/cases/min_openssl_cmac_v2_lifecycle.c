#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include <stdio.h>
#include <string.h>

static void print_hex_field(const char *name, const unsigned char *buf, size_t len)
{
    size_t i;
    printf("%s=", name);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int bytes_equal(const unsigned char *a, size_t alen,
                       const unsigned char *b, size_t blen)
{
    return alen == blen && memcmp(a, b, alen) == 0;
}

static void run_case(const char *algorithm, const char *sequence,
                     const unsigned char *key, size_t key_len)
{
    static const unsigned char message[] = {
        0x6d, 0x61, 0x63, 0x20, 0x6c, 0x69, 0x66, 0x65,
        0x63, 0x79, 0x63, 0x6c, 0x65, 0x20, 0x6d, 0x73,
        0x67
    };
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned char out1[64] = {0};
    unsigned char out2[64] = {0};
    unsigned char out3[64] = {0};
    size_t outl1 = 0;
    size_t outl2 = 0;
    size_t outl3 = 0;
    int init_ret = 0;
    int update1_ret = 0;
    int final1_ret = -1;
    int final2_ret = -1;
    int final3_ret = -1;
    int update_after_final_ret = -1;
    int update_after_second_final_ret = -1;

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac != NULL) {
        ctx = EVP_MAC_CTX_new(mac);
    }
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *) algorithm, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (ctx != NULL) {
        init_ret = EVP_MAC_init(ctx, key, key_len, params);
        if (init_ret == 1) {
            update1_ret = EVP_MAC_update(ctx, message, sizeof(message));
        }
        if (update1_ret == 1) {
            final1_ret = EVP_MAC_final(ctx, out1, &outl1, sizeof(out1));
        }
        if (strcmp(sequence, "update_after_final") == 0) {
            if (final1_ret == 1) {
                update_after_final_ret = EVP_MAC_update(ctx, message, sizeof(message));
                final2_ret = EVP_MAC_final(ctx, out2, &outl2, sizeof(out2));
            }
        } else if (strcmp(sequence, "third_final") == 0) {
            if (final1_ret == 1) {
                final2_ret = EVP_MAC_final(ctx, out2, &outl2, sizeof(out2));
                final3_ret = EVP_MAC_final(ctx, out3, &outl3, sizeof(out3));
            }
        } else if (strcmp(sequence, "update_after_second_final") == 0) {
            if (final1_ret == 1) {
                final2_ret = EVP_MAC_final(ctx, out2, &outl2, sizeof(out2));
                update_after_second_final_ret = EVP_MAC_update(ctx, message, sizeof(message));
                final3_ret = EVP_MAC_final(ctx, out3, &outl3, sizeof(out3));
            }
        }
    }

    printf("algorithm=%s\n", algorithm);
    printf("sequence=%s\n", sequence);
    printf("init_ret=%d\n", init_ret);
    printf("update1_ret=%d\n", update1_ret);
    printf("final1_ret=%d\n", final1_ret);
    printf("final2_ret=%d\n", final2_ret);
    printf("final3_ret=%d\n", final3_ret);
    printf("update_after_final_ret=%d\n", update_after_final_ret);
    printf("update_after_second_final_ret=%d\n", update_after_second_final_ret);
    printf("outl1=%zu\n", outl1);
    printf("outl2=%zu\n", outl2);
    printf("outl3=%zu\n", outl3);
    print_hex_field("out1_hex", out1, outl1);
    print_hex_field("out2_hex", out2, outl2);
    print_hex_field("out3_hex", out3, outl3);
    printf("out1_eq_out2=%d\n", bytes_equal(out1, outl1, out2, outl2));
    printf("out2_eq_out3=%d\n", bytes_equal(out2, outl2, out3, outl3));
    printf("--\n");

    if (ctx != NULL) {
        EVP_MAC_CTX_free(ctx);
    }
    if (mac != NULL) {
        EVP_MAC_free(mac);
    }
}

int main(void)
{
    static const unsigned char key128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    run_case("AES-128-CBC", "update_after_final", key128, sizeof(key128));
    run_case("AES-128-CBC", "third_final", key128, sizeof(key128));
    run_case("AES-128-CBC", "update_after_second_final", key128, sizeof(key128));
    run_case("AES-256-CBC", "update_after_final", key256, sizeof(key256));
    run_case("AES-256-CBC", "third_final", key256, sizeof(key256));
    run_case("AES-256-CBC", "update_after_second_final", key256, sizeof(key256));

    ERR_print_errors_fp(stderr);
    return 0;
}

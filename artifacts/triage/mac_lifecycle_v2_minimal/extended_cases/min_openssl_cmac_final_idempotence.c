#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include <stdio.h>
#include <string.h>

struct path_a_result {
    int fetch_ok;
    int ctx_ok;
    int init_ret;
    int update_ret;
    int final_ret;
    unsigned char tag[64];
    size_t tag_len;
};

struct path_b_result {
    int fetch_ok;
    int ctx_ok;
    int init_ret;
    int update_ret;
    int length_query_ret;
    int output_final_ret;
    unsigned char tag[64];
    size_t length_query_len;
    size_t tag_len;
};

struct path_c_result {
    int fetch_ok;
    int ctx_ok;
    int init_ret;
    int update_ret;
    int final1_ret;
    int final2_ret;
    unsigned char tag1[64];
    unsigned char tag2[64];
    size_t tag1_len;
    size_t tag2_len;
};

static const unsigned char message[] = {
    0x6d, 0x61, 0x63, 0x20, 0x6c, 0x69, 0x66, 0x65,
    0x63, 0x79, 0x63, 0x6c, 0x65, 0x20, 0x6d, 0x73,
    0x67
};

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

static int setup_cmac(const char *cipher_name,
                      const unsigned char *key,
                      size_t key_len,
                      EVP_MAC **mac_out,
                      EVP_MAC_CTX **ctx_out,
                      OSSL_PARAM params[2])
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;

    *mac_out = NULL;
    *ctx_out = NULL;

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac == NULL) {
        return 0;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return 0;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *) cipher_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    *mac_out = mac;
    *ctx_out = ctx;
    return EVP_MAC_init(ctx, key, key_len, params);
}

static struct path_a_result run_path_a(const char *cipher_name,
                                       const unsigned char *key,
                                       size_t key_len)
{
    struct path_a_result r;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    memset(&r, 0, sizeof(r));
    r.final_ret = -1;

    r.init_ret = setup_cmac(cipher_name, key, key_len, &mac, &ctx, params);
    r.fetch_ok = mac != NULL;
    r.ctx_ok = ctx != NULL;

    if (r.init_ret == 1) {
        r.update_ret = EVP_MAC_update(ctx, message, sizeof(message));
    }
    if (r.update_ret == 1) {
        r.final_ret = EVP_MAC_final(ctx, r.tag, &r.tag_len, sizeof(r.tag));
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return r;
}

static struct path_b_result run_path_b(const char *cipher_name,
                                       const unsigned char *key,
                                       size_t key_len)
{
    struct path_b_result r;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    memset(&r, 0, sizeof(r));
    r.length_query_ret = -1;
    r.output_final_ret = -1;

    r.init_ret = setup_cmac(cipher_name, key, key_len, &mac, &ctx, params);
    r.fetch_ok = mac != NULL;
    r.ctx_ok = ctx != NULL;

    if (r.init_ret == 1) {
        r.update_ret = EVP_MAC_update(ctx, message, sizeof(message));
    }
    if (r.update_ret == 1) {
        r.length_query_ret = EVP_MAC_final(ctx, NULL, &r.length_query_len, 0);
    }
    if (r.length_query_ret == 1) {
        r.output_final_ret = EVP_MAC_final(ctx, r.tag, &r.tag_len, sizeof(r.tag));
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return r;
}

static struct path_c_result run_path_c(const char *cipher_name,
                                       const unsigned char *key,
                                       size_t key_len)
{
    struct path_c_result r;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    memset(&r, 0, sizeof(r));
    r.final1_ret = -1;
    r.final2_ret = -1;

    r.init_ret = setup_cmac(cipher_name, key, key_len, &mac, &ctx, params);
    r.fetch_ok = mac != NULL;
    r.ctx_ok = ctx != NULL;

    if (r.init_ret == 1) {
        r.update_ret = EVP_MAC_update(ctx, message, sizeof(message));
    }
    if (r.update_ret == 1) {
        r.final1_ret = EVP_MAC_final(ctx, r.tag1, &r.tag1_len, sizeof(r.tag1));
    }
    if (r.final1_ret == 1) {
        r.final2_ret = EVP_MAC_final(ctx, r.tag2, &r.tag2_len, sizeof(r.tag2));
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return r;
}

static void run_algorithm(const char *cipher_name,
                          const unsigned char *key,
                          size_t key_len)
{
    struct path_a_result a;
    struct path_b_result b;
    struct path_c_result c;
    int tag_a_eq_tag_b;
    int tag_c1_eq_tag_c2;
    int tag_c2_eq_tag_a;

    a = run_path_a(cipher_name, key, key_len);
    b = run_path_b(cipher_name, key, key_len);
    c = run_path_c(cipher_name, key, key_len);

    tag_a_eq_tag_b = bytes_equal(a.tag, a.tag_len, b.tag, b.tag_len);
    tag_c1_eq_tag_c2 = bytes_equal(c.tag1, c.tag1_len, c.tag2, c.tag2_len);
    tag_c2_eq_tag_a = bytes_equal(c.tag2, c.tag2_len, a.tag, a.tag_len);

    printf("algorithm=%s\n", cipher_name);
    printf("key_len=%zu\n", key_len);
    printf("message_len=%zu\n", sizeof(message));

    printf("path_a_fetch_ok=%d\n", a.fetch_ok);
    printf("path_a_ctx_ok=%d\n", a.ctx_ok);
    printf("path_a_init_ret=%d\n", a.init_ret);
    printf("path_a_update_ret=%d\n", a.update_ret);
    printf("path_a_final_ret=%d\n", a.final_ret);
    printf("path_a_tag_len=%zu\n", a.tag_len);
    print_hex_field("tag_A", a.tag, a.tag_len);

    printf("path_b_fetch_ok=%d\n", b.fetch_ok);
    printf("path_b_ctx_ok=%d\n", b.ctx_ok);
    printf("path_b_init_ret=%d\n", b.init_ret);
    printf("path_b_update_ret=%d\n", b.update_ret);
    printf("path_b_length_query_ret=%d\n", b.length_query_ret);
    printf("path_b_output_final_ret=%d\n", b.output_final_ret);
    printf("path_b_length_query_len=%zu\n", b.length_query_len);
    printf("path_b_tag_len=%zu\n", b.tag_len);
    print_hex_field("tag_B", b.tag, b.tag_len);

    printf("path_c_fetch_ok=%d\n", c.fetch_ok);
    printf("path_c_ctx_ok=%d\n", c.ctx_ok);
    printf("path_c_init_ret=%d\n", c.init_ret);
    printf("path_c_update_ret=%d\n", c.update_ret);
    printf("path_c_final1_ret=%d\n", c.final1_ret);
    printf("path_c_final2_ret=%d\n", c.final2_ret);
    printf("path_c_tag1_len=%zu\n", c.tag1_len);
    printf("path_c_tag2_len=%zu\n", c.tag2_len);
    print_hex_field("tag_C1", c.tag1, c.tag1_len);
    print_hex_field("tag_C2", c.tag2, c.tag2_len);

    printf("tag_A_eq_tag_B=%d\n", tag_a_eq_tag_b);
    printf("tag_C1_eq_tag_C2=%d\n", tag_c1_eq_tag_c2);
    printf("tag_C2_eq_tag_A=%d\n", tag_c2_eq_tag_a);
    printf("--\n");
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

    run_algorithm("AES-128-CBC", key128, sizeof(key128));
    run_algorithm("AES-256-CBC", key256, sizeof(key256));

    ERR_print_errors_fp(stderr);
    return 0;
}

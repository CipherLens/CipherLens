#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include <stdio.h>
#include <string.h>

#define APPLICATION_REJECT "APPLICATION_REJECT"
#define APPLICATION_ACCEPTED_POST_FINISH_DATA "APPLICATION_ACCEPTED_POST_FINISH_DATA"

static const unsigned char authorized_prefix[] = "authorized-prefix";
static const unsigned char post_finish_data[] = "post-finish-data";

static void print_hex_field(const char *name, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", name);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void run_case(const char *algorithm,
                     const unsigned char *key,
                     size_t key_len)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned char tag_prefix[64] = {0};
    unsigned char tag_after_post_finish[64] = {0};
    size_t tag_prefix_len = 0;
    size_t tag_after_post_finish_len = 0;
    int setup_status = 0;
    int update_prefix_status = 0;
    int finish_status = -1;
    int post_finish_update_status = -1;
    int final_after_post_finish_status = -1;
    const char *application_decision = APPLICATION_REJECT;

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac != NULL) {
        ctx = EVP_MAC_CTX_new(mac);
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *) algorithm, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (ctx != NULL) {
        setup_status = EVP_MAC_init(ctx, key, key_len, params);
    }
    if (setup_status == 1) {
        update_prefix_status = EVP_MAC_update(
            ctx,
            authorized_prefix,
            strlen((const char *) authorized_prefix));
    }
    if (update_prefix_status == 1) {
        finish_status = EVP_MAC_final(
            ctx,
            tag_prefix,
            &tag_prefix_len,
            sizeof(tag_prefix));
    }

    if (finish_status == 1) {
        post_finish_update_status = EVP_MAC_update(
            ctx,
            post_finish_data,
            strlen((const char *) post_finish_data));
    }
    if (post_finish_update_status == 1) {
        final_after_post_finish_status = EVP_MAC_final(
            ctx,
            tag_after_post_finish,
            &tag_after_post_finish_len,
            sizeof(tag_after_post_finish));
        if (final_after_post_finish_status == 1) {
            application_decision = APPLICATION_ACCEPTED_POST_FINISH_DATA;
        }
    }

    printf("library=openssl\n");
    printf("algorithm=%s\n", algorithm);
    printf("setup_status=%d\n", setup_status);
    printf("update_prefix_status=%d\n", update_prefix_status);
    printf("finish_status=%d\n", finish_status);
    print_hex_field("tag_prefix", tag_prefix, tag_prefix_len);
    printf("post_finish_update_status=%d\n", post_finish_update_status);
    printf("final_after_post_finish_status=%d\n", final_after_post_finish_status);
    print_hex_field("tag_after_post_finish", tag_after_post_finish, tag_after_post_finish_len);
    printf("application_decision=%s\n", application_decision);
    printf("--\n");

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
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

    run_case("AES-128-CBC", key128, sizeof(key128));
    run_case("AES-256-CBC", key256, sizeof(key256));

    ERR_print_errors_fp(stderr);
    return 0;
}

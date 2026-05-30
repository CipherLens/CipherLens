#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

#define VALUE_LITERAL "[VALUE]"
#define TOLEN_VALUE [BUFLEN]
#define CANARY_SIZE_VALUE [CANARY_SIZE]
#define CANARY_BYTE 0xA5

static int parse_long_literal(const char *s, long *out)
{
    char *end = NULL;
    long v;

    if (s == NULL || out == NULL) {
        return 0;
    }

    v = strtol(s, &end, 10);
    if (end == s || *end != '\0') {
        return 0;
    }

    *out = v;
    return 1;
}

static int canary_corrupted(const unsigned char *canary, size_t canary_size)
{
    for (size_t i = 0; i < canary_size; i++) {
        if (canary[i] != CANARY_BYTE) {
            return 1;
        }
    }
    return 0;
}

static void print_buffer_prefix(const unsigned char *buf, size_t len)
{
    size_t limit = len < 16 ? len : 16;

    printf("output_prefix=");
    for (size_t i = 0; i < limit; i++) {
        printf("%02x", (unsigned) buf[i]);
    }
    printf("\n");
}

int main(void)
{
    BIGNUM *X = NULL;
    unsigned char *buf = NULL;
    unsigned char *canary = NULL;
    int ret = 0;
    long signed_value = 0;
    unsigned long magnitude = 0;
    size_t tolen = (size_t) TOLEN_VALUE;
    size_t canary_size = (size_t) CANARY_SIZE_VALUE;
    size_t total_len = tolen + canary_size;
    int exit_code = 0;

    setbuf(stdout, NULL);

    printf("OPENSSL_VERSION_TEXT=%s\n", OPENSSL_VERSION_TEXT);
    printf("template_mutation VALUE=%s\n", VALUE_LITERAL);
    printf("template_mutation BUFLEN=%zu\n", tolen);
    printf("template_mutation CANARY_SIZE=%zu\n", canary_size);

    if (!parse_long_literal(VALUE_LITERAL, &signed_value)) {
        printf("[ERROR] target VALUE parse failed.\n");
        return 2;
    }

    if (signed_value < 0) {
        magnitude = (unsigned long) (-signed_value);
    } else {
        magnitude = (unsigned long) signed_value;
    }

    if (canary_size == 0 || total_len < tolen) {
        printf("[ERROR] invalid output/canary sizing.\n");
        return 2;
    }

    buf = malloc(total_len);
    if (buf == NULL) {
        printf("[ERROR] output allocation failed.\n");
        return 2;
    }
    memset(buf, 0x42, total_len);
    canary = buf + tolen;
    memset(canary, CANARY_BYTE, canary_size);

    X = BN_new();
    if (X == NULL) {
        printf("[ERROR] BN_new failed.\n");
        exit_code = 2;
        goto cleanup;
    }

    if (!BN_set_word(X, magnitude)) {
        printf("[ERROR] BN_set_word failed.\n");
        exit_code = 2;
        goto cleanup;
    }

    if (signed_value < 0) {
        BN_set_negative(X, 1);
    }

    ret = BN_signed_bn2bin(X, buf, (int) tolen);

    printf("ret=%d\n", ret);
    print_buffer_prefix(buf, tolen);

    if (canary_corrupted(canary, canary_size)) {
        printf("[BUG] target overwrote canary after output buffer.\n");
        exit_code = 1;
        goto cleanup;
    }

    if (ret < 0) {
        printf("[OK] target rejected small output buffer and canary intact.\n");
        exit_code = 0;
        goto cleanup;
    }

    printf("[INFO] target serialized into provided buffer; canary intact.\n");
    exit_code = 0;

cleanup:
    BN_free(X);
    free(buf);
    return exit_code;
}

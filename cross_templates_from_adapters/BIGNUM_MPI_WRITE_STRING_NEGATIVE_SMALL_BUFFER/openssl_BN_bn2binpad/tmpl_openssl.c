#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#define BUFLEN [BUFLEN]
#define CANARY_SIZE [CANARY_SIZE]
#define CANARY_BYTE 0xA5

static int canary_corrupted(unsigned char *buf)
{
    for (size_t i = 0; i < CANARY_SIZE; i++) {
        if (buf[BUFLEN + i] != CANARY_BYTE) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    BIGNUM *X = NULL;
    unsigned char buf[BUFLEN + CANARY_SIZE];
    int ret = 0;
    long signed_value = [VALUE];
    unsigned long magnitude = 0;

    memset(buf, 0x42, sizeof(buf));
    memset(buf + BUFLEN, CANARY_BYTE, CANARY_SIZE);

    if (signed_value < 0) {
        magnitude = (unsigned long)(-signed_value);
    } else {
        magnitude = (unsigned long)signed_value;
    }

    /*
     * Adapter-generated initialization.
     */
    X = BN_new();

    if (X == NULL) {
        printf("target init failed\n");
        return 2;
    }

    /*
     * Adapter-generated input construction.
     */
    BN_set_word(X, abs(VALUE)); BN_set_negative(X, 1);

    /*
     * Adapter-generated trigger call.
     * target_api: BN_bn2binpad
     */
    unsigned char *buf = (unsigned char *)malloc(BUFLEN); BN_bn2binpad(X, buf, BUFLEN);

    printf("ret=%d\n", ret);
    printf("buf/canary prefix=");

    for (size_t i = 0; i < BUFLEN + 8 && i < sizeof(buf); i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {
            printf("%c", c);
        } else {
            printf("\\x%02x", c);
        }
    }
    printf("\n");

    if (canary_corrupted(buf)) {
        printf("[BUG] Canary corrupted: target API wrote beyond caller buffer.\n");
        free(buf); BN_free(X);
        return 1;
    }

    printf("[OK] Canary intact.\n");

    free(buf); BN_free(X);
    return 0;
}

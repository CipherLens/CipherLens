#include <stdio.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    const char *passphrase = "testpassword";
    FILE *fp = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int ok;
    int ret = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <test.p12>\n", argv[0]);
        return 2;
    }

    path = argv[1];
    fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("fopen");
        goto end;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    if (p12 == NULL) {
        fprintf(stderr, "d2i_PKCS12_fp failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ok = PKCS12_parse(p12, passphrase, &pkey, &cert, &ca);
    printf("PKCS12_parse returned %d\n", ok);
    if (ok != 1) {
        ERR_print_errors_fp(stderr);
    }

    ret = 0;

end:
    sk_X509_pop_free(ca, X509_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    PKCS12_free(p12);
    if (fp != NULL) {
        fclose(fp);
    }
    return ret;
}

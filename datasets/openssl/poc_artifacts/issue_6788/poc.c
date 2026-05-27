#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *bio = NULL;
    X509_CRL *crl = NULL;
    X509_NAME *issuer = NULL;
    int ret = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <crl.pem>\n", argv[0]);
        return 2;
    }

    path = argv[1];
    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    if (crl == NULL) {
        fprintf(stderr, "PEM_read_bio_X509_CRL failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    issuer = X509_CRL_get_issuer(crl);
    if (issuer == NULL) {
        fprintf(stderr, "X509_CRL_get_issuer returned NULL\n");
        goto end;
    }

    printf("CRL issuer: ");
    if (X509_NAME_print_ex_fp(stdout, issuer, 0, XN_FLAG_ONELINE) < 0) {
        fprintf(stderr, "\nX509_NAME_print_ex_fp failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    printf("\n");

    ret = 0;

end:
    X509_CRL_free(crl);
    BIO_free(bio);
    return ret;
}

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <servercert.pem>\n", argv[0]);
        return 2;
    }

    path = argv[1];

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        fprintf(stderr, "PEM_read_bio_X509 failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    printf("SSL server purpose: %d\n", X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0));
    printf("SSL client purpose: %d\n", X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 0));
    printf("Any purpose: %d\n", X509_check_purpose(cert, X509_PURPOSE_ANY, 0));

    ret = 0;

end:
    X509_free(cert);
    BIO_free(bio);
    return ret;
}

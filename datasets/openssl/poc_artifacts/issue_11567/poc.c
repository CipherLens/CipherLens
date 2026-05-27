#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cert.pem>\n", argv[0]);
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

    if (!X509_print_fp(stdout, cert)) {
        fprintf(stderr, "X509_print_fp failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ret = 0;

end:
    X509_free(cert);
    BIO_free(bio);
    return ret;
}

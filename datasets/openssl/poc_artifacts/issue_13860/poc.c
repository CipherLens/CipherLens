#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cert.der>\n", argv[0]);
        return 2;
    }

    path = argv[1];

    bio = BIO_new_file(path, "rb");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    cert = d2i_X509_bio(bio, NULL);
    if (cert == NULL) {
        fprintf(stderr, "d2i_X509_bio failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "X509_get_pubkey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (!PEM_write_PUBKEY(stdout, pkey)) {
        fprintf(stderr, "PEM_write_PUBKEY failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ret = 0;

end:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(bio);
    return ret;
}

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    const BIGNUM *n = NULL;
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

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "X509_get_pubkey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        fprintf(stderr, "EVP_PKEY_get1_RSA failed, certificate may not contain RSA key\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    RSA_get0_key(rsa, &n, NULL, NULL);
    if (n == NULL) {
        fprintf(stderr, "RSA modulus is NULL\n");
        goto end;
    }

    printf("Modulus=");
    BN_print_fp(stdout, n);
    printf("\n");

    ret = 0;

end:
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(bio);
    return ret;
}

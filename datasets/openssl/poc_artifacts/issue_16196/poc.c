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
    X509_REQ *req = NULL;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    const BIGNUM *n = NULL;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <request.csr>\n", argv[0]);
        return 2;
    }

    path = argv[1];

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (req == NULL) {
        fprintf(stderr, "PEM_read_bio_X509_REQ failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    pkey = X509_REQ_get_pubkey(req);
    if (pkey == NULL) {
        fprintf(stderr, "X509_REQ_get_pubkey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        fprintf(stderr, "EVP_PKEY_get1_RSA failed, request may not contain RSA key\n");
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
    X509_REQ_free(req);
    BIO_free(bio);
    return ret;
}

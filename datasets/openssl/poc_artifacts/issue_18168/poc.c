#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *in_path = NULL;
    const char *out_path = "rsa_out.pem";
    BIO *in = NULL;
    BIO *out = NULL;
    RSA *rsa = NULL;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <rsa_private_key.pem>\n", argv[0]);
        return 2;
    }

    in_path = argv[1];

    in = BIO_new_file(in_path, "r");
    if (in == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", in_path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);
    if (rsa == NULL) {
        fprintf(stderr, "PEM_read_bio_RSAPrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    out = BIO_new_file(out_path, "w");
    if (out == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", out_path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (!PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "PEM_write_bio_RSAPrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    printf("RSA private key was read and written to %s\n", out_path);
    ret = 0;

end:
    RSA_free(rsa);
    BIO_free(out);
    BIO_free(in);
    return ret;
}

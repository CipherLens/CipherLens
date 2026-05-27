#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static int read_file(const char *path, unsigned char **out, size_t *out_len)
{
    FILE *fp = NULL;
    long size;
    unsigned char *buf = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "fopen failed: %s\n", path);
        return 0;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 0;
    }

    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return 0;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return 0;
    }

    buf = malloc((size_t)size);
    if (buf == NULL && size > 0) {
        fclose(fp);
        return 0;
    }

    if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return 0;
    }

    fclose(fp);
    *out = buf;
    *out_len = (size_t)size;
    return 1;
}

static int write_public_key(EVP_PKEY *pkey, const char *path)
{
    BIO *out = BIO_new_file(path, "w");
    int ok;

    if (out == NULL) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    ok = PEM_write_bio_PUBKEY(out, pkey);
    BIO_free(out);
    return ok;
}

static int sm2_sign(EVP_PKEY *pkey,
                    const unsigned char *msg, size_t msg_len,
                    unsigned char **sig, size_t *sig_len)
{
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const char *id = "Alice";
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        goto end;
    }

    if (EVP_DigestSignInit(mctx, &pctx, EVP_sm3(), NULL, pkey) != 1) {
        goto end;
    }

    if (EVP_PKEY_CTX_set1_id(pctx, id, strlen(id)) != 1) {
        goto end;
    }

    if (EVP_DigestSign(mctx, NULL, sig_len, msg, msg_len) != 1) {
        goto end;
    }

    *sig = malloc(*sig_len);
    if (*sig == NULL) {
        goto end;
    }

    if (EVP_DigestSign(mctx, *sig, sig_len, msg, msg_len) != 1) {
        free(*sig);
        *sig = NULL;
        goto end;
    }

    ret = 1;

end:
    if (!ret) {
        ERR_print_errors_fp(stderr);
    }
    EVP_MD_CTX_free(mctx);
    return ret;
}

static int sm2_verify(EVP_PKEY *pkey,
                      const unsigned char *msg, size_t msg_len,
                      const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    const char *id = "Alice";
    int ret = 0;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        goto end;
    }

    if (EVP_DigestVerifyInit(mctx, &pctx, EVP_sm3(), NULL, pkey) != 1) {
        goto end;
    }

    if (EVP_PKEY_CTX_set1_id(pctx, id, strlen(id)) != 1) {
        goto end;
    }

    ret = EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len);

end:
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
    }
    EVP_MD_CTX_free(mctx);
    return ret == 1;
}

int main(int argc, char **argv)
{
    const char *key_path = NULL;
    const char *msg_path = NULL;
    BIO *key_bio = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *msg = NULL;
    size_t msg_len = 0;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int ret = 1;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <sm2_private_key.pem> <message_file>\n", argv[0]);
        return 2;
    }

    key_path = argv[1];
    msg_path = argv[2];

    key_bio = BIO_new_file(key_path, "r");
    if (key_bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", key_path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    pkey = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        fprintf(stderr, "PEM_read_bio_PrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (!write_public_key(pkey, "sm2_pub.pem")) {
        fprintf(stderr, "PEM_write_bio_PUBKEY failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (!read_file(msg_path, &msg, &msg_len)) {
        fprintf(stderr, "read_file failed: %s\n", msg_path);
        goto end;
    }

    if (!sm2_sign(pkey, msg, msg_len, &sig, &sig_len)) {
        fprintf(stderr, "SM2 signing failed\n");
        goto end;
    }

    if (!sm2_verify(pkey, msg, msg_len, sig, sig_len)) {
        fprintf(stderr, "SM2 verification failed\n");
        goto end;
    }

    printf("SM2 sign/verify succeeded, signature length = %zu\n", sig_len);
    ret = 0;

end:
    free(sig);
    free(msg);
    EVP_PKEY_free(pkey);
    BIO_free(key_bio);
    return ret;
}

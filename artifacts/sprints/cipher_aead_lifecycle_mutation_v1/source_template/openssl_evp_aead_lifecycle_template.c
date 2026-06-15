#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#ifndef AEAD_CASE_ID
#define AEAD_CASE_ID "unset_case_id"
#endif

#ifndef AEAD_CASE_NAME
#define AEAD_CASE_NAME "unset_case_name"
#endif

#ifndef AEAD_ALGORITHM
#define AEAD_ALGORITHM "aes-128-gcm"
#endif

#ifndef AEAD_MODE
#define AEAD_MODE "encrypt"
#endif

#ifndef AEAD_STATE_SEQUENCE
#define AEAD_STATE_SEQUENCE "unset_state_sequence"
#endif

static const unsigned char KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const unsigned char IV[12] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
};

static const unsigned char AAD[] = "codex-aead-aad";
static const unsigned char PLAINTEXT[] = "codex-aead-lifecycle-plaintext";
static const unsigned char EXTRA[] = "extra-after-terminal-state";

static void print_hex(const char *label, const unsigned char *buf, int len)
{
    int i;
    printf("%s=", label);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static const EVP_CIPHER *select_cipher(void)
{
    if (strcmp(AEAD_ALGORITHM, "aes-128-gcm") == 0)
        return EVP_aes_128_gcm();
    return EVP_aes_128_gcm();
}

static int encrypt_reference(unsigned char *ciphertext, int *ciphertext_len,
                             unsigned char *tag, int tag_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int ret = 0;
    int outlen = 0;
    int total = 0;

    if (ctx == NULL) {
        printf("REF_STEP=EVP_CIPHER_CTX_new ret=0\n");
        return 0;
    }
    printf("REF_STEP=EVP_CIPHER_CTX_new ret=1\n");

    ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
    printf("REF_STEP=EncryptInit ret=%d\n", ret);
    if (ret != 1)
        goto done;

    ret = EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
    printf("REF_STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
    if (ret != 1)
        goto done;

    ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT,
                            (int) strlen((const char *) PLAINTEXT));
    printf("REF_STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
    if (ret != 1)
        goto done;
    total += outlen;

    ret = EVP_EncryptFinal_ex(ctx, ciphertext + total, &outlen);
    printf("REF_STEP=Final ret=%d outlen=%d\n", ret, outlen);
    if (ret != 1)
        goto done;
    total += outlen;

    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag);
    printf("REF_STEP=GetTag ret=%d tag_len=%d\n", ret, tag_len);
    if (ret != 1)
        goto done;

    *ciphertext_len = total;
    print_hex("REF_CIPHERTEXT", ciphertext, total);
    print_hex("REF_TAG", tag, tag_len);

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret == 1;
}

static int run_selected_case(void)
{
AEAD_CASE_BODY
}

int main(void)
{
    int ret;

    printf("OPENSSL_VERSION=%s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("CASE_ID=%s\n", AEAD_CASE_ID);
    printf("CASE_NAME=%s\n", AEAD_CASE_NAME);
    printf("ALGORITHM=%s\n", AEAD_ALGORITHM);
    printf("MODE=%s\n", AEAD_MODE);
    printf("STATE_SEQUENCE=%s\n", AEAD_STATE_SEQUENCE);

    ret = run_selected_case();
    printf("HARNESS_RETURN=%d\n", ret);
    fflush(stdout);
    return ret;
}

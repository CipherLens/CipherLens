#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define BLOCK_SIZE [INPUT_LEN]
#define PADDING_BYTE_VALUE 0x[PADDING_BYTE]

static int encrypt_one_block_no_padding(const unsigned char key[16],
                                        const unsigned char iv[16],
                                        const unsigned char plaintext[BLOCK_SIZE],
                                        unsigned char ciphertext[BLOCK_SIZE])
{
    EVP_CIPHER_CTX *enc_ctx = NULL;
    unsigned char tmp[64];
    int enc_update_len = 0;
    int enc_final_len = 0;
    int ok = 0;

    memset(tmp, 0, sizeof(tmp));

    enc_ctx = EVP_CIPHER_CTX_new();
    if (enc_ctx == NULL) {
        printf("[ERROR] EVP_CIPHER_CTX_new failed for encryption.\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_cbc(), NULL, key, iv) <= 0) {
        printf("[ERROR] EVP_EncryptInit_ex failed.\n");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_set_padding(enc_ctx, 0) <= 0) {
        printf("[ERROR] EVP_CIPHER_CTX_set_padding encrypt none failed.\n");
        goto cleanup;
    }

    if (EVP_EncryptUpdate(enc_ctx, tmp, &enc_update_len, plaintext, BLOCK_SIZE) <= 0) {
        printf("[ERROR] EVP_EncryptUpdate failed.\n");
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(enc_ctx, tmp + enc_update_len, &enc_final_len) <= 0) {
        printf("[ERROR] EVP_EncryptFinal_ex failed.\n");
        goto cleanup;
    }

    if (enc_update_len + enc_final_len != BLOCK_SIZE) {
        printf("[ERROR] unexpected encrypted length: %d\n", enc_update_len + enc_final_len);
        goto cleanup;
    }

    memcpy(ciphertext, tmp, BLOCK_SIZE);
    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(enc_ctx);
    return ok ? 0 : -1;
}

int main(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char input[BLOCK_SIZE];
    unsigned char out[64];
    unsigned char bad_plain[BLOCK_SIZE];
    int input_len = BLOCK_SIZE;
    int update_len = 0;
    int final_len = 0;
    int ret = 0;

    setbuf(stdout, NULL);

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(input, 0, sizeof(input));
    memset(out, 0, sizeof(out));
    memset(bad_plain, 0x41, sizeof(bad_plain));
    bad_plain[BLOCK_SIZE - 1] = (unsigned char) PADDING_BYTE_VALUE;

    if (encrypt_one_block_no_padding(key, iv, bad_plain, input) != 0) {
        printf("[ERROR] invalid-padding input construction failed.\n");
        return 2;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("[ERROR] EVP_CIPHER_CTX_new failed.\n");
        return 2;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) <= 0) {
        printf("[ERROR] EVP_DecryptInit_ex failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }

    if (EVP_CIPHER_CTX_set_padding(ctx, 1) <= 0) {
        printf("[ERROR] EVP_CIPHER_CTX_set_padding failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }

    if (EVP_DecryptUpdate(ctx, out, &update_len, input, input_len) <= 0) {
        printf("[ERROR] EVP_DecryptUpdate failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }

    final_len = 0;
    ret = EVP_DecryptFinal_ex(ctx, out + update_len, &final_len);

    printf("template_mutation PADDING_BYTE=%02x\n", (unsigned) PADDING_BYTE_VALUE);
    printf("template_mutation INPUT_LEN=%d\n", BLOCK_SIZE);
    printf("EVP_DecryptFinal_ex ret=%d\n", ret);
    printf("update_len=%d\n", update_len);
    printf("final_len=%d\n", final_len);

    if (ret <= 0 && final_len == 0) {
        printf("[OK] target rejected invalid padding and final_len remained zero. ret=%d final_len=%d\n",
               ret, final_len);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (ret <= 0 && final_len != 0) {
        printf("[BUG] target rejected invalid padding but final_len was polluted. ret=%d final_len=%d\n",
               ret, final_len);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    printf("[TRIAGE] target accepted invalid padding unexpectedly. ret=%d final_len=%d\n",
           ret, final_len);
    EVP_CIPHER_CTX_free(ctx);
    return 2;
}

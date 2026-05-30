#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mbedtls/cipher.h"

#define BLOCK_SIZE 16

static int encrypt_one_block_no_padding(const unsigned char key[16],
                                        const unsigned char iv[16],
                                        const unsigned char plaintext[16],
                                        unsigned char ciphertext[16])
{
    int ret;
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *cipher_info;
    unsigned char local_iv[16];
    unsigned char tmp[32];
    size_t olen1 = 0;
    size_t olen2 = 0;

    memcpy(local_iv, iv, 16);
    memset(tmp, 0, sizeof(tmp));

    mbedtls_cipher_init(&ctx);

    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    if (cipher_info == NULL) {
        printf("cipher_info AES_128_CBC failed\n");
        return -1;
    }

    ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        printf("encrypt setup failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_setkey(&ctx, key, 128, MBEDTLS_ENCRYPT);
    if (ret != 0) {
        printf("encrypt setkey failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
    if (ret != 0) {
        printf("encrypt set padding none failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_set_iv(&ctx, local_iv, 16);
    if (ret != 0) {
        printf("encrypt set iv failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_reset(&ctx);
    if (ret != 0) {
        printf("encrypt reset failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_update(&ctx, plaintext, BLOCK_SIZE, tmp, &olen1);
    if (ret != 0) {
        printf("encrypt update failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_finish(&ctx, tmp + olen1, &olen2);
    if (ret != 0) {
        printf("encrypt finish failed: %d\n", ret);
        goto cleanup;
    }

    if (olen1 + olen2 != BLOCK_SIZE) {
        printf("unexpected encrypted length: %zu\n", olen1 + olen2);
        ret = -2;
        goto cleanup;
    }

    memcpy(ciphertext, tmp, BLOCK_SIZE);
    ret = 0;

cleanup:
    mbedtls_cipher_free(&ctx);
    return ret;
}

int main(void)
{
    int ret;
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char ciphertext[BLOCK_SIZE];
    unsigned char output[BLOCK_SIZE * 2];

    /*
     * This plaintext block has invalid PKCS#7 padding:
     *
     * input_len   = 16
     * padding_len = 0x80 = 128
     *
     * Buggy behavior:
     *   data_len = input_len - padding_len
     *            = 16 - 128
     *            = huge size_t value
     *
     * Fixed behavior:
     *   padding_len > input_len is rejected before data_len assignment.
     */
    unsigned char bad_plain[BLOCK_SIZE] = {
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x80
    };

    size_t update_olen = 0;
    size_t finish_olen = 0;

    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *cipher_info;

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(output, 0, sizeof(output));

    ret = encrypt_one_block_no_padding(key, iv, bad_plain, ciphertext);
    if (ret != 0) {
        printf("encrypt_one_block_no_padding failed: %d\n", ret);
        return 2;
    }

    mbedtls_cipher_init(&ctx);

    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    if (cipher_info == NULL) {
        printf("cipher_info AES_128_CBC failed\n");
        return 2;
    }

    ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        printf("decrypt setup failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_setkey(&ctx, key, 128, MBEDTLS_DECRYPT);
    if (ret != 0) {
        printf("decrypt setkey failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7);
    if (ret != 0) {
        printf("decrypt set padding pkcs7 failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_set_iv(&ctx, iv, sizeof(iv));
    if (ret != 0) {
        printf("decrypt set iv failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_reset(&ctx);
    if (ret != 0) {
        printf("decrypt reset failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_cipher_update(&ctx,
                                ciphertext,
                                sizeof(ciphertext),
                                output,
                                &update_olen);
    if (ret != 0) {
        printf("decrypt update failed: %d\n", ret);
        goto cleanup;
    }

    finish_olen = 0;

    ret = mbedtls_cipher_finish(&ctx,
                                output + update_olen,
                                &finish_olen);

    printf("cipher_finish ret=%d\n", ret);
    printf("expected ret=%d\n", MBEDTLS_ERR_CIPHER_INVALID_PADDING);
    printf("update_olen=%zu\n", update_olen);
    printf("finish_olen=%zu\n", finish_olen);

    if (ret == MBEDTLS_ERR_CIPHER_INVALID_PADDING && finish_olen == 0) {
        printf("[OK] fixed behavior: invalid padding rejected and outlen remains zero.\n");
    } else if (ret == MBEDTLS_ERR_CIPHER_INVALID_PADDING && finish_olen != 0) {
        printf("[BUG] invalid padding rejected but outlen is unsafe/nonzero.\n");
    } else {
        printf("[INFO] unexpected behavior: ret=%d finish_olen=%zu\n", ret, finish_olen);
    }

cleanup:
    mbedtls_cipher_free(&ctx);
    return 0;
}

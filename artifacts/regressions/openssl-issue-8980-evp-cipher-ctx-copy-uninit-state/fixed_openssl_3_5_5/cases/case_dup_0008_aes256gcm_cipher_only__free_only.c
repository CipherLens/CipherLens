/*
 * Case 0008: aes256gcm / cipher_only_no_key_no_iv / free_only
 * Pattern: OPENSSL-ISSUE-8980 (EVP_CIPHER_CTX_dup variant, OpenSSL 3.5.5)
 * Oracle type: crash_sanitizer_oracle
 *
 * cipher_algorithm : EVP_aes_256_gcm()
 * init_state       : cipher_only_no_key_no_iv
 * post_dup_action  : free_only
 */
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const unsigned char key16[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char key24[24] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
    };
    static const unsigned char iv12[12] = {
        0x00,0x01,0x02,0x03,0x04,0x05,
        0x06,0x07,0x08,0x09,0x0a,0x0b
    };
    static const unsigned char plain[16] = "Hello, OpenSSL!\0";

    (void)key24;

    EVP_CIPHER_CTX *src = NULL;
    EVP_CIPHER_CTX *dst = NULL;
    const EVP_CIPHER *cipher = NULL;

    src = EVP_CIPHER_CTX_new();
    if (src == NULL) {
        fprintf(stderr, "[ERROR] EVP_CIPHER_CTX_new failed\n");
        goto end;
    }

    cipher = EVP_aes_256_gcm();
    if (cipher == NULL) {
        fprintf(stderr, "[ERROR] cipher fetch failed\n");
        goto end;
    }

    /* partial init: cipher only, no key, no IV */
    if (EVP_EncryptInit_ex(src, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EncryptInit_ex failed\n");
        goto end;
    }

    /* Core trigger: EVP_CIPHER_CTX_dup on context in state: cipher_only_no_key_no_iv */
    dst = EVP_CIPHER_CTX_dup(src);
    printf("[DUP] dst=%s\n", dst ? "non-NULL" : "NULL");

    /* post-dup: just free */
    /* nothing extra */

    if (dst == NULL) {
        printf("[VERDICT] safe_fixed_behavior (NULL returned)\n");
    } else {
        printf("[VERDICT] safe_fixed_behavior (non-NULL, no crash)\n");
    }

end:
    EVP_CIPHER_CTX_free(dst);
    EVP_CIPHER_CTX_free(src);
    return 0;
}

/*
 * Auto campaign EVP CCM lifecycle harness.
 * Local state-order mutation only; no exploit chain or DER consumption oracle.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static int ccm_encrypt_once(const unsigned char *pt, int pt_len,
                            unsigned char *ct, unsigned char *tag, int tag_len)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int ok = 0;
    if (ctx == NULL) return 0;
    ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL) == 1;
    ok = ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, NULL, &len, NULL, pt_len) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)) == 1;
    if (pt_len > 0)
        ok = ok && EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) == 1;
    ok = ok && EVP_EncryptFinal_ex(ctx, ct + len, &len) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int ccm_decrypt_once(const unsigned char *ct, int ct_len,
                            const unsigned char *tag, int tag_len, int set_tag)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    unsigned char out[64] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int ok = 0;
    if (ctx == NULL) return 0;
    ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL) == 1;
    if (set_tag)
        ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, (void *)tag) == 1;
    ok = ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1;
    ok = ok && EVP_DecryptUpdate(ctx, NULL, &len, NULL, ct_len) == 1;
    ok = ok && EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad)) == 1;
    if (ct_len > 0)
        ok = ok && EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main(void)
{
    const char *case_id = "ccm_truncated_tag_length";
    const char *expected_behavior = "observation";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int enc_ok = 0, dec_ok = 0;
    int ret1 = 0, ret2 = 0, ret3 = 0, ret4 = 0, ret5 = 0, ret6 = 0, ret7 = 0;
    int out_len = 0;
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    unsigned char plaintext[] = "local ccm msg";
    unsigned char ciphertext[64] = {0};
    unsigned char out[64] = {0};
    unsigned char tag[16] = {0};
    int plaintext_len = (int)(sizeof(plaintext) - 1);
    EVP_CIPHER_CTX *ctx = NULL;


    enc_ok = ccm_encrypt_once(plaintext, plaintext_len, ciphertext, tag, 8);
    dec_ok = ccm_decrypt_once(ciphertext, plaintext_len, tag, 8, 1);
    actual_behavior = (enc_ok && dec_ok) ? "success" : "error";

    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:

    printf("ORACLE_EVENT family=cipher_aead_lifecycle_ccm\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT semantic_mismatch=%d\n", semantic_mismatch);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

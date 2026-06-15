/*
 * Auto campaign EVP_CIPHER_CTX_copy lifecycle harness.
 * Unsafe self-copy and use-after-free cases are recorded as disabled seeds only.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static int init_gcm(EVP_CIPHER_CTX *ctx)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    return EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) == 1;
}

int main(void)
{
    const char *case_id = "ctx_copy_gcm_after_plaintext_before_final";
    const char *expected_behavior = "success";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret1 = 0, ret2 = 0, ret3 = 0, ret4 = 0;
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    unsigned char plaintext[] = "local gcm copy msg";
    unsigned char out[128] = {0};
    int plaintext_len = (int)(sizeof(plaintext) - 1);
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *src = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dst = EVP_CIPHER_CTX_new();

    if (src == NULL || dst == NULL)
        goto done;
    
    ret1 = init_gcm(src);
    ret3 = EVP_EncryptUpdate(src, out, &out_len, plaintext, plaintext_len);
    ret2 = EVP_CIPHER_CTX_copy(dst, src);
    actual_behavior = (ret1 && ret3 == 1 && ret2 == 1) ? "success" : "error";

    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:

    printf("ORACLE_EVENT family=cipher_aead_lifecycle_ctx_copy\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT semantic_mismatch=%d\n", semantic_mismatch);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    EVP_CIPHER_CTX_free(src);
    EVP_CIPHER_CTX_free(dst);
    return 0;
}

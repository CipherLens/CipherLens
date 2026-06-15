/*
 * Auto campaign EVP AEAD GCM lifecycle harness.
 * Observation cases are not vulnerability claims.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

int main(void)
{
    const char *case_id = "cipher_aead_gcm_reset_reuse_observation";
    const char *expected_behavior = "observation";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret_init = 0, ret_update = 0, ret_final = 0, ret_tag = 0, ret_reset = 0, ret_second_init = 0;
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char tag[16] = {0};
    unsigned char plaintext[] = "local gcm message";
    unsigned char out[128] = {0};
    int plaintext_len = (int)(sizeof(plaintext) - 1);
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        goto done;

    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, out, &out_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);
    ret_reset = EVP_CIPHER_CTX_reset(ctx);
    ret_second_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 &&
                       ret_reset == 1 && ret_second_init == 1) ? "success" : "error";

    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:
    printf("ORACLE_EVENT family=cipher_aead_lifecycle\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

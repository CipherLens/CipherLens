#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define TAG_LENGTH [TAG_LENGTH]

/*
 * CCM allows only even tag lengths from 4 to 16.
 * Returns 1 if valid, 0 if invalid.
 */
static int is_valid_ccm_tag_length(int tlen)
{
    return (tlen >= 4 && tlen <= 16 && (tlen % 2 == 0));
}

int main(void)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;
    int init_ret = 0;

    setbuf(stdout, NULL);

    printf("template_mutation TAG_LENGTH=%d\n", TAG_LENGTH);

    /*
     * Source vulnerability: PSA psa_aead_setup() accepted invalid CCM tag
     * length 3 without validation. Fixed by psa_validate_tag_length().
     * Target probe: EVP_CIPHER_CTX_ctrl with EVP_CTRL_CCM_SET_TAG and
     * invalid tag length. Oracle: ctrl return code (0=rejected, 1=accepted).
     */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("[ERROR] EVP_CIPHER_CTX_new failed.\n");
        return 2;
    }

    init_ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    printf("EVP_DecryptInit_ex ret=%d\n", init_ret);
    if (init_ret <= 0) {
        printf("[INFO] invalid_parameter_setup_oracle: EVP_DecryptInit_ex failed (init_ret=%d).\n",
               init_ret);
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }

    printf("calling EVP_CIPHER_CTX_ctrl(EVP_CTRL_CCM_SET_TAG, %d)...\n", TAG_LENGTH);
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, TAG_LENGTH, NULL);
    printf("EVP_CIPHER_CTX_ctrl ret=%d\n", ret);

    if (!is_valid_ccm_tag_length(TAG_LENGTH)) {
        if (ret > 0) {
            printf("[BUG] target accepted invalid CCM tag length=%d at ctrl.\n", TAG_LENGTH);
        } else {
            printf("[OK] target rejected invalid CCM tag length=%d.\n", TAG_LENGTH);
        }
    } else {
        if (ret > 0) {
            printf("[OK] target accepted valid CCM tag length=%d.\n", TAG_LENGTH);
        } else {
            printf("[INFO] target rejected valid CCM tag length=%d (needs triage).\n", TAG_LENGTH);
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

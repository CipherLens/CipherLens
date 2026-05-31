/*
 * Case: case_dup_0000_openssl_3_5_5
 * Template: EVP_CIPHER_CTX_DUP_UNINIT_STATE
 * Pattern: OPENSSL-ISSUE-8980 (same-library equivalent API variant)
 * Source library: OpenSSL 3.5.5
 * Vulnerability class: evp_context_state_lifecycle
 * Oracle type: crash_sanitizer_oracle
 *
 * Slot bindings:
 *   CIPHER_ALGORITHM = EVP_aes_128_gcm()
 *   SRC_KEY_BYTES    = NULL  (no key — partial init trigger)
 *   SRC_IV_BYTES     = NULL  (no IV  — partial init trigger)
 *
 * Expected behavior on OpenSSL 3.5.5 (safe/fixed):
 *   EVP_CIPHER_CTX_dup on a partially-initialized AES-GCM context returns
 *   either NULL (safe rejection) or a valid ctx (safe copy), without any
 *   crash, ASAN signal, or Valgrind uninitialized-memory error.
 *
 * In OpenSSL 1.0.2 (buggy), the equivalent EVP_CIPHER_CTX_copy path would
 * access uninitialized GCM state (gcm.key pointer) due to missing NULL guard.
 */

#include <openssl/evp.h>
#include <stdio.h>

int main(void)
{
    EVP_CIPHER_CTX *src = NULL;
    EVP_CIPHER_CTX *dst = NULL;
    const EVP_CIPHER *cipher = NULL;

    src = EVP_CIPHER_CTX_new();
    if (src == NULL) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto end;
    }

    cipher = EVP_aes_128_gcm();
    if (cipher == NULL) {
        fprintf(stderr, "EVP_aes_128_gcm failed\n");
        goto end;
    }

    /*
     * Partial initialization: cipher algorithm associated,
     * but NO key (NULL) and NO IV (NULL).
     * In OpenSSL 1.0.2, EVP_CIPHER_CTX_copy on this state accesses
     * uninitialized gcm.key pointer → crash / uninit memory read.
     * In OpenSSL 3.5.5, EVP_CTRL_COPY has NULL guard → safe behavior.
     */
    if (EVP_EncryptInit_ex(src, cipher, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        goto end;
    }

    /*
     * Core trigger: EVP_CIPHER_CTX_dup on partially-initialized AES-GCM context.
     * Internally: EVP_CIPHER_CTX_new() + EVP_CIPHER_CTX_copy(out, in)
     * → invokes EVP_CTRL_COPY handler for AES-GCM.
     */
    dst = EVP_CIPHER_CTX_dup(src);

    if (dst == NULL) {
        printf("[RESULT] EVP_CIPHER_CTX_dup returned NULL "
               "(safe rejection of partial context).\n");
        printf("[VERDICT] safe_fixed_behavior\n");
    } else {
        printf("[RESULT] EVP_CIPHER_CTX_dup returned non-NULL "
               "(safe copy of partial context succeeded).\n");
        printf("[VERDICT] safe_fixed_behavior\n");
    }

end:
    EVP_CIPHER_CTX_free(dst);
    EVP_CIPHER_CTX_free(src);
    return 0;
}

/*
 * Template: EVP_MAC_GET_SIZE_UNINIT_LIFECYCLE
 * Source pattern: OPENSSL-ISSUE-22842
 * Source library: OpenSSL
 * Vulnerability class: mac_context_uninitialized_state_query
 * Oracle type: mac_context_size_lifecycle_oracle
 *
 * STATE_A: EVP_MAC_CTX_get_mac_size(ctx) before EVP_MAC_init.
 * STATE_B: EVP_MAC_init(ctx, key, ..., digest=SHA256), then get_mac_size.
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>

#define EXPECTED_MAC_SIZE [EXPECTED_MAC_SIZE]

static void bug_signal_handler(int signo)
{
    fprintf(stderr, "[BUG] mac_context_lifecycle: crash or sanitizer signal: %d\n", signo);
    fflush(stderr);
    _Exit(128 + signo);
}

int main(void)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    const unsigned char key[] = [KEY_BYTES];
    size_t pre_size = 0;
    size_t post_size = 0;
    int init_ok = 0;
    int ret = 1;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);

    printf("template_mutation MAC_NAME=%s DIGEST_NAME=%s KEY_LEN=%d EXPECTED_MAC_SIZE=%d\n",
           "[MAC_NAME]", "[DIGEST_NAME]", [KEY_LEN], EXPECTED_MAC_SIZE);

    mac = EVP_MAC_fetch(NULL, "[MAC_NAME]", NULL);
    if (mac == NULL) {
        fprintf(stderr, "[TRIAGE] mac_context_lifecycle: unexpected size/state: EVP_MAC_fetch failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        fprintf(stderr, "[TRIAGE] mac_context_lifecycle: unexpected size/state: EVP_MAC_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /*
     * STATE_A: the original bug path queries the MAC size before EVP_MAC_init
     * initializes provider algctx state. Safe behavior is no crash.
     */
    pre_size = EVP_MAC_CTX_get_mac_size(ctx);
    printf("STATE_A pre-init EVP_MAC_CTX_get_mac_size returned %zu\n", pre_size);
    if (pre_size == 0) {
        printf("[OK] mac_context_lifecycle: pre-setup operation rejected safely\n");
    } else {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: pre-init size=%zu\n", pre_size);
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "[DIGEST_NAME]", 0);
    params[1] = OSSL_PARAM_construct_end();

    init_ok = EVP_MAC_init(ctx, key, [KEY_LEN], params);
    printf("STATE_B EVP_MAC_init returned %d\n", init_ok);
    if (init_ok != 1) {
        fprintf(stderr, "[TRIAGE] mac_context_lifecycle: unexpected size/state: EVP_MAC_init failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    post_size = EVP_MAC_CTX_get_mac_size(ctx);
    printf("STATE_B post-init EVP_MAC_CTX_get_mac_size returned %zu\n", post_size);
    if (post_size == EXPECTED_MAC_SIZE) {
        printf("[OK] mac_context_lifecycle: initialized size matched\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: post-init size=%zu expected=%d\n",
               post_size, EXPECTED_MAC_SIZE);
    }

end:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

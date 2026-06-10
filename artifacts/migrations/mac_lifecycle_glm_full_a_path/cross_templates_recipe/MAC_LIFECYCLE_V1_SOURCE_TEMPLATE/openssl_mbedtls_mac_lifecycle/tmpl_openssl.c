#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#define LIFECYCLE_SEQUENCE_ID [LIFECYCLE_SEQUENCE_ID]
#define MAC_BUFFER_LEN 32

/*
 * Harness: mac_lifecycle
 * Oracle: lifecycle_state_transition_semantic_oracle
 * Library: OpenSSL EVP_MAC
 *
 * The sequence id is rendered by template_maker.render_cases:
 *   0 normal_init_update_final
 *   1 repeated_final
 *   2 update_after_final
 *   3 abort_then_update (projected as free-then-update guard)
 */

static void bug_signal_handler(int signo)
{
    fprintf(stderr, "[BUG] mac_lifecycle: crash or sanitizer signal: %d\n", signo);
    fflush(stderr);
    _Exit(128 + signo);
}

static const char *sequence_name(void)
{
    switch (LIFECYCLE_SEQUENCE_ID) {
    case 0: return "normal_init_update_final";
    case 1: return "repeated_final";
    case 2: return "update_after_final";
    case 3: return "abort_then_update";
    default: return "unknown";
    }
}

int main(void)
{
    static const unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char msg[] = "mac-lifecycle-message";
    unsigned char mac[MAC_BUFFER_LEN];
    size_t mac_len = 0;
    EVP_MAC *mac_impl = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    int init_ret = 0;
    int update_ret = 0;
    int final_ret = 0;
    int after_ret = 0;
    int ret = 0;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);
    memset(mac, 0, sizeof(mac));

    printf("template_mutation LIFECYCLE_SEQUENCE_ID=%d sequence=%s\n",
           LIFECYCLE_SEQUENCE_ID, sequence_name());

    mac_impl = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac_impl == NULL) {
        printf("[TRIAGE] mac_lifecycle: OpenSSL MAC fetch failed for CMAC\n");
        return 2;
    }

    ctx = EVP_MAC_CTX_new(mac_impl);
    if (ctx == NULL) {
        printf("[TRIAGE] mac_lifecycle: OpenSSL MAC ctx allocation failed\n");
        EVP_MAC_free(mac_impl);
        return 2;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();

    init_ret = EVP_MAC_init(ctx, key, sizeof(key), params);
    update_ret = init_ret > 0 ? EVP_MAC_update(ctx, msg, sizeof(msg) - 1) : 0;
    final_ret = update_ret > 0 ? EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac)) : 0;
    printf("openssl init_ret=%d update_ret=%d final_ret=%d mac_len=%zu\n",
           init_ret, update_ret, final_ret, mac_len);

    if (init_ret <= 0 || update_ret <= 0 || final_ret <= 0) {
        printf("[TRIAGE] mac_lifecycle: normal setup/update/final failed before state transition\n");
        ret = 2;
        goto end;
    }

    if (LIFECYCLE_SEQUENCE_ID == 0) {
        printf("[OK] mac_lifecycle: normal_init_update_final completed successfully\n");
        ret = 0;
    } else if (LIFECYCLE_SEQUENCE_ID == 1) {
        mac_len = 0;
        after_ret = EVP_MAC_final(ctx, mac, &mac_len, sizeof(mac));
        printf("openssl repeated_final ret=%d mac_len=%zu\n", after_ret, mac_len);
        if (after_ret <= 0) {
            printf("[OK] mac_lifecycle: repeated_final rejected after terminal finalization\n");
        } else {
            printf("[TRIAGE] mac_lifecycle: repeated_final accepted after terminal finalization\n");
        }
        ret = 0;
    } else if (LIFECYCLE_SEQUENCE_ID == 2) {
        after_ret = EVP_MAC_update(ctx, msg, sizeof(msg) - 1);
        printf("openssl update_after_final ret=%d\n", after_ret);
        if (after_ret <= 0) {
            printf("[OK] mac_lifecycle: update_after_final rejected after terminal finalization\n");
        } else {
            printf("[TRIAGE] mac_lifecycle: update_after_final accepted after terminal finalization\n");
        }
        ret = 0;
    } else if (LIFECYCLE_SEQUENCE_ID == 3) {
        EVP_MAC_CTX_free(ctx);
        ctx = NULL;
        printf("[OK] mac_lifecycle: abort_then_update projected as no-call-after-free guard\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_lifecycle: unknown lifecycle sequence id=%d\n", LIFECYCLE_SEQUENCE_ID);
        ret = 2;
    }

end:
    if (ctx != NULL)
        EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac_impl);
    return ret;
}

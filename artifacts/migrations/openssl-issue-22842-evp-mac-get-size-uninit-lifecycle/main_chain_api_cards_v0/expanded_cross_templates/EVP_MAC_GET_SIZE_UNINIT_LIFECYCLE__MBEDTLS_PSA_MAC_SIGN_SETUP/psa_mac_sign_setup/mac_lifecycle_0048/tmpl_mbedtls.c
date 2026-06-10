#include <psa/crypto.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#define KEY_LEN 17
#define MESSAGE_LEN 21
#define MAC_LEN 32

/*
 * Harness: object_state_lifecycle
 * Oracle: mac_context_size_lifecycle_oracle
 * Target API: psa_mac_sign_setup
 *
 * This is an object lifecycle semantic projection of OpenSSL issue_22842.
 * It validates PSA MAC operation safety before setup and after normal setup;
 * it does not reproduce OpenSSL provider algctx internals.
 */

static void bug_signal_handler(int signo)
{
    fprintf(stderr, "[BUG] mac_context_lifecycle: crash or sanitizer signal: %d\n", signo);
    fflush(stderr);
    _Exit(128 + signo);
}

static void print_psa_status(const char *label, psa_status_t status)
{
    printf("%s status=%d\n", label, (int) status);
}

int main(void)
{
    static const unsigned char key_bytes[] = "rag-seed-hmac-key";
    static const unsigned char message[] = "mac lifecycle message";
    unsigned char mac[MAC_LEN];
    size_t mac_length = 0;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_mac_operation_t operation_pre = PSA_MAC_OPERATION_INIT;
    psa_mac_operation_t operation_post = PSA_MAC_OPERATION_INIT;
    int ret = 1;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);
    memset(mac, 0, sizeof(mac));

    printf("template_mutation PSA_ALG=%s KEY_LEN=%d MESSAGE_LEN=%d MAC_LEN=%d\n",
           "PSA_ALG_HMAC(PSA_ALG_SHA_256)", KEY_LEN, MESSAGE_LEN, MAC_LEN);

    status = psa_crypto_init();
    print_psa_status("psa_crypto_init", status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: psa_crypto_init failed\n");
        goto end;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    status = psa_import_key(&attributes, key_bytes, KEY_LEN, &key_id);
    print_psa_status("psa_import_key", status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: psa_import_key failed\n");
        goto end;
    }

    /*
     * STATE_A: use a fresh operation before psa_mac_sign_setup. Safe behavior
     * is rejection without crash. This operation is aborted immediately.
     */
    status = psa_mac_update(&operation_pre, message, MESSAGE_LEN);
    print_psa_status("pre-setup psa_mac_update", status);
    if (status != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: pre-setup operation rejected safely\n");
    } else {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: pre-setup MAC update succeeded\n");
    }
    psa_mac_abort(&operation_pre);

    /*
     * STATE_B: independent initialized operation.
     */
    status = psa_mac_sign_setup(&operation_post, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    print_psa_status("psa_mac_sign_setup", status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: psa_mac_sign_setup failed\n");
        goto end;
    }

    status = psa_mac_update(&operation_post, message, MESSAGE_LEN);
    print_psa_status("post-setup psa_mac_update", status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: post-setup MAC update failed\n");
        goto end;
    }

    status = psa_mac_sign_finish(&operation_post, mac, MAC_LEN, &mac_length);
    print_psa_status("psa_mac_sign_finish", status);
    printf("psa_mac_sign_finish mac_length=%zu\n", mac_length);
    if (status == PSA_SUCCESS && mac_length > 0 && mac_length <= MAC_LEN) {
        printf("[OK] mac_context_lifecycle: initialized MAC operation completed\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: finish status=%d mac_length=%zu\n",
               (int) status, mac_length);
    }

end:
    psa_mac_abort(&operation_pre);
    psa_mac_abort(&operation_post);
    if (key_id != 0)
        psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
    return ret;
}

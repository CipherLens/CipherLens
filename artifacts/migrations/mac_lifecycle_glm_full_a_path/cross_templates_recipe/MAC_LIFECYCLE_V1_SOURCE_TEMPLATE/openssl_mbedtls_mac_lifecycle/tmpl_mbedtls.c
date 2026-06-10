#include <psa/crypto.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#define LIFECYCLE_SEQUENCE_ID [LIFECYCLE_SEQUENCE_ID]
#define MAC_BUFFER_LEN 32

/*
 * Harness: mac_lifecycle
 * Oracle: lifecycle_state_transition_semantic_oracle
 * Library: mbedTLS PSA MAC
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
    static const unsigned char key_bytes[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char msg[] = "mac-lifecycle-message";
    unsigned char mac[MAC_BUFFER_LEN];
    size_t mac_len = 0;
    psa_status_t status;
    psa_status_t setup_status;
    psa_status_t update_status;
    psa_status_t final_status;
    psa_status_t after_status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    int ret = 0;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);
    memset(mac, 0, sizeof(mac));

    printf("template_mutation LIFECYCLE_SEQUENCE_ID=%d sequence=%s\n",
           LIFECYCLE_SEQUENCE_ID, sequence_name());

    status = psa_crypto_init();
    printf("psa_crypto_init status=%d\n", (int) status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_lifecycle: psa_crypto_init failed\n");
        return 2;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);

    status = psa_import_key(&attributes, key_bytes, sizeof(key_bytes), &key_id);
    printf("psa_import_key status=%d\n", (int) status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_lifecycle: psa_import_key failed\n");
        ret = 2;
        goto end;
    }

    setup_status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_CMAC);
    update_status = setup_status == PSA_SUCCESS ? psa_mac_update(&operation, msg, sizeof(msg) - 1) : setup_status;
    final_status = update_status == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, sizeof(mac), &mac_len) : update_status;
    printf("psa setup_status=%d update_status=%d final_status=%d mac_len=%zu\n",
           (int) setup_status, (int) update_status, (int) final_status, mac_len);

    if (setup_status != PSA_SUCCESS || update_status != PSA_SUCCESS || final_status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_lifecycle: normal setup/update/final failed before state transition\n");
        ret = 2;
        goto end;
    }

    if (LIFECYCLE_SEQUENCE_ID == 0) {
        printf("[OK] mac_lifecycle: normal_init_update_final completed successfully\n");
        ret = 0;
    } else if (LIFECYCLE_SEQUENCE_ID == 1) {
        mac_len = 0;
        after_status = psa_mac_sign_finish(&operation, mac, sizeof(mac), &mac_len);
        printf("psa repeated_final status=%d mac_len=%zu\n", (int) after_status, mac_len);
        if (after_status != PSA_SUCCESS) {
            printf("[OK] mac_lifecycle: repeated_final rejected after terminal finalization\n");
        } else {
            printf("[TRIAGE] mac_lifecycle: repeated_final accepted after terminal finalization\n");
        }
        ret = 0;
    } else if (LIFECYCLE_SEQUENCE_ID == 2) {
        after_status = psa_mac_update(&operation, msg, sizeof(msg) - 1);
        printf("psa update_after_final status=%d\n", (int) after_status);
        if (after_status != PSA_SUCCESS) {
            printf("[OK] mac_lifecycle: update_after_final rejected after terminal finalization\n");
        } else {
            printf("[TRIAGE] mac_lifecycle: update_after_final accepted after terminal finalization\n");
        }
        ret = 0;
    } else if (LIFECYCLE_SEQUENCE_ID == 3) {
        after_status = psa_mac_abort(&operation);
        printf("psa abort status=%d\n", (int) after_status);
        after_status = psa_mac_update(&operation, msg, sizeof(msg) - 1);
        printf("psa abort_then_update status=%d\n", (int) after_status);
        if (after_status != PSA_SUCCESS) {
            printf("[OK] mac_lifecycle: abort_then_update rejected after abort\n");
        } else {
            printf("[TRIAGE] mac_lifecycle: abort_then_update accepted after abort\n");
        }
        ret = 0;
    } else {
        printf("[TRIAGE] mac_lifecycle: unknown lifecycle sequence id=%d\n", LIFECYCLE_SEQUENCE_ID);
        ret = 2;
    }

end:
    psa_mac_abort(&operation);
    if (key_id != 0)
        psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
    return ret;
}

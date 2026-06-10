#include <psa/crypto.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#define KEY_LEN [KEY_LEN]
#define MESSAGE_LEN [MESSAGE_LEN]
#define MAC_LEN [MAC_LEN]
#define EXPECTED_MAC_SIZE [EXPECTED_MAC_SIZE]

/*
 * Harness: object_state_lifecycle
 * Oracle: mac_context_size_lifecycle_oracle
 * Target API: psa_mac_sign_setup
 *
 * MAC setup and lifecycle sequence are framework-owned render slots.
 * They are populated from template_maker/mac_lifecycle_sequences.py.
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
    static const unsigned char key_bytes[KEY_LEN] = [KEY_BYTES];
    static const unsigned char message[MESSAGE_LEN] = [MESSAGE_BYTES];
    unsigned char mac[MAC_LEN];
    size_t mac_length = 0;
    size_t second_mac_length = 0;

    psa_status_t status;
    psa_status_t status2;
    psa_status_t status3;
    psa_status_t status4;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    int ret = 1;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);
    memset(mac, 0, sizeof(mac));

    printf("template_mutation TARGET_KEY_TYPE=%s TARGET_KEY_ALGORITHM=%s DIGEST_OR_CIPHER=%s KEY_LEN=%d MESSAGE_LEN=%d MAC_LEN=%d EXPECTED_MAC_SIZE=%d EXPECTED_VERDICT_CLASS=%s\n",
           "[TARGET_KEY_TYPE]", "[TARGET_KEY_ALGORITHM]", "[DIGEST_OR_CIPHER]", KEY_LEN, MESSAGE_LEN, MAC_LEN, EXPECTED_MAC_SIZE, "[EXPECTED_VERDICT_CLASS]");

    status = psa_crypto_init();
    print_psa_status("psa_crypto_init", status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: psa_crypto_init failed\n");
        goto end;
    }

    psa_set_key_type(&attributes, [TARGET_KEY_TYPE]);
    [TARGET_MAC_SETUP_PARAMS]
    psa_set_key_algorithm(&attributes, [TARGET_KEY_ALGORITHM]);

    status = psa_import_key(&attributes, key_bytes, KEY_LEN, &key_id);
    print_psa_status("psa_import_key", status);
    if (status != PSA_SUCCESS) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state: psa_import_key failed\n");
        goto end;
    }

    [TARGET_LIFECYCLE_SEQUENCE]

    printf("TARGET oracle_class=%s\n", [TARGET_ORACLE_OBSERVATION]);

end:
    psa_mac_abort(&operation);
    if (key_id != 0)
        psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
    return ret;
}

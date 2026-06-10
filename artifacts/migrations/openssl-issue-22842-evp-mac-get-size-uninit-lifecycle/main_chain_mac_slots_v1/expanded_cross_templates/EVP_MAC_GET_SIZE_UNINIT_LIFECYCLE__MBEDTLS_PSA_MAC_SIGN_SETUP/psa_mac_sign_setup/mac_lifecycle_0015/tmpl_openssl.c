/*
 * Template: EVP_MAC_GET_SIZE_UNINIT_LIFECYCLE
 * Source pattern: OPENSSL-ISSUE-22842
 * Source library: OpenSSL
 * Vulnerability class: mac_context_uninitialized_state_query
 * Oracle type: mac_context_size_lifecycle_oracle
 *
 * MAC setup and lifecycle sequence are framework-owned render slots.
 * They are populated from template_maker/mac_lifecycle_sequences.py.
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>

#define KEY_LEN [KEY_LEN]
#define MESSAGE_LEN [MESSAGE_LEN]
#define MAC_LEN [MAC_LEN]
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
    const unsigned char key[KEY_LEN] = [KEY_BYTES];
    const unsigned char message[MESSAGE_LEN] = [MESSAGE_BYTES];
    unsigned char out[MAC_LEN];
    size_t outl = 0;
    size_t second_outl = 0;
    size_t pre_size = 0;
    int init_ok = 0;
    int update_ok = 0;
    int final_ok = 0;
    int second_final_ok = 0;
    int ret = 1;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);
    memset(out, 0, sizeof(out));

    printf("template_mutation MAC_NAME=%s DIGEST_OR_CIPHER=%s KEY_LEN=%d MESSAGE_LEN=%d EXPECTED_MAC_SIZE=%d EXPECTED_VERDICT_CLASS=%s\n",
           "[MAC_NAME]", "[DIGEST_OR_CIPHER]", KEY_LEN, MESSAGE_LEN, EXPECTED_MAC_SIZE, "[EXPECTED_VERDICT_CLASS]");

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

    [SOURCE_MAC_SETUP_PARAMS]

    [SOURCE_LIFECYCLE_SEQUENCE]

    printf("SOURCE oracle_class=%s\n", [SOURCE_ORACLE_OBSERVATION]);

end:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}

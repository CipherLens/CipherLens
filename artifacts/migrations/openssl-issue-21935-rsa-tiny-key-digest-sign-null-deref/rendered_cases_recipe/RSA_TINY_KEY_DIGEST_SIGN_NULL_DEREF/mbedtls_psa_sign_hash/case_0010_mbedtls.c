#include <psa/crypto.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

#define KEY_BITS 32
#define HASH_LEN 32
#define SIG_LEN 256

/*
 * Harness: pkey_capability_mismatch_oracle
 * Oracle: rsa_invalid_key_sign_rejection_oracle
 * Target API: psa_sign_hash
 *
 * The key bytes intentionally encode tiny or invalid RSA private key material.
 * Safe behavior is rejection at psa_import_key or psa_sign_hash without crash.
 */

static void bug_signal_handler(int signo)
{
    fprintf(stderr, "[BUG] crash or sanitizer signal: %d\n", signo);
    fflush(stderr);
    _Exit(128 + signo);
}

int main(void)
{
    static const unsigned char rsa_key_der[] = {
        0x30,0x1b,0x02,0x01,0x00,0x02,0x02,0x0c,0xa1,0x02,0x01,0x11,0x02,0x02,0x0a,0xc1,0x02,0x01,0x3d,0x02,0x01,0x35,0x02,0x01,0x31,0x02,0x01,0x26,0x02,0x01,0x26
    };
    unsigned char hash[HASH_LEN];
    unsigned char sig[SIG_LEN];
    size_t sig_len = 0;

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    int ret = 1;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);
    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    printf("template_mutation KEY_BITS=%d HASH_LEN=%d SIG_LEN=%d\n",
           KEY_BITS, HASH_LEN, SIG_LEN);

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[SAFE] invalid RSA key signing rejected during psa_crypto_init: %d\n",
                (int) status);
        ret = 0;
        goto end;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, KEY_BITS);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH));

    status = psa_import_key(&attributes, rsa_key_der, sizeof(rsa_key_der), &key_id);
    printf("psa_import_key returned %d\n", (int) status);
    if (status != PSA_SUCCESS) {
        printf("[SAFE] invalid RSA key signing rejected by psa_import_key: %d\n",
               (int) status);
        printf("[VERDICT] safe_fixed_behavior\n");
        ret = 0;
        goto end;
    }

    status = psa_sign_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                           hash, HASH_LEN,
                           sig, sizeof(sig), &sig_len);
    printf("psa_sign_hash returned %d sig_len=%zu\n", (int) status, sig_len);

    if (status == PSA_SUCCESS) {
        printf("[TRIAGE] signing with invalid RSA key succeeded\n");
    } else {
        printf("[SAFE] invalid RSA key signing rejected by psa_sign_hash: %d\n",
               (int) status);
        printf("[VERDICT] safe_fixed_behavior\n");
    }
    ret = 0;

end:
    if (key_id != 0)
        psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
    return ret;
}

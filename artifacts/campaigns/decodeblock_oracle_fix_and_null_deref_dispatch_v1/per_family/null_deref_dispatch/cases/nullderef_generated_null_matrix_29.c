#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/store.h>
int main(void) {
    unsigned char in[32];
    unsigned char out[64];
    unsigned char key[16];
    const char *actual = "error";
    int ret = 0, outl_i = 0;
    unsigned int outl_u = 0;
    size_t mac_len = 0;
    BIGNUM *bn = NULL;
    BIO *bio = NULL;
    EVP_MD_CTX *md = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_STORE_CTX *store = NULL;
    memset(in, 0x66, sizeof(in));
    memset(out, 0, sizeof(out));
    memset(key, 0x77, sizeof(key));
    actual = "disabled"; ret = 0;
    printf("ORACLE_EVENT family=null_deref_dispatch\n");
    printf("ORACLE_EVENT case_id=nullderef_generated_null_matrix_29\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\n");
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=0\n");
    printf("ORACLE_EVENT contract_boundary=0\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\n");
    return 0;
}

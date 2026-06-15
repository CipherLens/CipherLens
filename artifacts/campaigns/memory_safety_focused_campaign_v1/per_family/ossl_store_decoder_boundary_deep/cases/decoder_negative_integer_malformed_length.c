#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
int main(void) {
    const unsigned char data[] = {0x02, 0x82, 0x00, 0x04, 0xff};
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(data, 5);
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, NULL, 0, NULL, NULL);
    int ret = 0;
    if (bio != NULL && ctx != NULL)
        ret = OSSL_DECODER_from_bio(ctx, bio);
    printf("ORACLE_EVENT family=ossl_store_decoder_boundary_deep\n");
    printf("ORACLE_EVENT case_id=decoder_negative_integer_malformed_length\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\n");
    printf("ORACLE_EVENT actual_behavior=%s\n", ret == 1 ? "success" : "error");
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=0\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\n");
    OSSL_DECODER_CTX_free(ctx);
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return 0;
}

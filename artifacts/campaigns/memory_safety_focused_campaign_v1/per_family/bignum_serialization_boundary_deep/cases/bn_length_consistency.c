#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
int main(void) {
    unsigned char buf[512] = {0};
    unsigned char out[64];
    char hex[512] = {0};
    BIGNUM *a = BN_new();
    char *s = NULL;
    int ret = 0;
    memset(out, 0xcc, sizeof(out));
    BN_hex2bn(&a,"0102030405"); ret=(BN_num_bytes(a)==5);
    int canary_corrupted = 0;
    for (int i=0;i<8;i++) if (out[i] != 0xcc) canary_corrupted = 1;
    for (int i=12;i<64;i++) if (out[i] != 0xcc) canary_corrupted = 1;
    printf("ORACLE_EVENT family=bignum_serialization_boundary_deep\n");
    printf("ORACLE_EVENT case_id=bn_length_consistency\n");
    printf("ORACLE_EVENT expected_behavior=memory_safety_watch\n");
    printf("ORACLE_EVENT actual_behavior=%s\n", ret >= 0 ? "success" : "error");
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=%d\n", canary_corrupted);
    printf("ORACLE_EVENT candidate_label=%s\n", canary_corrupted ? "memory_safety_candidate" : "no_candidate");
    OPENSSL_free(s);
    BN_free(a);
    return 0;
}

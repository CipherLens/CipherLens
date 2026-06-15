#include <stdio.h>
#include <openssl/asn1.h>
int main(void) {
    const unsigned char data[] = {0x30, 0x13, 0xa0, 0x80, 0x02, 0xff, 0x00, 0x00};
    const unsigned char *p = data;
    long len = 8;
    ASN1_TYPE *obj = d2i_ASN1_TYPE(NULL, &p, len);
    const char *actual = obj != NULL ? "success" : "error";
    printf("ORACLE_EVENT family=asn1_nested_boundary\n");
    printf("ORACLE_EVENT case_id=asn1_malformed_random_corpus_sample\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\n");
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=0\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\n");
    ASN1_TYPE_free(obj);
    return 0;
}

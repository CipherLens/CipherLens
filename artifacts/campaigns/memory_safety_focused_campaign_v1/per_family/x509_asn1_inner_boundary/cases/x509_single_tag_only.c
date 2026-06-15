#include <stdio.h>
#include <openssl/x509.h>
int main(void) {
    const unsigned char data[] = {0x30};
    const unsigned char *p = data;
    long len = 1;
    X509_REQ *obj = d2i_X509_REQ(NULL, &p, len);
    const char *actual = obj != NULL ? "success" : "error";
    printf("ORACLE_EVENT family=x509_asn1_inner_boundary\n");
    printf("ORACLE_EVENT case_id=x509_single_tag_only\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\n");
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=0\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\n");
    X509_REQ_free(obj);
    return 0;
}

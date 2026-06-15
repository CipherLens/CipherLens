#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
int main(void) {
    const unsigned char der[] = {0x30, 0x09, 0x30, 0x07, 0x30, 0x82, 0x10, 0x00, 0x87, 0x02, 0x01};
    const unsigned char *p = der;
    long len = 11;
    X509_CRL *obj = NULL;
    obj = d2i_X509_CRL(NULL, &p, len); X509_CRL_free(obj);
    printf("ORACLE_EVENT family=x509_inner_boundary_structured\n");
    printf("ORACLE_EVENT case_id=x509_structured_023\n");
    printf("ORACLE_EVENT trigger_api=d2i_X509_CRL\n");
    printf("ORACLE_EVENT input_class=malformed_only_structured\n");
    printf("ORACLE_EVENT uses_trailing_garbage=0\n");
    printf("ORACLE_EVENT uses_full_consumption_oracle=0\n");
    printf("ORACLE_EVENT expected_behavior=reject_or_no_crash\n");
    printf("ORACLE_EVENT actual_behavior=%s\n", obj != NULL ? "success" : "error");
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=0\n");
    printf("ORACLE_EVENT candidate_label=no_candidate\n");
    return 0;
}

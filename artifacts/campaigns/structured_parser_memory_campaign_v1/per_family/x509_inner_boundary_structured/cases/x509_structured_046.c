#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
int main(void) {
    const unsigned char der[] = {0x30, 0x0f, 0x30, 0x0d, 0x30, 0x20, 0xa0, 0x1e, 0x30, 0x1c, 0x04, 0x82, 0x01, 0x00, 0x61, 0x62, 0x63};
    const unsigned char *p = der;
    long len = 17;
    X509_REQ *obj = NULL;
    obj = d2i_X509_REQ(NULL, &p, len); X509_REQ_free(obj);
    printf("ORACLE_EVENT family=x509_inner_boundary_structured\n");
    printf("ORACLE_EVENT case_id=x509_structured_046\n");
    printf("ORACLE_EVENT trigger_api=d2i_X509_REQ\n");
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

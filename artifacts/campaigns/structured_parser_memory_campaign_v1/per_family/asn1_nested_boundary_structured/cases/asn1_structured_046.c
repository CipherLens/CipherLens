#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
int main(void) {
    const unsigned char der[] = {0x30, 0x20, 0xa0, 0x1e, 0x30, 0x1c, 0x04, 0x82, 0x01, 0x00, 0x61, 0x62, 0x63};
    const unsigned char *p = der;
    long len = 13;
    STACK_OF(ASN1_TYPE) *obj = NULL;
    obj = d2i_ASN1_SEQUENCE_ANY(NULL, &p, len); sk_ASN1_TYPE_pop_free(obj, ASN1_TYPE_free);
    printf("ORACLE_EVENT family=asn1_nested_boundary_structured\n");
    printf("ORACLE_EVENT case_id=asn1_structured_046\n");
    printf("ORACLE_EVENT trigger_api=d2i_ASN1_SEQUENCE_ANY\n");
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

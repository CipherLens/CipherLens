#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

#define FIRST_VALUE_LEN [FIRST_VALUE_LEN]

int main(void)
{
    ASN1_STRING *s = NULL;
    int ret = 0;
    unsigned char first_data[FIRST_VALUE_LEN];
    unsigned char reuse_data[FIRST_VALUE_LEN];

    setbuf(stdout, NULL);

    memset(first_data, 0x11, FIRST_VALUE_LEN);
    memset(reuse_data, 0xaa, FIRST_VALUE_LEN);

    printf("template_mutation FIRST_VALUE_LEN=%d\n", FIRST_VALUE_LEN);

    /*
     * Semantic projection from mbedtls_asn1_store_named_data lifecycle:
     *   step1: nonzero value → internal buffer allocated
     *   step2: zero-length update → internal state modified
     *   step3: same-length reuse → safe reallocation or potential crash
     *
     * OpenSSL ASN1_STRING_set keeps the buffer allocated on zero-length update.
     * Expected result: migrated_safe (no crash; OpenSSL handles lifecycle safely).
     */
    s = ASN1_STRING_new();
    if (s == NULL) {
        printf("[ERROR] ASN1_STRING_new failed.\n");
        return 2;
    }

    /* Step 1: set nonzero value (FIRST_VALUE_LEN bytes). */
    ret = ASN1_STRING_set(s, first_data, FIRST_VALUE_LEN);
    printf("step1 ASN1_STRING_set(len=%d) ret=%d data=%p len=%d\n",
           FIRST_VALUE_LEN, ret,
           (void *) ASN1_STRING_get0_data(s),
           ASN1_STRING_length(s));
    if (ret != 1) {
        printf("[INFO] object_state_lifecycle: step1 failed. ret=%d\n", ret);
        ASN1_STRING_free(s);
        return 2;
    }

    /* Step 2: zero-length update (the stale-state trigger in vulnerable systems). */
    ret = ASN1_STRING_set(s, NULL, 0);
    printf("step2 ASN1_STRING_set(len=0) ret=%d data=%p len=%d\n",
           ret,
           (void *) ASN1_STRING_get0_data(s),
           ASN1_STRING_length(s));
    if (ret != 1) {
        printf("[INFO] object_state_lifecycle: step2 failed. ret=%d\n", ret);
        ASN1_STRING_free(s);
        return 2;
    }

    /* Step 3: reuse with same length as step1.
     * Buggy systems: skip reallocation, memcpy to NULL → crash.
     * OpenSSL: safe reallocation or in-place write. */
    ret = ASN1_STRING_set(s, reuse_data, FIRST_VALUE_LEN);
    printf("step3 ASN1_STRING_set(len=%d) ret=%d data=%p len=%d\n",
           FIRST_VALUE_LEN, ret,
           (void *) ASN1_STRING_get0_data(s),
           ASN1_STRING_length(s));

    if (ret == 1 &&
        ASN1_STRING_length(s) == FIRST_VALUE_LEN &&
        ASN1_STRING_get0_data(s) != NULL) {
        printf("[OK] object_state_lifecycle: safe update after zero-length reset. ret=%d\n", ret);
    } else if (ret != 1) {
        printf("[INFO] object_state_lifecycle: step3 failed. ret=%d\n", ret);
    } else {
        printf("[TRIAGE] object_state_lifecycle: unexpected state. ret=%d len=%d\n",
               ret, ASN1_STRING_length(s));
    }

    ASN1_STRING_free(s);
    return 0;
}

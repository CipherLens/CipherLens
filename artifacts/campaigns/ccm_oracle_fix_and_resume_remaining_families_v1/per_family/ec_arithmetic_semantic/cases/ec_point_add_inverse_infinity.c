/*
 * Auto campaign EC arithmetic semantic harness.
 * Local mathematical identities only; invalid observations are not vulnerability claims.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

int main(void)
{
    const char *case_id = "ec_point_add_inverse_infinity";
    const char *expected_behavior = "semantic_equivalence";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret = 0, ret2 = 0;
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *k = BN_new();
    BIGNUM *order = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP *group2 = NULL;
    EC_POINT *p = NULL;
    EC_POINT *q = NULL;
    EC_POINT *r = NULL;
    const EC_POINT *gen = NULL;

    if (bn_ctx == NULL || k == NULL || order == NULL || x == NULL || y == NULL || group == NULL)
        goto done;
    p = EC_POINT_new(group);
    q = EC_POINT_new(group);
    r = EC_POINT_new(group);
    gen = EC_GROUP_get0_generator(group);
    if (p == NULL || q == NULL || r == NULL || gen == NULL)
        goto done;

    BN_one(k);
    EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    EC_POINT_copy(q, p);
    EC_POINT_invert(group, q, bn_ctx);
    ret = EC_POINT_add(group, r, p, q, bn_ctx);
    actual_behavior = (ret == 1 && EC_POINT_is_at_infinity(group, r)) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;


done:

    printf("ORACLE_EVENT family=ec_arithmetic_semantic\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT semantic_mismatch=%d\n", semantic_mismatch);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    EC_POINT_free(p);
    EC_POINT_free(q);
    EC_POINT_free(r);
    EC_GROUP_free(group2);
    EC_GROUP_free(group);
    BN_free(k);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(bn_ctx);
    return 0;
}

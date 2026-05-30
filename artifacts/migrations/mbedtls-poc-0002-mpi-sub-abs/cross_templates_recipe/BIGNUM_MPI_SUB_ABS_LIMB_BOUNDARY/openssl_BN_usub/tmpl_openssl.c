#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>

#define A_LITERAL "[A_VALUE]"
#define B_LITERAL "[B_VALUE]"
#define A_BASE_VALUE [A_BASE]
#define B_BASE_VALUE [B_BASE]

static int set_bn_from_string(BIGNUM **out, int base, const char *value)
{
    if (out == NULL || value == NULL) {
        return 0;
    }

    if (base == 10) {
        return BN_dec2bn(out, value) > 0;
    }

    if (base == 16) {
        return BN_hex2bn(out, value) > 0;
    }

    return 0;
}

int main(void)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *r = NULL;
    int ret = 0;
    int cmp = 0;

    setbuf(stdout, NULL);

    bn_ctx = BN_CTX_new();
    a = BN_new();
    b = BN_new();
    r = BN_new();

    if (bn_ctx == NULL || a == NULL || b == NULL || r == NULL) {
        printf("[ERROR] target BN allocation failed.\n");
        ret = 2;
        goto cleanup;
    }

    if (!set_bn_from_string(&a, A_BASE_VALUE, A_LITERAL)) {
        printf("[ERROR] target read lhs failed.\n");
        ret = 2;
        goto cleanup;
    }

    if (!set_bn_from_string(&b, B_BASE_VALUE, B_LITERAL)) {
        printf("[ERROR] target read rhs failed.\n");
        ret = 2;
        goto cleanup;
    }

    cmp = BN_ucmp(a, b);
    ret = BN_usub(r, a, b);

    printf("template_mutation A_VALUE=%s\n", A_LITERAL);
    printf("template_mutation B_VALUE=%s\n", B_LITERAL);
    printf("template_mutation A_BASE=%d\n", A_BASE_VALUE);
    printf("template_mutation B_BASE=%d\n", B_BASE_VALUE);
    printf("cmp=%d\n", cmp);
    printf("ret=%d\n", ret);

    if (cmp < 0 && ret == 0) {
        printf("[OK] target rejected lhs<rhs unsigned subtraction or avoided producing result.\n");
        ret = 0;
        goto cleanup;
    }

    if (cmp < 0 && ret != 0) {
        printf("[TRIAGE] target produced result for lhs<rhs unsigned subtraction; semantic projection needs review.\n");
        ret = 2;
        goto cleanup;
    }

    printf("[INFO] target lhs>=rhs normal unsigned subtraction path.\n");
    ret = 0;

cleanup:
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_CTX_free(bn_ctx);
    return ret;
}

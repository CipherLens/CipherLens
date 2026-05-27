# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_exp.c
Knowledge type: api_constraints

## Snippet 1

```c
* BN_MOD_MUL_WORD is only used with 'w' large, so the BN_ucmp test is
     * probably more overhead than always using BN_mod (which uses BN_copy if
     * a similar test returns true).
     */
    /*
     * We can use BN_mod and do not need BN_nnmod because our accumulator is
     * never negative (the result of BN_mod does not depend on the sign of
     * the modulus).
     */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
    (BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))

    if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0
        || BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
        ERR_raise(ERR_LIB_BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bn_check_top(p);
    bn_check_top(m);

    if (!BN_is_odd(m)) {
        ERR_raise(ERR_LIB_BN, BN_R_CALLED_WITH_EVEN_MODULUS);
        return 0;
    }
    if (m->top == 1)
        a %= m->d[0]; /* make sure that 'a' is reduced */
```


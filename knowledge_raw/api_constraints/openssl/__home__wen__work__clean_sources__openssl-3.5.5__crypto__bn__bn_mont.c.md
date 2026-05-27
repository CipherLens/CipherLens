# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_mont.c
Knowledge type: api_constraints

## Snippet 1

```c
BN_zero(Ri);
        else if ((BN_mod_inverse(Ri, R, &tmod, ctx)) == NULL)
            goto err;
        if (!BN_lshift(Ri, Ri, BN_BITS2))
            goto err; /* R*Ri */
        if (!BN_is_zero(Ri)) {
            if (!BN_sub_word(Ri, 1))
                goto err;
        } else { /* if N mod word size == 1 */

            if (!BN_set_word(Ri, BN_MASK2))
                goto err; /* Ri-- (mod word size) */
        }
        if (!BN_div(Ri, NULL, Ri, &tmod, ctx))
            goto err;
        /*
         * Ni = (R*Ri-1)/N, keep only least significant word:
         */
        mont->n0[0] = (Ri->top > 0) ? Ri->d[0] : 0;
        mont->n0[1] = 0;
#endif
    }
#else /* !MONT_WORD */
    { /* bignum version */
        mont->ri = BN_num_bits(&mont->N);
        BN_zero(R);
        if (!BN_set_bit(R, mont->ri))
            goto err; /* R = 2^ri */
```


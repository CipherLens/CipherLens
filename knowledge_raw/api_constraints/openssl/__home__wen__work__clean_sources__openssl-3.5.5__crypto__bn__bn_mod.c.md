# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_mod.c
Knowledge type: api_constraints

## Snippet 1

```c
if (m->neg) {
        abs_m = BN_dup(m);
        if (abs_m == NULL)
            return 0;
        abs_m->neg = 0;
    }

    ret = BN_mod_lshift_quick(r, r, n, (abs_m ? abs_m : m));
    bn_check_top(r);

    BN_free(abs_m);
    return ret;
}

/*
 * BN_mod_lshift variant that may be used if a is non-negative and less than
 * m
 */
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m)
{
    if (r != a) {
        if (BN_copy(r, a) == NULL)
            return 0;
    }

    while (n > 0) {
        int max_shift;
```


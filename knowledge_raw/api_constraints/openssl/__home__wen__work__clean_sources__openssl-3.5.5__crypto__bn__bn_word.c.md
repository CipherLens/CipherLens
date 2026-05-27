# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_word.c
Knowledge type: api_constraints

## Snippet 1

```c
/*
     * If |w| is too long and we don't have BN_ULLONG then we need to fall
     * back to using BN_div_word
     */
    if (w > ((BN_ULONG)1 << BN_BITS4)) {
        BIGNUM *tmp = BN_dup(a);
        if (tmp == NULL)
            return (BN_ULONG)-1;

        ret = BN_div_word(tmp, w);
        BN_free(tmp);

        return ret;
    }
#endif

    bn_check_top(a);
    w &= BN_MASK2;
    for (i = a->top - 1; i >= 0; i--) {
#ifndef BN_LLONG
        /*
         * We can assume here that | w <= ((BN_ULONG)1 << BN_BITS4) | and so
         * | ret < ((BN_ULONG)1 << BN_BITS4) | and therefore the shifts here are
         * safe and will not overflow
         */
        ret = ((ret << BN_BITS4) | ((a->d[i] >> BN_BITS4) & BN_MASK2l)) % w;
        ret = ((ret << BN_BITS4) | (a->d[i] & BN_MASK2l)) % w;
#else
```

## Snippet 2

```c
int i;

    bn_check_top(a);
    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a))
        return BN_set_word(a, w);
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_sub_word(a, w);
        if (!BN_is_zero(a))
            a->neg = !(a->neg);
        return i;
    }
    for (i = 0; w != 0 && i < a->top; i++) {
        a->d[i] = l = (a->d[i] + w) & BN_MASK2;
        w = (w > l) ? 1 : 0;
    }
    if (w && i == a->top) {
        if (bn_wexpand(a, a->top + 1) == NULL)
            return 0;
        a->top++;
        a->d[i] = w;
```

## Snippet 3

```c
int i;

    bn_check_top(a);
    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a)) {
        i = BN_set_word(a, w);
        if (i != 0)
            BN_set_negative(a, 1);
        return i;
    }
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_add_word(a, w);
        a->neg = 1;
        return i;
    }

    if ((a->top == 1) && (a->d[0] < w)) {
        a->d[0] = w - a->d[0];
        a->neg = 1;
        return 1;
    }
```

## Snippet 4

```c
bn_check_top(a);
    w &= BN_MASK2;

    /* degenerate case: w is zero */
    if (!w)
        return 1;
    /* degenerate case: a is zero */
    if (BN_is_zero(a)) {
        i = BN_set_word(a, w);
        if (i != 0)
            BN_set_negative(a, 1);
        return i;
    }
    /* handle 'a' when negative */
    if (a->neg) {
        a->neg = 0;
        i = BN_add_word(a, w);
        a->neg = 1;
        return i;
    }

    if ((a->top == 1) && (a->d[0] < w)) {
        a->d[0] = w - a->d[0];
        a->neg = 1;
        return 1;
    }
    i = 0;
    for (;;) {
```


# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_recp.c
Knowledge type: api_constraints

## Snippet 1

```c
bn_init(&(ret->N));
    bn_init(&(ret->Nr));
    ret->flags = BN_FLG_MALLOCED;
    return ret;
}

void BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
    if (recp == NULL)
        return;
    BN_free(&recp->N);
    BN_free(&recp->Nr);
    if (recp->flags & BN_FLG_MALLOCED)
        OPENSSL_free(recp);
}

int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx)
{
    if (BN_is_zero(d) || !BN_copy(&(recp->N), d))
        return 0;
    BN_zero(&(recp->Nr));
    recp->num_bits = BN_num_bits(d);
    recp->shift = 0;
    return 1;
}

int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
    BN_RECP_CTX *recp, BN_CTX *ctx)
```

## Snippet 2

```c
bn_init(&(ret->Nr));
    ret->flags = BN_FLG_MALLOCED;
    return ret;
}

void BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
    if (recp == NULL)
        return;
    BN_free(&recp->N);
    BN_free(&recp->Nr);
    if (recp->flags & BN_FLG_MALLOCED)
        OPENSSL_free(recp);
}

int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx)
{
    if (BN_is_zero(d) || !BN_copy(&(recp->N), d))
        return 0;
    BN_zero(&(recp->Nr));
    recp->num_bits = BN_num_bits(d);
    recp->shift = 0;
    return 1;
}

int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
    BN_RECP_CTX *recp, BN_CTX *ctx)
{
```


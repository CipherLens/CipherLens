# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_blind.c
Knowledge type: api_constraints

## Snippet 1

```c
err:
    BN_BLINDING_free(ret);
    return NULL;
}

void BN_BLINDING_free(BN_BLINDING *r)
{
    if (r == NULL)
        return;
    BN_free(r->A);
    BN_free(r->Ai);
    BN_free(r->e);
    BN_free(r->mod);
    CRYPTO_THREAD_lock_free(r->lock);
    OPENSSL_free(r);
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 0;

    if ((b->A == NULL) || (b->Ai == NULL)) {
        ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        goto err;
    }

    if (b->counter == -1)
```

## Snippet 2

```c
err:
    BN_BLINDING_free(ret);
    return NULL;
}

void BN_BLINDING_free(BN_BLINDING *r)
{
    if (r == NULL)
        return;
    BN_free(r->A);
    BN_free(r->Ai);
    BN_free(r->e);
    BN_free(r->mod);
    CRYPTO_THREAD_lock_free(r->lock);
    OPENSSL_free(r);
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 0;

    if ((b->A == NULL) || (b->Ai == NULL)) {
        ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        goto err;
    }

    if (b->counter == -1)
        b->counter = 0;
```

## Snippet 3

```c
BN_BLINDING_free(ret);
    return NULL;
}

void BN_BLINDING_free(BN_BLINDING *r)
{
    if (r == NULL)
        return;
    BN_free(r->A);
    BN_free(r->Ai);
    BN_free(r->e);
    BN_free(r->mod);
    CRYPTO_THREAD_lock_free(r->lock);
    OPENSSL_free(r);
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 0;

    if ((b->A == NULL) || (b->Ai == NULL)) {
        ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        goto err;
    }

    if (b->counter == -1)
        b->counter = 0;
```

## Snippet 4

```c
return NULL;
}

void BN_BLINDING_free(BN_BLINDING *r)
{
    if (r == NULL)
        return;
    BN_free(r->A);
    BN_free(r->Ai);
    BN_free(r->e);
    BN_free(r->mod);
    CRYPTO_THREAD_lock_free(r->lock);
    OPENSSL_free(r);
}

int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx)
{
    int ret = 0;

    if ((b->A == NULL) || (b->Ai == NULL)) {
        ERR_raise(ERR_LIB_BN, BN_R_NOT_INITIALIZED);
        goto err;
    }

    if (b->counter == -1)
        b->counter = 0;

    if (++b->counter == BN_BLINDING_COUNTER && b->e != NULL && !(b->flags & BN_BLINDING_NO_RECREATE)) {
```

## Snippet 5

```c
BN_BLINDING *ret = NULL;

    if (b == NULL)
        ret = BN_BLINDING_new(NULL, NULL, m);
    else
        ret = b;

    if (ret == NULL)
        goto err;

    if (ret->A == NULL && (ret->A = BN_new()) == NULL)
        goto err;
    if (ret->Ai == NULL && (ret->Ai = BN_new()) == NULL)
        goto err;

    if (e != NULL) {
        BN_free(ret->e);
        ret->e = BN_dup(e);
    }
    if (ret->e == NULL)
        goto err;

    if (bn_mod_exp != NULL)
        ret->bn_mod_exp = bn_mod_exp;
    if (m_ctx != NULL)
        ret->m_ctx = m_ctx;

    do {
```

## Snippet 6

```c
if (b == NULL)
        ret = BN_BLINDING_new(NULL, NULL, m);
    else
        ret = b;

    if (ret == NULL)
        goto err;

    if (ret->A == NULL && (ret->A = BN_new()) == NULL)
        goto err;
    if (ret->Ai == NULL && (ret->Ai = BN_new()) == NULL)
        goto err;

    if (e != NULL) {
        BN_free(ret->e);
        ret->e = BN_dup(e);
    }
    if (ret->e == NULL)
        goto err;

    if (bn_mod_exp != NULL)
        ret->bn_mod_exp = bn_mod_exp;
    if (m_ctx != NULL)
        ret->m_ctx = m_ctx;

    do {
        int rv;
        if (!BN_priv_rand_range_ex(ret->A, ret->mod, 0, ctx))
```

## Snippet 7

```c
if (ret == NULL)
        goto err;

    if (ret->A == NULL && (ret->A = BN_new()) == NULL)
        goto err;
    if (ret->Ai == NULL && (ret->Ai = BN_new()) == NULL)
        goto err;

    if (e != NULL) {
        BN_free(ret->e);
        ret->e = BN_dup(e);
    }
    if (ret->e == NULL)
        goto err;

    if (bn_mod_exp != NULL)
        ret->bn_mod_exp = bn_mod_exp;
    if (m_ctx != NULL)
        ret->m_ctx = m_ctx;

    do {
        int rv;
        if (!BN_priv_rand_range_ex(ret->A, ret->mod, 0, ctx))
            goto err;
        if (int_bn_mod_inverse(ret->Ai, ret->A, ret->mod, ctx, &rv))
            break;
```


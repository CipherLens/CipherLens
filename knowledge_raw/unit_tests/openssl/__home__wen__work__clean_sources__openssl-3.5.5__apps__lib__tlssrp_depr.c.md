# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/lib/tlssrp_depr.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/srp.h>
#include "apps_ui.h"
#include "apps.h"
#include "s_apps.h"

static int srp_Verify_N_and_g(const BIGNUM *N, const BIGNUM *g)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    int ret = g != NULL && N != NULL && bn_ctx != NULL && BN_is_odd(N) && BN_check_prime(N, bn_ctx, NULL) == 1 && p != NULL && BN_rshift1(p, N) &&
        /* p = (N-1)/2 */
        BN_check_prime(p, bn_ctx, NULL) == 1 && r != NULL &&
        /* verify g^((N-1)/2) == -1 (mod N) */
        BN_mod_exp(r, g, p, N, bn_ctx) && BN_add_word(r, 1) && BN_cmp(r, N) == 0;

    BN_free(r);
    BN_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

/*-
 * This callback is used here for two purposes:
 * - extended debugging
 * - making some primality tests for unknown groups
 * The callback is only called for a non default group.
 *
 * An application does not need the call back at all if
 * only the standard groups are used.  In real life situations,
 * client and server already share well known groups,
 * thus there is no need to verify them.
 * Furthermore, in case that a server actually proposes a group that
 * is not one of those defined in RFC 5054, it is more appropriate
 * to add the group to a static list and then compare since
 * primality tests are rather cpu consuming.
```

## Call pattern 2

```c
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/srp.h>
#include "apps_ui.h"
#include "apps.h"
#include "s_apps.h"

static int srp_Verify_N_and_g(const BIGNUM *N, const BIGNUM *g)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    int ret = g != NULL && N != NULL && bn_ctx != NULL && BN_is_odd(N) && BN_check_prime(N, bn_ctx, NULL) == 1 && p != NULL && BN_rshift1(p, N) &&
        /* p = (N-1)/2 */
        BN_check_prime(p, bn_ctx, NULL) == 1 && r != NULL &&
        /* verify g^((N-1)/2) == -1 (mod N) */
        BN_mod_exp(r, g, p, N, bn_ctx) && BN_add_word(r, 1) && BN_cmp(r, N) == 0;

    BN_free(r);
    BN_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

/*-
 * This callback is used here for two purposes:
 * - extended debugging
 * - making some primality tests for unknown groups
 * The callback is only called for a non default group.
 *
 * An application does not need the call back at all if
 * only the standard groups are used.  In real life situations,
 * client and server already share well known groups,
 * thus there is no need to verify them.
 * Furthermore, in case that a server actually proposes a group that
 * is not one of those defined in RFC 5054, it is more appropriate
 * to add the group to a static list and then compare since
 * primality tests are rather cpu consuming.
 */
```

## Call pattern 3

```c
static int srp_Verify_N_and_g(const BIGNUM *N, const BIGNUM *g)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    int ret = g != NULL && N != NULL && bn_ctx != NULL && BN_is_odd(N) && BN_check_prime(N, bn_ctx, NULL) == 1 && p != NULL && BN_rshift1(p, N) &&
        /* p = (N-1)/2 */
        BN_check_prime(p, bn_ctx, NULL) == 1 && r != NULL &&
        /* verify g^((N-1)/2) == -1 (mod N) */
        BN_mod_exp(r, g, p, N, bn_ctx) && BN_add_word(r, 1) && BN_cmp(r, N) == 0;

    BN_free(r);
    BN_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

/*-
 * This callback is used here for two purposes:
 * - extended debugging
 * - making some primality tests for unknown groups
 * The callback is only called for a non default group.
 *
 * An application does not need the call back at all if
 * only the standard groups are used.  In real life situations,
 * client and server already share well known groups,
 * thus there is no need to verify them.
 * Furthermore, in case that a server actually proposes a group that
 * is not one of those defined in RFC 5054, it is more appropriate
 * to add the group to a static list and then compare since
 * primality tests are rather cpu consuming.
 */

static int ssl_srp_verify_param_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    BIGNUM *N = NULL, *g = NULL;

    if (((N = SSL_get_srp_N(s)) == NULL) || ((g = SSL_get_srp_g(s)) == NULL))
```

## Call pattern 4

```c
static int srp_Verify_N_and_g(const BIGNUM *N, const BIGNUM *g)
{
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *r = BN_new();
    int ret = g != NULL && N != NULL && bn_ctx != NULL && BN_is_odd(N) && BN_check_prime(N, bn_ctx, NULL) == 1 && p != NULL && BN_rshift1(p, N) &&
        /* p = (N-1)/2 */
        BN_check_prime(p, bn_ctx, NULL) == 1 && r != NULL &&
        /* verify g^((N-1)/2) == -1 (mod N) */
        BN_mod_exp(r, g, p, N, bn_ctx) && BN_add_word(r, 1) && BN_cmp(r, N) == 0;

    BN_free(r);
    BN_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

/*-
 * This callback is used here for two purposes:
 * - extended debugging
 * - making some primality tests for unknown groups
 * The callback is only called for a non default group.
 *
 * An application does not need the call back at all if
 * only the standard groups are used.  In real life situations,
 * client and server already share well known groups,
 * thus there is no need to verify them.
 * Furthermore, in case that a server actually proposes a group that
 * is not one of those defined in RFC 5054, it is more appropriate
 * to add the group to a static list and then compare since
 * primality tests are rather cpu consuming.
 */

static int ssl_srp_verify_param_cb(SSL *s, void *arg)
{
    SRP_ARG *srp_arg = (SRP_ARG *)arg;
    BIGNUM *N = NULL, *g = NULL;

    if (((N = SSL_get_srp_N(s)) == NULL) || ((g = SSL_get_srp_g(s)) == NULL))
        return 0;
```


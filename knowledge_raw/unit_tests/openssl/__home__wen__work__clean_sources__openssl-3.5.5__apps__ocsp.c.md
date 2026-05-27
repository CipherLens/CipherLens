# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/ocsp.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
int i;
    BIGNUM *bn = NULL;
    char *itmp, *row[DB_NUMBER], **rrow;
    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    bn = ASN1_INTEGER_to_BN(ser, NULL);
    OPENSSL_assert(bn); /* FIXME: should report an error at this
                         * point and abort */
    if (BN_is_zero(bn)) {
        itmp = OPENSSL_strdup("00");
        OPENSSL_assert(itmp);
    } else {
        itmp = BN_bn2hex(bn);
    }
    row[DB_serial] = itmp;
    BN_free(bn);
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    OPENSSL_free(itmp);
    return rrow;
}

static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
    int timeout)
{
#ifndef OPENSSL_NO_SOCK
    return http_server_get_asn1_req(ASN1_ITEM_rptr(OCSP_REQUEST),
        (ASN1_VALUE **)preq, NULL, pcbio, acbio,
        NULL /* found_keep_alive */,
        prog, 1 /* accept_get */, timeout);
#else
    BIO_printf(bio_err,
        "Error getting OCSP request - sockets not supported\n");
    *preq = NULL;
    return 0;
#endif
}

static int send_ocsp_response(BIO *cbio, const OCSP_RESPONSE *resp)
{
#ifndef OPENSSL_NO_SOCK
```

## Call pattern 2

```c
for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    bn = ASN1_INTEGER_to_BN(ser, NULL);
    OPENSSL_assert(bn); /* FIXME: should report an error at this
                         * point and abort */
    if (BN_is_zero(bn)) {
        itmp = OPENSSL_strdup("00");
        OPENSSL_assert(itmp);
    } else {
        itmp = BN_bn2hex(bn);
    }
    row[DB_serial] = itmp;
    BN_free(bn);
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    OPENSSL_free(itmp);
    return rrow;
}

static int do_responder(OCSP_REQUEST **preq, BIO **pcbio, BIO *acbio,
    int timeout)
{
#ifndef OPENSSL_NO_SOCK
    return http_server_get_asn1_req(ASN1_ITEM_rptr(OCSP_REQUEST),
        (ASN1_VALUE **)preq, NULL, pcbio, acbio,
        NULL /* found_keep_alive */,
        prog, 1 /* accept_get */, timeout);
#else
    BIO_printf(bio_err,
        "Error getting OCSP request - sockets not supported\n");
    *preq = NULL;
    return 0;
#endif
}

static int send_ocsp_response(BIO *cbio, const OCSP_RESPONSE *resp)
{
#ifndef OPENSSL_NO_SOCK
    return http_server_send_asn1_resp(prog, cbio,
        0 /* no keep-alive */,
        "application/ocsp-response",
```


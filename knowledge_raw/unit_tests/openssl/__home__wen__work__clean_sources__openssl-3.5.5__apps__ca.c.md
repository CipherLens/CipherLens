# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/ca.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
if (!app_conf_try_number(conf, section, ENV_DEFAULT_DAYS, &days))
                days = 0;
        }
        if (enddate == NULL && days == 0) {
            BIO_printf(bio_err, "cannot lookup how many days to certify for\n");
            goto end;
        }
        if (days != 0 && enddate != NULL)
            BIO_printf(bio_err,
                "Warning: -enddate or -not_after option overriding -days option\n");

        if (rand_ser) {
            if ((serial = BN_new()) == NULL || !rand_serial(serial, NULL)) {
                BIO_printf(bio_err, "error generating serial number\n");
                goto end;
            }
        } else {
            serial = load_serial(serialfile, NULL, create_ser, NULL);
            if (serial == NULL) {
                BIO_printf(bio_err, "error while loading serial number\n");
                goto end;
            }
            if (verbose) {
                if (BN_is_zero(serial)) {
                    BIO_printf(bio_err, "next serial number is 00\n");
                } else {
                    if ((f = BN_bn2hex(serial)) == NULL)
                        goto end;
                    BIO_printf(bio_err, "next serial number is %s\n", f);
                    OPENSSL_free(f);
                }
            }
        }

        if ((attribs = NCONF_get_section(conf, policy)) == NULL) {
            BIO_printf(bio_err, "unable to find 'section' for %s\n", policy);
            goto end;
        }

        if ((cert_sk = sk_X509_new_null()) == NULL) {
```

## Call pattern 2

```c
goto end;
            }
        } else {
            serial = load_serial(serialfile, NULL, create_ser, NULL);
            if (serial == NULL) {
                BIO_printf(bio_err, "error while loading serial number\n");
                goto end;
            }
            if (verbose) {
                if (BN_is_zero(serial)) {
                    BIO_printf(bio_err, "next serial number is 00\n");
                } else {
                    if ((f = BN_bn2hex(serial)) == NULL)
                        goto end;
                    BIO_printf(bio_err, "next serial number is %s\n", f);
                    OPENSSL_free(f);
                }
            }
        }

        if ((attribs = NCONF_get_section(conf, policy)) == NULL) {
            BIO_printf(bio_err, "unable to find 'section' for %s\n", policy);
            goto end;
        }

        if ((cert_sk = sk_X509_new_null()) == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }
        if (spkac_file != NULL) {
            total++;
            j = certify_spkac(&x, spkac_file, pkey, x509, dgst, sigopts,
                attribs, db, serial, subj, chtype, multirdn,
                email_dn, startdate, enddate, days, extensions,
                conf, verbose, certopt, get_nameopt(), default_op,
                ext_copy, dateopt);
            if (j < 0)
                goto end;
            if (j > 0) {
                total_done++;
```

## Call pattern 3

```c
pp = sk_OPENSSL_PSTRING_value(db->db->data, i);
            if (pp[DB_type][0] == DB_TYPE_REV) {
                if ((r = X509_REVOKED_new()) == NULL)
                    goto end;
                j = make_revoked(r, pp[DB_rev_date]);
                if (!j)
                    goto end;
                if (j == 2)
                    crl_v2 = 1;
                if (!BN_hex2bn(&serial, pp[DB_serial]))
                    goto end;
                tmpser = BN_to_ASN1_INTEGER(serial, NULL);
                BN_free(serial);
                serial = NULL;
                if (!tmpser)
                    goto end;
                X509_REVOKED_set_serialNumber(r, tmpser);
                ASN1_INTEGER_free(tmpser);
                X509_CRL_add0_revoked(crl, r);
            }
        }

        /*
         * sort the data so it will be written in serial number order
         */
        X509_CRL_sort(crl);

        /* we now have a CRL */
        if (verbose)
            BIO_printf(bio_err, "signing CRL\n");

        /* Add any extensions asked for */

        if (crl_ext != NULL || crlnumberfile != NULL) {
            X509V3_CTX crlctx;

            X509V3_set_ctx(&crlctx, x509, NULL, NULL, crl, 0);
            X509V3_set_nconf(&crlctx, conf);

            if (crl_ext != NULL)
```

## Call pattern 4

```c
}
        }
        if (crl_ext != NULL || crl_v2) {
            if (!X509_CRL_set_version(crl, X509_CRL_VERSION_2))
                goto end;
        }

        /* we have a CRL number that need updating */
        if (crlnumberfile != NULL
            && !save_serial(crlnumberfile, "new", crlnumber, NULL))
            goto end;

        BN_free(crlnumber);
        crlnumber = NULL;

        if (!do_X509_CRL_sign(crl, pkey, dgst, sigopts))
            goto end;

        Sout = bio_open_default(outfile, 'w',
            output_der ? FORMAT_ASN1 : FORMAT_TEXT);
        if (Sout == NULL)
            goto end;

        PEM_write_bio_X509_CRL(Sout, crl);

        /* Rename the crlnumber file */
        if (crlnumberfile != NULL
            && !rotate_serial(crlnumberfile, "new", "old"))
            goto end;
    }
    /*****************************************************************/
    if (dorevoke) {
        if (infile == NULL) {
            BIO_printf(bio_err, "no input files\n");
            goto end;
        } else {
            X509 *revcert;

            revcert = load_cert_pass(infile, informat, 1, passin,
                "certificate to be revoked");
```

## Call pattern 5

```c
end:
    if (ret)
        ERR_print_errors(bio_err);
    BIO_free_all(Sout);
    BIO_free_all(out);
    BIO_free_all(in);
    OSSL_STACK_OF_X509_free(cert_sk);

    cleanse(passin);
    if (free_passin)
        OPENSSL_free(passin);
    BN_free(serial);
    BN_free(crlnumber);
    free_index(db);
    sk_OPENSSL_STRING_free(sigopts);
    sk_OPENSSL_STRING_free(vfyopts);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    X509_CRL_free(crl);
    NCONF_free(conf);
    NCONF_free(extfile_conf);
    release_engine(e);
    return ret;
}

static char *lookup_conf(const CONF *conf, const char *section, const char *tag)
{
    char *entry = NCONF_get_string(conf, section, tag);
    if (entry == NULL)
        BIO_printf(bio_err, "variable lookup failed for %s::%s\n", section, tag);
    return entry;
}

static int certify(X509 **xret, const char *infile, int informat,
    EVP_PKEY *pkey, X509 *x509,
    const char *dgst,
    STACK_OF(OPENSSL_STRING) *sigopts,
    STACK_OF(OPENSSL_STRING) *vfyopts,
    STACK_OF(CONF_VALUE) *policy, CA_DB *db,
```

## Call pattern 6

```c
end:
    if (ret)
        ERR_print_errors(bio_err);
    BIO_free_all(Sout);
    BIO_free_all(out);
    BIO_free_all(in);
    OSSL_STACK_OF_X509_free(cert_sk);

    cleanse(passin);
    if (free_passin)
        OPENSSL_free(passin);
    BN_free(serial);
    BN_free(crlnumber);
    free_index(db);
    sk_OPENSSL_STRING_free(sigopts);
    sk_OPENSSL_STRING_free(vfyopts);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    X509_CRL_free(crl);
    NCONF_free(conf);
    NCONF_free(extfile_conf);
    release_engine(e);
    return ret;
}

static char *lookup_conf(const CONF *conf, const char *section, const char *tag)
{
    char *entry = NCONF_get_string(conf, section, tag);
    if (entry == NULL)
        BIO_printf(bio_err, "variable lookup failed for %s::%s\n", section, tag);
    return entry;
}

static int certify(X509 **xret, const char *infile, int informat,
    EVP_PKEY *pkey, X509 *x509,
    const char *dgst,
    STACK_OF(OPENSSL_STRING) *sigopts,
    STACK_OF(OPENSSL_STRING) *vfyopts,
    STACK_OF(CONF_VALUE) *policy, CA_DB *db,
    BIGNUM *serial, const char *subj, unsigned long chtype,
```

## Call pattern 7

```c
X509_NAME_free(dn_subject);
    }

    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(ret), NULL, 0);
    if (row[DB_name] == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    if (BN_is_zero(serial))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = BN_bn2hex(serial);
    if (row[DB_serial] == NULL) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }

    if (row[DB_name][0] == '\0') {
        /*
         * An empty subject! We'll use the serial number instead. If
         * unique_subject is in use then we don't want different entries with
         * empty subjects matching each other.
         */
        OPENSSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
        if (row[DB_name] == NULL) {
            BIO_printf(bio_err, "Memory allocation failure\n");
            goto end;
        }
    }

    if (db->attributes.unique_subject) {
        OPENSSL_STRING *crow = row;

        rrow = TXT_DB_get_by_index(db->db, DB_name, crow);
        if (rrow != NULL) {
            BIO_printf(bio_err,
                "ERROR:There is already a certificate for %s\n",
                row[DB_name]);
```

## Call pattern 8

```c
BIGNUM *bn = NULL;
    int ok = -1, i;

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
    bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x509), NULL);
    if (!bn)
        goto end;
    if (BN_is_zero(bn))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = BN_bn2hex(bn);
    BN_free(bn);
    if (row[DB_name] != NULL && row[DB_name][0] == '\0') {
        /* Entries with empty Subjects actually use the serial number instead */
        OPENSSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
    }
    if ((row[DB_name] == NULL) || (row[DB_serial] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }
    /*
     * We have to lookup by serial number because name lookup skips revoked
     * certs
     */
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        BIO_printf(bio_err,
            "Adding Entry with serial number %s to DB for %s\n",
            row[DB_serial], row[DB_name]);

        /* We now just add it to the database as DB_TYPE_REV('V') */
        row[DB_type] = OPENSSL_strdup("V");
        tm = X509_get0_notAfter(x509);
        row[DB_exp_date] = app_malloc(tm->length + 1, "row exp_data");
        memcpy(row[DB_exp_date], tm->data, tm->length);
        row[DB_exp_date][tm->length] = '\0';
        row[DB_rev_date] = NULL;
```

## Call pattern 9

```c
int ok = -1, i;

    for (i = 0; i < DB_NUMBER; i++)
        row[i] = NULL;
    row[DB_name] = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
    bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x509), NULL);
    if (!bn)
        goto end;
    if (BN_is_zero(bn))
        row[DB_serial] = OPENSSL_strdup("00");
    else
        row[DB_serial] = BN_bn2hex(bn);
    BN_free(bn);
    if (row[DB_name] != NULL && row[DB_name][0] == '\0') {
        /* Entries with empty Subjects actually use the serial number instead */
        OPENSSL_free(row[DB_name]);
        row[DB_name] = OPENSSL_strdup(row[DB_serial]);
    }
    if ((row[DB_name] == NULL) || (row[DB_serial] == NULL)) {
        BIO_printf(bio_err, "Memory allocation failure\n");
        goto end;
    }
    /*
     * We have to lookup by serial number because name lookup skips revoked
     * certs
     */
    rrow = TXT_DB_get_by_index(db->db, DB_serial, row);
    if (rrow == NULL) {
        BIO_printf(bio_err,
            "Adding Entry with serial number %s to DB for %s\n",
            row[DB_serial], row[DB_name]);

        /* We now just add it to the database as DB_TYPE_REV('V') */
        row[DB_type] = OPENSSL_strdup("V");
        tm = X509_get0_notAfter(x509);
        row[DB_exp_date] = app_malloc(tm->length + 1, "row exp_data");
        memcpy(row[DB_exp_date], tm->data, tm->length);
        row[DB_exp_date][tm->length] = '\0';
        row[DB_rev_date] = NULL;
        row[DB_file] = OPENSSL_strdup("unknown");
```


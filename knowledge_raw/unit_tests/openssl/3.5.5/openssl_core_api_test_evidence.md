# Unit Test and Example Evidence: OpenSSL 3.5.5 Core APIs

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## BN_bn2binpad

Status: found in local tests and internal callers.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/crypto`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/bntest.c`: direct tests around lines 1821, 1824, 1840, 1843, 1846, 1850, and 1855.
- Internal callers include `crypto/rsa/rsa_ossl.c`, `crypto/dh/dh_key.c`, `crypto/sm2/sm2_crypt.c`, `crypto/sm2/sm2_sign.c`.
- Manpage: `doc/man3/BN_bn2bin.pod`.

## BN_signed_bn2bin

Status: found in local tests and manpage.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/bntest.c`: signed conversion tests around lines 1943 and 1948.
- Manpage: `doc/man3/BN_bn2bin.pod`.

## BN_usub

Status: found in local tests and internal callers.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/crypto`

Evidence:

- `test/bntest.c`: direct tests around lines 1264, 1272, 1274, 1290, 1293, 1296, and 1299.
- Internal callers include `crypto/bn/bn_mont.c` and `crypto/bn/bn_gcd.c`.

## BN_sub

Status: found in local tests and internal callers.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/crypto`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/bntest.c`: direct tests around lines 262, 264, 307, 1232, 1234, 1250, 1253, 1256, and 1259.
- Manpage: `doc/man3/BN_add.pod`.
- Many internal callers in `crypto/bn`, `crypto/rsa`, `crypto/ffc`, and `crypto/sm2`.

## EVP_DigestVerifyInit / EVP_DigestVerifyInit_ex

Status: found in local tests, demos, and manpage.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/demos`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/evp_extra_test.c`: direct calls around lines 1949, 1996, 2009, 2017, 2530, 2639, and 2657.
- `test/algorithmid_test.c`: `EVP_DigestVerifyInit_ex` around line 154.
- Demos include `demos/signature/rsa_pss_hash.c`, `demos/signature/EVP_EC_Signature_demo.c`, `EVP_DSA_Signature_demo.c`, and `EVP_ED_Signature_demo.c`.
- Manpage: `doc/man3/EVP_DigestVerifyInit.pod`.

## EVP_DigestVerify

Status: found in local tests, demos, and manpage.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/demos`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/ecdsatest.c`: direct return-value checks around lines 255, 257, 260, 262, 265, 267, 273, 275, 280, 282, 315, 317, 322, and 324.
- `test/slh_dsa_test.c`: direct call around line 578.
- Demo: `demos/signature/EVP_ED_Signature_demo.c`.
- Manpage: `doc/man3/EVP_DigestVerifyInit.pod`.

## EVP_PKEY_verify

Status: found in local tests, demos, and manpage.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/demos`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/evp_extra_test.c`: direct calls around lines 1661 and 1738.
- `test/evp_test.c`: direct call around line 2939.
- `test/slh_dsa_test.c`: direct calls around lines 231, 421, 508, and 509.
- Demo: `demos/signature/rsa_pss_direct.c`.
- Manpage: `doc/man3/EVP_PKEY_verify.pod`.

## EVP_CipherFinal_ex

Status: found in local tests, demos, and manpage.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/demos`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/evp_extra_test.c`: direct calls around lines 4967, 5014, 5021, 5081, 5097, 5184, 5262, and 5296.
- `test/evp_test.c`: direct call around line 1410.
- `test/afalgtest.c` and `test/evp_fetch_prov_test.c`: direct calls.
- Manpage examples in `doc/man3/EVP_EncryptInit.pod`.

## EVP_DecryptFinal_ex

Status: found in local tests, demos, internal callers, and manpage.

Searched paths:

- `/home/wen/work/clean_sources/openssl-3.5.5/test`
- `/home/wen/work/clean_sources/openssl-3.5.5/demos`
- `/home/wen/work/clean_sources/openssl-3.5.5/crypto`
- `/home/wen/work/clean_sources/openssl-3.5.5/doc/man3`

Evidence:

- `test/aesgcmtest.c`: direct call around line 95.
- `test/evp_extra_test.c`: direct call around line 6307.
- Demos: `demos/cipher/aesgcm.c`, `demos/cipher/aeskeywrap.c`, `demos/cipher/ariacbc.c`.
- Internal callers include `crypto/pem/pem_lib.c`, `crypto/pkcs12/p12_decr.c`, `crypto/hpke/hpke.c`.
- Manpage: `doc/man3/EVP_EncryptInit.pod`.

# WOLFSSL-POC-0007 Candidate Selection

## Selected Candidate

- Candidate PoC ID: WOLFSSL-POC-0007
- CVE: CVE-2026-5295
- Module family: PKCS7 / CMS
- Bug class: PKCS7 ORI OID processing stack buffer overflow
- Primary vulnerable function:
  - wc_PKCS7_DecryptOri
- Expected vulnerable source region:
  - wolfcrypt/src/pkcs7.c
  - oriOID[MAX_OID_SZ]
  - XMEMCPY from ASN.1 parsed OID into fixed stack buffer

## Selection Rationale

This candidate expands the dataset beyond X.509, DTLS 1.3, and PKCS7 SignedData encoding.

Unlike WOLFSSL-POC-0006, this issue is expected to exercise a PKCS7/CMS parsing and decrypt callback path. The trigger shape is an EnvelopedData message containing OtherRecipientInfo with an oversized ORI OID.

## Expected Trigger Shape

- Build wolfSSL with PKCS7 support.
- Register an ORI decrypt callback using wc_PKCS7_SetOriDecryptCb.
- Feed a crafted CMS EnvelopedData / PKCS7 envelope containing an ORI recipient.
- Make the ORI OID longer than MAX_OID_SZ / 32 bytes.
- Trigger wc_PKCS7_DecryptOri.
- Observe sanitizer-visible stack buffer overflow in vulnerable version.

## Initial Quality Status

- Status: candidate selected
- Vulnerable version: pending
- Fixed version: pending
- Current version: pending

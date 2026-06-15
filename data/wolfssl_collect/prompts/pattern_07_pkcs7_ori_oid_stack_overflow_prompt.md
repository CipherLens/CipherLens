# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: Pattern-07
- Name: PKCS7 ORI OID / fixed stack OID buffer overflow
- Related PoC: WOLFSSL-POC-0007
- Trigger surface: pkcs7_ori_recipient_decryption
- Input type: reconstructed_pkcs7_envelopeddata_ori_oversized_oid
- Quality level: Q1_strict_reproduction_candidate

## Bug Mechanism

Core issue:

An ASN.1 parsed ORI OBJECT IDENTIFIER length is trusted and copied into a fixed stack OID buffer before validating capacity.

Trust boundary:

ASN.1 PKCS7/CMS EnvelopedData OtherRecipientInfo oriType OID -> wc_PKCS7_DecryptOri stack buffer

Vulnerable operation:

XMEMCPY copies oriOIDSz bytes into oriOID[MAX_OID_SZ] without checking oriOIDSz <= MAX_OID_SZ first

Failure modes:

stack_buffer_overflow, out_of_bounds_write, oid_length_trust_boundary_error, sanitizer_visible_crash

## Recipe Slots

- ori_oid_length: controls the number of bytes copied into the fixed ORI OID stack buffer | observed: 80 | mutation: encode oriType OBJECT IDENTIFIER with length greater than MAX_OID_SZ
- destination_capacity: capacity of fixed stack OID buffer | observed: MAX_OID_SZ / sizeof(oriOID)
- destination_buffer: local ORI OID destination | observed: byte oriOID[MAX_OID_SZ]
- parsed_length_variable: ASN.1 OID length returned by GetASNObjectId | observed: oriOIDSz
- copy_operation: copies ASN.1 OID bytes into fixed stack buffer | observed: XMEMCPY(oriOID, pkiMsg + *idx, (word32)oriOIDSz)
- callback_reachability: ORI decrypt path requires registered callback | observed: wc_PKCS7_SetOriDecryptCb
- api_entrypoint: public API path that reaches ORI OID parsing

## Mutation Strategy

- Construct a PKCS7/CMS EnvelopedData input.
- Include RecipientInfo with ORI / OtherRecipientInfo encoding.
- Encode oriType as an ASN.1 OBJECT IDENTIFIER with length greater than MAX_OID_SZ.
- Include a minimal oriValue so parsing reaches the ORI callback path.
- Register an ORI decrypt callback with wc_PKCS7_SetOriDecryptCb.
- Call wc_PKCS7_DecodeEnvelopedData.
- Observe whether wc_PKCS7_DecryptOri rejects the oversized OID before copying.

## Oracle

Primary oracle: asan_stack_buffer_overflow

Signals:

- ERROR: AddressSanitizer: stack-buffer-overflow
- WRITE of size 80
- crash in wc_PKCS7_DecryptOri
- crash path includes wc_PKCS7_DecodeEnvelopedData
- sanitizer report shows oriOID overflow

Fixed behavior:

- wc_PKCS7_DecodeEnvelopedData returns -140
- safe rejection
- NO_ASAN_CRASH_OBSERVED
- no sanitizer crash

## AST Masking Targets

- fixed stack OID buffer declaration
- ASN.1 OID length extraction
- missing OID length upper-bound check
- XMEMCPY from ASN.1 input into stack buffer
- fixed-version oriOIDSz <= MAX_OID_SZ guard

## RAG Keywords

wc_PKCS7_DecodeEnvelopedData, wc_PKCS7_DecryptOri, wc_PKCS7_SetOriDecryptCb, OtherRecipientInfo, ORI, oriType, oriValue, oriOID, oriOIDSz, MAX_OID_SZ, GetASNObjectId, XMEMCPY, ASN_PARSE_E

## Task

You are given source code from a cryptographic library.

Find code regions that may implement the same vulnerability pattern.

Focus on:

1. Whether untrusted ASN.1 / X.509 length or count values cross into fixed-size buffers.
2. Whether the checked length differs from the copied length.
3. Whether setter APIs store untrusted length without capacity validation.
4. Whether getter, text extraction, or DER re-encoding paths trust previously stored values.
5. Whether compatibility APIs copy into caller-provided buffers.

For each suspicious code region, report:

- Function name
- File path
- Relevant variables
- Guard condition
- Copy or write operation
- Destination capacity
- Why it matches this pattern
- A suggested mutation or test input shape

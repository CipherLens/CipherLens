import json
import re
from pathlib import Path

ROOT = Path(".")
BUILD_ROOT = Path("~/workplace/CryptoPoc/Builds/wolfssl_repro").expanduser()

BASE_JSONL = ROOT / "data/jsonl/wolfssl_pattern_prompt_eval_v1.jsonl"
OUT_JSONL = ROOT / "data/jsonl/wolfssl_code_localization_eval_v1.jsonl"


CONFIG = {
    "Pattern-01": {
        "vulnerable_build_candidates": [
            "wolfssl-4.2.0-asan-extra",
            "wolfssl-4.2.0-asan"
        ],
        "fixed_build_candidates": [
            "wolfssl-4.3.0-asan-extra",
            "wolfssl-4.3.0-asan"
        ],
        "source_file": "wolfcrypt/src/asn.c",
        "function_name": "GetName",
        "anchor_patterns": [
            "dName->loc[count++]"
        ],
        "before": 60,
        "after": 80,
        "mask_regexes": [
            [
                r"dName->loc\[count\+\+\]\s*=\s*[^;]+;",
                "/* MASKED_VULNERABLE_WRITE: dName->loc[count++] assignment without sufficient count bound */"
            ]
        ],
        "ground_truth": {
            "file": "wolfcrypt/src/asn.c",
            "function": "GetName",
            "vulnerable_operation": "dName->loc[count++] = ...",
            "guard_condition": "missing or insufficient bound check on count before writing into dName->loc",
            "destination_capacity": "fixed-size dName->loc array",
            "matched_recipe_slots": [
                "name_sequence_count",
                "parser_state_capacity",
                "name_field_type"
            ]
        },
        "answer": "The suspicious region is in GetName in wolfcrypt/src/asn.c. The parser records parsed X.509 name field identifiers into dName->loc using count++. In the vulnerable pattern, repeated or malformed name fields can increase count beyond the fixed-size location array capacity. The write dName->loc[count++] = ... matches the recipe because the index is derived from parsed ASN.1 name element count and must be bounded before the assignment."
    },
    "Pattern-02": {
        "vulnerable_build_candidates": [
            "wolfssl-3.10.2-asan",
            "wolfssl-v3.10.2-stable-asan-certfields"
        ],
        "fixed_build_candidates": [
            "wolfssl-v3.11.0-stable-asan-certfields",
            "wolfssl-3.11.0-asan"
        ],
        "source_file": "src/ssl.c",
        "function_name": "wolfSSL_X509_NAME_get_text_by_NID",
        "anchor_patterns": [
            "wolfSSL_X509_NAME_get_text_by_NID",
            "buf[textSz]",
            "buf[len]"
        ],
        "before": 40,
        "after": 90,
        "mask_regexes": [
            [
                r"buf\[[^\]]+\]\s*=\s*'\\0';",
                "/* MASKED_VULNERABLE_TERMINATOR_WRITE: possible off-by-one NUL write */"
            ],
            [
                r"XMEMCPY\([^;]+;",
                "/* MASKED_COPY: text copied into caller-provided fixed-size buffer */"
            ]
        ],
        "ground_truth": {
            "file": "src/ssl.c",
            "function": "wolfSSL_X509_NAME_get_text_by_NID",
            "vulnerable_operation": "copy text field into caller buffer and append NUL terminator",
            "guard_condition": "length check does not correctly reserve space for trailing NUL",
            "destination_capacity": "caller-provided buffer length",
            "matched_recipe_slots": [
                "target_text_field",
                "output_buffer_size",
                "field_text_length",
                "terminator_policy",
                "nid_selector"
            ]
        },
        "answer": "The suspicious region is wolfSSL_X509_NAME_get_text_by_NID in src/ssl.c. The function copies a selected X.509 text field into a caller-provided buffer and appends a string terminator. It matches the off-by-one recipe because a field length equal to the output buffer size can make the terminator write land one byte past the stack buffer."
    },
    "Pattern-03": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-x509date",
            "wolfssl-5.9.0-asan-x509date"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.1-stable-asan-x509date",
            "wolfssl-5.9.1-asan-x509date"
        ],
        "source_file": "src/x509.c",
        "function_name": "wolfSSL_X509_set_notAfter",
        "anchor_patterns": [
            "wolfSSL_X509_set_notAfter",
            "x509->notAfter.length",
            "XMEMCPY(x509->notAfter.data"
        ],
        "before": 50,
        "after": 90,
        "mask_regexes": [
            [
                r"x509->notAfter\.length\s*=\s*t->length;",
                "/* MASKED_LENGTH_STORE: stores untrusted ASN1_TIME length */"
            ],
            [
                r"XMEMCPY\(x509->notAfter\.data[^;]+;",
                "/* MASKED_VULNERABLE_COPY: copies ASN1_TIME data using untrusted length */"
            ]
        ],
        "ground_truth": {
            "file": "src/x509.c",
            "function": "wolfSSL_X509_set_notAfter",
            "vulnerable_operation": "store ASN1_TIME length and copy data using t->length",
            "guard_condition": "missing capacity check that t->length fits internal date buffer",
            "destination_capacity": "internal WOLFSSL_ASN1_TIME / X509 date buffer",
            "matched_recipe_slots": [
                "time_object_type",
                "declared_time_length",
                "actual_data_capacity",
                "target_date_field",
                "accessor_path"
            ]
        },
        "answer": "The suspicious region is the X.509 notAfter setter/accessor path in src/x509.c. The vulnerability pattern is that a crafted ASN1_TIME object carries an oversized declared length. If the setter stores this length or copies data using it without checking the internal buffer capacity, a later accessor or serializer can trigger a heap-buffer-overflow. The same reasoning also applies to the notBefore path."
    },
    "Pattern-04": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-akid"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.1-stable-asan-akid"
        ],
        "source_file": "src/x509.c",
        "function_name": "CertFromX509",
        "anchor_patterns": [
            "XMEMCPY(cert->akid, x509->authKeyIdSrc, x509->authKeyIdSrcSz)",
            "authKeyIdSrcSz",
            "authKeyIdSz < sizeof(cert->akid)"
        ],
        "before": 40,
        "after": 70,
        "mask_regexes": [
            [
                r"if\s*\(x509->authKeyIdSz\s*<\s*sizeof\(cert->akid\)\)",
                "if (/* MASKED_GUARD: checked length may differ from copied length */)"
            ],
            [
                r"XMEMCPY\(cert->akid,\s*x509->authKeyIdSrc,\s*x509->authKeyIdSrcSz\);",
                "/* MASKED_VULNERABLE_COPY: copies authKeyIdSrcSz into cert->akid */"
            ]
        ],
        "ground_truth": {
            "file": "src/x509.c",
            "function": "CertFromX509",
            "vulnerable_operation": "XMEMCPY(cert->akid, x509->authKeyIdSrc, x509->authKeyIdSrcSz)",
            "guard_condition": "guard checks authKeyIdSz but copy uses authKeyIdSrcSz",
            "destination_capacity": "sizeof(cert->akid)",
            "matched_recipe_slots": [
                "checked_length",
                "copied_length",
                "destination_capacity",
                "oversized_substructure",
                "conversion_path"
            ]
        },
        "answer": "The suspicious region is CertFromX509 in src/x509.c. The old guard checks x509->authKeyIdSz against sizeof(cert->akid), but the WOLFSSL_AKID_NAME branch copies x509->authKeyIdSrcSz bytes into cert->akid. This directly matches the checked-length versus copied-length recipe. A crafted AuthorityKeyIdentifier with a small keyIdentifier and a large authorityCertIssuer URI makes authKeyIdSz small while authKeyIdSrcSz is much larger, producing a heap-buffer-overflow."
    },
    "Pattern-05": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-dtls13-ack"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.1-stable-asan-dtls13-ack"
        ],
        "source_file": "src/dtls13.c",
        "function_name": "Dtls13WriteAckMessage",
        "anchor_patterns": [
            "ret = Dtls13GetAckListLength(recordNumberList, &msgSz)",
            "while (recordNumberList != NULL)",
            "c64toa(&recordNumberList->epoch, ackMessage)"
        ],
        "before": 45,
        "after": 80,
        "mask_regexes": [
            [
                r"ret\s*=\s*Dtls13GetAckListLength\(recordNumberList,\s*&msgSz\);",
                "ret = /* MASKED_LENGTH_COMPUTATION: unbounded ACK list length is truncated into word16 msgSz */;"
            ],
            [
                r"ret\s*=\s*CheckAvailableSize\(ssl,\s*sendSz\);",
                "ret = /* MASKED_BUFFER_CHECK: uses sendSz derived from truncated msgSz */;"
            ],
            [
                r"while\s*\(recordNumberList\s*!=\s*NULL\)\s*\{",
                "while (/* MASKED_SERIALIZATION_LOOP: iterates over full unbounded ACK list */) {"
            ],
            [
                r"c64toa\(&recordNumberList->epoch,\s*ackMessage\);",
                "/* MASKED_WRITE: writes epoch for every ACK record into output buffer */;"
            ],
            [
                r"c64toa\(&recordNumberList->seq,\s*ackMessage\);",
                "/* MASKED_WRITE: writes sequence for every ACK record into output buffer */;"
            ]
        ],
        "ground_truth": {
            "file": "src/dtls13.c",
            "function": "Dtls13WriteAckMessage",
            "vulnerable_operation": "ACK serialization loop writes every Dtls13RecordNumber using c64toa while buffer sizing is based on msgSz stored as word16",
            "guard_condition": "vulnerable version has no maximum ACK record count guard before Dtls13GetAckListLength truncates DTLS13_RN_SIZE * numberElements into word16",
            "destination_capacity": "output buffer capacity checked by CheckAvailableSize using sendSz derived from truncated msgSz",
            "matched_recipe_slots": [
                "ack_record_count",
                "record_number_encoding_size",
                "encoded_length_type",
                "truncated_length_expression",
                "serialization_loop",
                "output_buffer_path",
                "fixed_record_bound"
            ]
        },
        "answer": "The suspicious region is Dtls13WriteAckMessage in src/dtls13.c. The vulnerable version computes the ACK list size by counting all records, then stores DTLS13_RN_SIZE * numberElements into a word16 msgSz. With 4097 records this length wraps or truncates, so CheckAvailableSize validates a buffer sized for the truncated value. The later while(recordNumberList != NULL) serialization loop still writes every ACK record using c64toa for epoch and sequence values, producing an out-of-bounds heap write. The fixed version adds seenRecordsCount / DTLS13_ACK_MAX_RECORDS bounds and passes the bounded count into Dtls13WriteAckMessage."
    }
,
    "Pattern-06": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.8.4-stable-asan-pkcs7-signedattrs"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-pkcs7-signedattrs"
        ],
        "source_file": "wolfcrypt/src/pkcs7.c",
        "function_name": "wc_PKCS7_BuildSignedAttributes",
        "anchor_patterns": [
            "add custom signed attributes if set",
            "esd->signedAttribsCount += pkcs7->signedAttribsSz",
            "&esd->signedAttribs[atrIdx]",
            "EncodeAttributes"
        ],
        "before": 70,
        "after": 65,
        "mask_regexes": [
            [
                r"esd->signedAttribsCount\s*\+=\s*pkcs7->signedAttribsSz;",
                "/* MASKED_COUNT_UPDATE: caller-controlled custom attribute count is added to internal signed attribute count */;"
            ],
            [
                r"esd->signedAttribsSz\s*\+=\s*\(word32\)EncodeAttributes\(",
                "esd->signedAttribsSz += (word32)/* MASKED_ENCODER_CALL: custom attributes are encoded into a fixed internal array */("
            ],
            [
                r"&esd->signedAttribs\[atrIdx\]",
                "/* MASKED_DESTINATION_ARRAY: fixed internal signedAttribs array at insertion index */"
            ],
            [
                r"\(int\)esd->signedAttribsCount",
                "/* MASKED_WRITE_COUNT: count may exceed fixed array capacity */"
            ],
            [
                r"word32\s+availableSpace\s*=\s*MAX_SIGNED_ATTRIBS_SZ\s*-\s*atrIdx;",
                "word32 availableSpace = /* MASKED_FIXED_GUARD: remaining fixed-array capacity */;"
            ],
            [
                r"if\s*\(pkcs7->signedAttribsSz\s*>\s*availableSpace\)",
                "if (/* MASKED_FIXED_CHECK: reject oversized custom signed attributes */)"
            ]
        ],
        "ground_truth": {
            "file": "wolfcrypt/src/pkcs7.c",
            "function": "wc_PKCS7_BuildSignedAttributes",
            "vulnerable_operation": "EncodeAttributes writes caller-controlled custom PKCS7Attrib entries into esd->signedAttribs starting at atrIdx without checking remaining fixed-array capacity",
            "guard_condition": "vulnerable version lacks availableSpace = MAX_SIGNED_ATTRIBS_SZ - atrIdx check before encoding pkcs7->signedAttribs",
            "destination_capacity": "fixed internal signed attribute descriptor array: esd->signedAttribs / signedAttribs[7] / MAX_SIGNED_ATTRIBS_SZ",
            "matched_recipe_slots": [
                "custom_attribute_count",
                "internal_attribute_capacity",
                "existing_attribute_index",
                "remaining_capacity",
                "destination_array",
                "encoder_function",
                "api_entrypoint"
            ]
        },
        "answer": "The suspicious region is wc_PKCS7_BuildSignedAttributes in wolfcrypt/src/pkcs7.c. In the vulnerable version, the custom signed attributes branch adds pkcs7->signedAttribsSz to esd->signedAttribsCount and then calls EncodeAttributes with &esd->signedAttribs[atrIdx] as the destination. There is no remaining-capacity check against the fixed signedAttribs[7] array, so a caller-controlled PKCS7Attrib array with 8 entries causes EncodeAttributes to write past the internal fixed array. The fixed version introduces availableSpace = MAX_SIGNED_ATTRIBS_SZ - atrIdx and returns BUFFER_E when pkcs7->signedAttribsSz exceeds the remaining capacity."
    }
,
    "Pattern-07": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-pkcs7-ori-oid"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.1-stable-asan-pkcs7-ori-oid"
        ],
        "source_file": "wolfcrypt/src/pkcs7.c",
        "function_name": "wc_PKCS7_DecryptOri",
        "anchor_patterns": [
            "Decrypt ASN.1 OtherRecipientInfo",
            "byte oriOID[MAX_OID_SZ]",
            "GetASNObjectId(pkiMsg, idx, &oriOIDSz, pkiMsgSz)",
            "XMEMCPY(oriOID, pkiMsg + *idx, (word32)oriOIDSz)"
        ],
        "before": 60,
        "after": 55,
        "mask_regexes": [
            [
                r"byte\s+oriOID\[MAX_OID_SZ\];",
                "byte /* MASKED_DESTINATION_BUFFER: fixed stack OID buffer */;"
            ],
            [
                r"if\s*\(GetASNObjectId\(pkiMsg,\s*idx,\s*&oriOIDSz,\s*pkiMsgSz\)\s*!=\s*0\)",
                "if (/* MASKED_PARSE_LENGTH: ASN.1 ORI OID length is parsed from untrusted input */)"
            ],
            [
                r"if\s*\(oriOIDSz\s*<=\s*0\s*\|\|\s*\(word32\)oriOIDSz\s*>\s*MAX_OID_SZ\)",
                "if (/* MASKED_FIXED_GUARD: reject OID length larger than fixed stack buffer */)"
            ],
            [
                r"XMEMCPY\(oriOID,\s*pkiMsg\s*\+\s*\*idx,\s*\(word32\)oriOIDSz\);",
                "/* MASKED_VULNERABLE_COPY: copies parsed ORI OID length into fixed stack buffer */;"
            ],
            [
                r"\*idx\s*\+=\s*\(word32\)oriOIDSz;",
                "/* MASKED_INDEX_ADVANCE: advances by parsed OID length */;"
            ],
            [
                r"ret\s*=\s*pkcs7->oriDecryptCb\(pkcs7,\s*oriOID,\s*\(word32\)oriOIDSz,",
                "ret = /* MASKED_CALLBACK_PATH: ORI callback receives copied OID */("
            ]
        ],
        "ground_truth": {
            "file": "wolfcrypt/src/pkcs7.c",
            "function": "wc_PKCS7_DecryptOri",
            "vulnerable_operation": "XMEMCPY(oriOID, pkiMsg + *idx, (word32)oriOIDSz)",
            "guard_condition": "vulnerable version lacks oriOIDSz <= MAX_OID_SZ validation before copying into oriOID[MAX_OID_SZ]",
            "destination_capacity": "MAX_OID_SZ / sizeof(oriOID), fixed stack buffer byte oriOID[MAX_OID_SZ]",
            "matched_recipe_slots": [
                "ori_oid_length",
                "destination_capacity",
                "destination_buffer",
                "parsed_length_variable",
                "copy_operation",
                "callback_reachability",
                "api_entrypoint"
            ]
        },
        "answer": "The suspicious region is wc_PKCS7_DecryptOri in wolfcrypt/src/pkcs7.c. The vulnerable code parses the ORI oriType OBJECT IDENTIFIER length into oriOIDSz using GetASNObjectId, then copies oriOIDSz bytes from the PKCS7/CMS input into the fixed stack buffer oriOID[MAX_OID_SZ]. In v5.9.0 there is no upper-bound check before XMEMCPY, so an OtherRecipientInfo with an 80-byte OID overflows the 32-byte stack buffer. The fixed version adds an oriOIDSz <= 0 || oriOIDSz > MAX_OID_SZ guard and rejects the oversized ORI OID before the copy."
    }
,
    "Pattern-08": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-pqc-keyshare-cleanup"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.1-stable-asan-pqc-keyshare-cleanup"
        ],
        "source_file": "src/tls.c",
        "function_name": "TLSX_KeyShare_ProcessPqcHybridClient",
        "anchor_patterns": [
            "TLSX_KeyShare_ProcessPqcHybridClient",
            "TLSX_KeyShare_FreeAll(ecc_kse",
            "TLSX_KeyShare_FreeAll(pqc_kse",
            "keyShareEntry->key"
        ],
        "before": 80,
        "after": 90,
        "mask_regexes": [
            [
                r"keyShareEntry->key\s*=\s*ecc_kse->key;",
                "keyShareEntry->key = /* MASKED_OWNERSHIP_TRANSFER: transferred ECC/PQC hybrid key pointer */;"
            ],
            [
                r"ecc_kse->key\s*=\s*NULL;",
                "/* MASKED_FIXED_NULLING: detach transferred key pointer before cleanup */;"
            ],
            [
                r"pqc_kse->key\s*=\s*NULL;",
                "/* MASKED_FIXED_NULLING: detach PQC key pointer before cleanup */;"
            ],
            [
                r"pqc_kse->privKey\s*=\s*NULL;",
                "/* MASKED_FIXED_NULLING: detach PQC private key pointer before cleanup */;"
            ],
            [
                r"TLSX_KeyShare_FreeAll\(ecc_kse,\s*ssl->heap\);",
                "/* MASKED_CLEANUP_CALL: frees temporary ECC key share entry */;"
            ],
            [
                r"TLSX_KeyShare_FreeAll\(pqc_kse,\s*ssl->heap\);",
                "/* MASKED_CLEANUP_CALL: frees temporary PQC key share entry */;"
            ],
            [
                r"ret\s*=\s*TLSX_KeyShare_ProcessPqcHybridClient\(",
                "ret = /* MASKED_PROCESSING_PATH: process truncated hybrid key share */("
            ],
            [
                r"TLSX_KeyShare_FreeAll\([^;\n]*\);",
                "/* MASKED_CLEANUP_CALL: frees KeyShare entry during error cleanup */;"
            ],
            [
                r"[A-Za-z_][A-Za-z0-9_]*->key\s*=\s*[^;\n]+;",
                "/* MASKED_KEY_POINTER_ASSIGNMENT: KeyShare key pointer ownership changes here */;"
            ],
            [
                r"[A-Za-z_][A-Za-z0-9_]*->privKey\s*=\s*[^;\n]+;",
                "/* MASKED_PRIVKEY_POINTER_ASSIGNMENT: PQC private key pointer ownership changes here */;"
            ],
            [
                r"[A-Za-z_][A-Za-z0-9_]*->key\s*=\s*NULL;",
                "/* MASKED_FIXED_NULLING: key pointer detached before cleanup */;"
            ],
            [
                r"[A-Za-z_][A-Za-z0-9_]*->privKey\s*=\s*NULL;",
                "/* MASKED_FIXED_NULLING: private key pointer detached before cleanup */;"
            ]
        ],
        "ground_truth": {
            "file": "src/tls.c",
            "function": "TLSX_KeyShare_ProcessPqcHybridClient",
            "vulnerable_operation": "ownership transfer and cleanup of hybrid KeyShare entries leaves stale key pointers that are later revisited by TLSX_KeyShare_FreeAll",
            "guard_condition": "vulnerable version fails to reliably NULL transferred ECC/PQC key pointers before temporary KeyShare cleanup",
            "destination_capacity": "not a fixed buffer issue; ownership capacity is the single owner invariant for KeyShare key material",
            "matched_recipe_slots": [
                "hybrid_group",
                "key_exchange_length",
                "expected_keyshare_size",
                "ownership_transfer",
                "cleanup_path",
                "processing_path",
                "fixed_pointer_sanitization"
            ]
        },
        "answer": "The suspicious region is TLSX_KeyShare_ProcessPqcHybridClient in src/tls.c. The vulnerable path processes a truncated TLS 1.3 PQC hybrid KeyShare and transfers key material between temporary ECC/PQC KeyShare entries and the final hybrid keyShareEntry. In v5.9.0, the error cleanup path can leave keyShareEntry or temporary entries still pointing to already-freed ML-KEM/Kyber key material. Later, wolfSSL_free walks TLS extensions through TLSX_FreeAll and TLSX_KeyShare_FreeAll, causing ForceZero to write to freed memory. The fixed version nulls transferred pointers such as ecc_kse->key, pqc_kse->key, or pqc_kse->privKey before cleanup so each key object has only one owner."
    }
,
    "Pattern-09": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.8.4-stable-asan-session-deser"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-session-deser"
        ],
        "source_file": "src/ssl_sess.c",
        "function_name": "wolfSSL_d2i_SSL_SESSION",
        "anchor_patterns": [
            "wolfSSL_d2i_SSL_SESSION",
            "SESSION_CERTS",
            "chain.count",
            "MAX_CHAIN_DEPTH"
        ],
        "before": 70,
        "after": 110,
        "mask_regexes": [
            [
                r"s->chain\.count\s*=\s*input\[[^\]]+\];",
                "s->chain.count = /* MASKED_DESERIALIZED_COUNT: untrusted SESSION_CERTS chain count */;"
            ],
            [
                r"if\s*\(\s*s->chain\.count\s*>\s*MAX_CHAIN_DEPTH\s*\)",
                "if (/* MASKED_FIXED_GUARD: reject chain.count larger than fixed certificate-chain array */)"
            ],
            [
                r"for\s*\([^;]*;\s*j\s*<\s*s->chain\.count\s*;[^)]*\)",
                "for (/* MASKED_VULNERABLE_LOOP: iterates over untrusted chain.count */)"
            ],
            [
                r"s->chain\.certs\[j\]\.buffer\s*=",
                "s->chain.certs[j].buffer = /* MASKED_FIXED_ARRAY_WRITE: writes into fixed x509_buffer array */"
            ],
            [
                r"s->chain\.certs\[j\]\.length\s*=",
                "s->chain.certs[j].length = /* MASKED_FIXED_ARRAY_WRITE: writes certificate length into fixed array */"
            ],
            [
                r"XMEMCPY\(s->chain\.certs\[j\]\.buffer,[^;]+;",
                "/* MASKED_CERT_COPY: copies serialized certificate into chain.certs[j].buffer */;"
            ],
            [
                r"if\s*\(\s*certSz\s*>\s*MAX_X509_SIZE\s*\)",
                "if (/* MASKED_FIXED_GUARD: reject serialized certificate length larger than MAX_X509_SIZE */)"
            ],
            [
                r"s->chain\.count[^;\n]*;",
                "/* MASKED_CHAIN_COUNT_USE: deserialized certificate-chain count controls parsing */;"
            ],
            [
                r"s->chain\.certs\[[^\]]+\]",
                "s->chain.certs[/* MASKED_FIXED_ARRAY_INDEX: index derived from chain.count */]"
            ],
            [
                r"MAX_CHAIN_DEPTH",
                "/* MASKED_CAPACITY_CONSTANT: MAX_CHAIN_DEPTH */"
            ],
            [
                r"wolfSSL_d2i_SSL_SESSION",
                "/* MASKED_API_ENTRYPOINT: wolfSSL_d2i_SSL_SESSION */"
            ]
        ],
        "ground_truth": {
            "file": "src/ssl_sess.c",
            "function": "wolfSSL_d2i_SSL_SESSION",
            "vulnerable_operation": "deserialized SESSION_CERTS chain.count controls writes into fixed x509_buffer certificate-chain array",
            "guard_condition": "vulnerable version lacks chain.count <= MAX_CHAIN_DEPTH validation before iterating over s->chain.certs[j]",
            "destination_capacity": "MAX_CHAIN_DEPTH / x509_buffer[9]",
            "matched_recipe_slots": [
                "serialized_session_source",
                "chain_count",
                "destination_capacity",
                "destination_array",
                "api_entrypoint",
                "fixed_guard"
            ]
        },
        "answer": "The suspicious region is wolfSSL_d2i_SSL_SESSION in src/ssl_sess.c. When SESSION_CERTS is enabled, the function deserializes chain.count from external SSL_SESSION data and then uses that count to populate s->chain.certs[j], a fixed certificate-chain array backed by x509_buffer entries. In v5.8.4, an attacker-controlled chain.count such as 0xff is not validated against MAX_CHAIN_DEPTH before the loop, so writes to s->chain.certs[j].length and s->chain.certs[j].buffer run past the fixed array. The fixed version rejects chain.count values greater than MAX_CHAIN_DEPTH and also validates certificate lengths before copying."
    }
,
    "Pattern-10": {
        "vulnerable_build_candidates": [
            "wolfssl-v5.8.4-stable-asan-alpn-parser"
        ],
        "fixed_build_candidates": [
            "wolfssl-v5.9.0-stable-asan-alpn-parser"
        ],
        "source_file": "src/ssl.c",
        "function_name": "wolfSSL_select_next_proto",
        "anchor_patterns": [
            "wolfSSL_select_next_proto",
            "serverNames",
            "clientNames",
            "XMEMCMP"
        ],
        "before": 70,
        "after": 90,
        "mask_regexes": [
            [
                r"XMEMCMP\([^;\\n]+;",
                "/* MASKED_OVERREAD_COMPARE: compares protocol names using untrusted length */;"
            ],
            [
                r"memcmp\([^;\\n]+;",
                "/* MASKED_OVERREAD_COMPARE: compares protocol names using untrusted length */;"
            ],
            [
                r"serverNames\[[^\\]]+\\]",
                "serverNames[/* MASKED_SERVER_PROTOCOL_LENGTH_OR_INDEX */]"
            ],
            [
                r"clientNames\[[^\\]]+\\]",
                "clientNames[/* MASKED_CLIENT_PROTOCOL_LENGTH_OR_INDEX */]"
            ],
            [
                r"serverLen",
                "/* MASKED_SERVER_BUFFER_LENGTH */"
            ],
            [
                r"clientLen",
                "/* MASKED_CLIENT_BUFFER_LENGTH */"
            ],
            [
                r"i\s*\+\s*serverNames\[[^\\]]+\\]",
                "/* MASKED_FIXED_GUARD: server protocol length must fit in remaining buffer */"
            ],
            [
                r"j\s*\+\s*clientNames\[[^\\]]+\\]",
                "/* MASKED_FIXED_GUARD: client protocol length must fit in remaining buffer */"
            ]
        ],
        "ground_truth": {
            "file": "src/ssl.c",
            "function": "wolfSSL_select_next_proto",
            "vulnerable_operation": "protocol length byte from malformed ALPN/NPN list is used as memcmp/XMEMCMP length without validating it against the remaining buffer",
            "guard_condition": "vulnerable version lacks validation that declared server/client protocol lengths fit within serverLen/clientLen before comparison",
            "destination_capacity": "actual protocol-list heap buffer length, observed 5 bytes in the PoC",
            "matched_recipe_slots": [
                "server_protocol_length",
                "client_protocol_length",
                "actual_buffer_size",
                "comparison_length",
                "comparison_operation",
                "api_entrypoint",
                "fixed_guard"
            ]
        },
        "answer": "The suspicious region is wolfSSL_select_next_proto in src/ssl.c. The function parses length-prefixed ALPN/NPN protocol lists and compares server and client protocol names. In v5.8.4, the declared protocol length byte can be larger than the actual remaining buffer, but the code still uses that value as the memcmp/XMEMCMP length. A 5-byte heap buffer with length byte 200 therefore causes a heap-buffer-over-read. The fixed version validates the declared protocol length against the remaining server/client list length before comparing or selecting a protocol."
    }

}


def read_jsonl(path):
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def find_build_dir(candidates):
    tried = []
    for name in candidates:
        p = BUILD_ROOT / name
        tried.append(str(p))
        if p.exists():
            return p
    raise FileNotFoundError("No build directory found. Tried:\n" + "\n".join(tried))


def find_anchor_line(lines, anchor_patterns):
    for pattern in anchor_patterns:
        for idx, line in enumerate(lines):
            if pattern in line:
                return idx
    return None


def extract_snippet(file_path, anchor_patterns, before, after):
    text = file_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    idx = find_anchor_line(lines, anchor_patterns)
    if idx is None:
        raise RuntimeError(f"anchor not found in {file_path}: {anchor_patterns}")

    start = max(0, idx - before)
    end = min(len(lines), idx + after + 1)

    snippet_lines = []
    for i in range(start, end):
        snippet_lines.append(f"{i + 1}: {lines[i]}")

    return {
        "file_path": str(file_path),
        "relative_file": str(file_path.relative_to(file_path.parents[2])) if len(file_path.parents) >= 3 else str(file_path),
        "anchor_line": idx + 1,
        "start_line": start + 1,
        "end_line": end,
        "code": "\n".join(snippet_lines)
    }


def make_masked_code(code, regexes):
    masked = code
    for pattern, repl in regexes:
        masked = re.sub(pattern, repl, masked)
    return masked


def main():
    base_rows = read_jsonl(BASE_JSONL)
    out_rows = []

    for row in base_rows:
        pattern_id = row["pattern_id"]
        cfg = CONFIG[pattern_id]

        vuln_build = find_build_dir(cfg["vulnerable_build_candidates"])
        fixed_build = find_build_dir(cfg["fixed_build_candidates"])

        vuln_file = vuln_build / cfg["source_file"]
        fixed_file = fixed_build / cfg["source_file"]

        if not vuln_file.exists():
            raise FileNotFoundError(f"vulnerable source file not found: {vuln_file}")
        if not fixed_file.exists():
            raise FileNotFoundError(f"fixed source file not found: {fixed_file}")

        vulnerable_snippet = extract_snippet(
            vuln_file,
            cfg["anchor_patterns"],
            cfg["before"],
            cfg["after"]
        )

        fixed_snippet = extract_snippet(
            fixed_file,
            cfg["anchor_patterns"],
            cfg["before"],
            cfg["after"]
        )

        masked_code = make_masked_code(
            vulnerable_snippet["code"],
            cfg["mask_regexes"]
        )

        enhanced = dict(row)
        enhanced["task_type"] = "vulnerability_code_localization"
        enhanced["source_context"] = {
            "vulnerable_build": str(vuln_build),
            "fixed_build": str(fixed_build),
            "vulnerable_source_file": cfg["source_file"],
            "fixed_source_file": cfg["source_file"]
        }
        enhanced["vulnerable_code"] = vulnerable_snippet
        enhanced["fixed_code"] = fixed_snippet
        enhanced["masked_code"] = masked_code
        enhanced["ground_truth"] = cfg["ground_truth"]
        enhanced["ground_truth_answer"] = cfg["answer"]

        out_rows.append(enhanced)

    OUT_JSONL.parent.mkdir(parents=True, exist_ok=True)

    with OUT_JSONL.open("w", encoding="utf-8") as f:
        for row in out_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[OK] wrote {OUT_JSONL}")
    print(f"[OK] total samples: {len(out_rows)}")


if __name__ == "__main__":
    main()

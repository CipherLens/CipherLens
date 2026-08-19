/*
 * Normalized template for MBEDTLS-POC-0020:
 * RSA DER parser accepts trailing garbage after the top-level SEQUENCE.
 *
 * Source public API: mbedtls_pk_parse_key
 * Internal isolation APIs: mbedtls_rsa_parse_key, mbedtls_rsa_parse_pubkey
 *
 * Mask anchors:
 * - [DER_KIND]
 * - [PARSE_API_KIND]
 * - [TRAILING_GARBAGE_BYTES]
 * - [TRAILING_GARBAGE_LEN]
 * - [EXPECT_RET]
 * - [TOP_LEVEL_SEQUENCE_END_CHECK]
 * - [RSA_PRIVATE_PARSE_CALL]
 * - [RSA_PUBLIC_PARSE_CALL]
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/private/rsa.h"
#include "mbedtls/version.h"

/*
 * These functions are present in the mbedTLS RSA parser implementation used by
 * the source PoC, but may not be declared by the public headers under all build
 * configurations. The normalized source API remains mbedtls_pk_parse_key.
 */
int mbedtls_rsa_parse_key(mbedtls_rsa_context *rsa,
                          const unsigned char *key,
                          size_t keylen);

int mbedtls_rsa_parse_pubkey(mbedtls_rsa_context *rsa,
                             const unsigned char *key,
                             size_t keylen);

#ifndef MBEDTLS_ERR_RSA_BAD_INPUT_DATA
#error "MBEDTLS_ERR_RSA_BAD_INPUT_DATA is not defined"
#endif

#define DER_KIND_VALUE "[DER_KIND]"
#define PARSE_API_KIND_VALUE "[PARSE_API_KIND]"
#define TRAILING_GARBAGE_HEX "[TRAILING_GARBAGE_BYTES]"
#define TRAILING_GARBAGE_EXPECTED_LEN ((size_t) [TRAILING_GARBAGE_LEN])
#define EXPECTED_RETURN_VALUE [EXPECT_RET]

static int hexval(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_to_bin(const char *hex,
                      unsigned char *out,
                      size_t out_size,
                      size_t *out_len)
{
    size_t n = 0;
    int hi = -1;

    while (*hex != '\0') {
        int v;

        if (isspace((unsigned char) *hex)) {
            hex++;
            continue;
        }

        v = hexval((unsigned char) *hex);
        if (v < 0) {
            return -1;
        }

        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_size) {
                return -2;
            }
            out[n++] = (unsigned char) ((hi << 4) | v);
            hi = -1;
        }

        hex++;
    }

    if (hi >= 0) {
        return -3;
    }

    *out_len = n;
    return 0;
}

static void rsa_init_compat(mbedtls_rsa_context *rsa)
{
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER < 0x03000000
    mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);
#else
    mbedtls_rsa_init(rsa);
#endif
}

static const char *select_base_der_hex(const char *der_kind)
{
    /*
     * Regression-test-derived minimal private key from
     * data/pocs/core10/MBEDTLS-POC-0020/poc/poc_rsa_trailing_garbage.c,
     * with the top-level trailing INTEGER removed. The base object is a
     * complete PKCS#1 RSAPrivateKey SEQUENCE.
     */
    static const char *private_base_hex =
        "3063020100021100cc8ab070369ede72920e5a51523c8571"
        "02030100010211009a6318982a7231de1894c54aa4909201"
        "020900f3058fd8dc484d61020900d7770dbd8b78a2110209"
        "009471f14c26428401020813425f060c4b72210208052b93"
        "d01747a87c";

    /*
     * Regression-test-derived minimal public key from the same source PoC,
     * with the top-level trailing INTEGER removed. The base object is a
     * complete PKCS#1 RSAPublicKey SEQUENCE.
     */
    static const char *public_base_hex =
        "308189028181009f091e6968b474f76f0e9c237c1d895996"
        "ae704b4f6d706acec8d2daac6209bf524aa3f658d0283a"
        "dba1077f6cbe92e425dcde52290b239cade91be86c884254"
        "34986806e85734e159768f3dfea932baaa9409d25bace8ee"
        "9dce0cdde0903207299de575ae60feccf0daf82334ab836"
        "38539b0da74072f253acea8afc8e66bb70203010001";

    if (strcmp(der_kind, "private") == 0) {
        return private_base_hex;
    }
    if (strcmp(der_kind, "public") == 0) {
        return public_base_hex;
    }

    return NULL;
}

static int build_der_with_trailing_garbage(const char *base_hex,
                                           const char *trailing_hex,
                                           unsigned char *der,
                                           size_t der_size,
                                           size_t *der_len,
                                           size_t *trailing_len)
{
    int ret;
    size_t base_len = 0;

    ret = hex_to_bin(base_hex, der, der_size, &base_len);
    if (ret != 0) {
        return ret;
    }

    ret = hex_to_bin(trailing_hex,
                     der + base_len,
                     der_size - base_len,
                     trailing_len);
    if (ret != 0) {
        return ret;
    }

    *der_len = base_len + *trailing_len;
    return 0;
}

static int parse_with_selected_api(const char *parse_api_kind,
                                   const char *der_kind,
                                   const unsigned char *der,
                                   size_t der_len)
{
    int ret = -1;

    if (strcmp(parse_api_kind, "rsa_private") == 0) {
        mbedtls_rsa_context rsa;

        rsa_init_compat(&rsa);
        /* [RSA_PRIVATE_PARSE_CALL] */
        ret = mbedtls_rsa_parse_key(&rsa, der, der_len);
        mbedtls_rsa_free(&rsa);
        return ret;
    }

    if (strcmp(parse_api_kind, "rsa_public") == 0) {
        mbedtls_rsa_context rsa;

        rsa_init_compat(&rsa);
        /* [RSA_PUBLIC_PARSE_CALL] */
        ret = mbedtls_rsa_parse_pubkey(&rsa, der, der_len);
        mbedtls_rsa_free(&rsa);
        return ret;
    }

    if (strcmp(parse_api_kind, "pk_private") == 0) {
        mbedtls_pk_context pk;

        if (strcmp(der_kind, "private") != 0) {
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        }

        mbedtls_pk_init(&pk);
        ret = mbedtls_pk_parse_key(&pk, der, der_len, NULL, 0);
        mbedtls_pk_free(&pk);
        return ret;
    }

    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
}

int main(void)
{
    const char *der_kind = DER_KIND_VALUE;
    const char *parse_api_kind = PARSE_API_KIND_VALUE;
    const char *base_hex = NULL;
    unsigned char *der = NULL;
    const size_t der_capacity = 512;
    size_t der_len = 0;
    size_t trailing_len = 0;
    int ret;

    setbuf(stdout, NULL);

    base_hex = select_base_der_hex(der_kind);
    if (base_hex == NULL) {
        printf("[ERROR] unsupported DER_KIND: %s\n", der_kind);
        return 2;
    }

    der = calloc(der_capacity, 1);
    if (der == NULL) {
        printf("[ERROR] allocation failed\n");
        return 2;
    }

    ret = build_der_with_trailing_garbage(base_hex,
                                          TRAILING_GARBAGE_HEX,
                                          der,
                                          der_capacity,
                                          &der_len,
                                          &trailing_len);
    if (ret != 0) {
        printf("[ERROR] DER construction failed: %d\n", ret);
        free(der);
        return 2;
    }

    if (trailing_len != TRAILING_GARBAGE_EXPECTED_LEN) {
        printf("[ERROR] trailing garbage length mismatch: got=%zu expected=%zu\n",
               trailing_len, TRAILING_GARBAGE_EXPECTED_LEN);
        free(der);
        return 2;
    }

    printf("DER kind: %s\n", der_kind);
    printf("Parse API kind: %s\n", parse_api_kind);
    printf("DER length with trailing garbage: %zu\n", der_len);
    printf("Trailing garbage length: %zu\n", trailing_len);

    /*
     * Fixed source guard represented by [TOP_LEVEL_SEQUENCE_END_CHECK]:
     * if (end != p + len) { return MBEDTLS_ERR_RSA_BAD_INPUT_DATA; }
     */
    ret = parse_with_selected_api(parse_api_kind, der_kind, der, der_len);

    printf("ret=%d\n", ret);
    printf("expected_buggy=0\n");
    printf("expected_fixed_or_safe=%d\n", EXPECTED_RETURN_VALUE);

    if (ret == 0) {
        printf("[BUG] parser accepted trailing garbage after top-level SEQUENCE.\n");
        free(der);
        return 1;
    }

    if (ret == EXPECTED_RETURN_VALUE ||
        ret == MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
        printf("[OK] parser rejected trailing garbage.\n");
        free(der);
        return 0;
    }

    printf("[INFO] parser rejected trailing garbage with alternate ret=%d\n", ret);
    free(der);
    return 0;
}

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_12","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:11b1e0c155f3f3f5af7fb4de","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:12","template_slot_ref":"slot:input:4260776f669a22788759","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_10","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:2491cd33fa9ff371fe70c077","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:10","template_slot_ref":"slot:input:b58f4163602980cd320a","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OBSERVATION","candidate_element_ref":"OBSERVATION_1_CONSUMED_LENGTH","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:3dbee2d5166177b2a9994c05","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OBSERVATION","target_semantic_ref":"SYNTHETIC_PARSE_CHANNEL","template_slot_ref":"slot:observation:08bee7820fa0f034852c","verified_fact_refs":["F_RO_OBSERVABLE_CONSUMED_LENGTH"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_6","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:40318d932f41d81dfc7648ef","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:6","template_slot_ref":"slot:input:ccfb5f50a7a97557453f","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INTERVENTION","candidate_element_ref":"INTERVENTION_1","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:43b9330cc288e2dec99b5ffc","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INTERVENTION","target_semantic_ref":"parameter:0","template_slot_ref":"slot:intervention:dc1a9a8709f74c1d7519","verified_fact_refs":["F_RC_INTERVENTION_APPEND_TRAILING_DATA"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OPERATION","candidate_element_ref":"OPERATION_0_PARSE_KEY","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:4b44922ed010b54965cd546a","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OPERATION","target_semantic_ref":"SYNTHETIC_PARSER","template_slot_ref":"slot:operation:eea92dfc4e9fa56cf10a","verified_fact_refs":["F_RC_OPERATION_PARSE_ENCODED_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_11","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:59f710dbe66f90b94237ddd7","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:11","template_slot_ref":"slot:input:a5606dcc2ff93e6597ed","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_9","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:5a006fcdbd90f9f08d78c479","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:9","template_slot_ref":"slot:input:07902d8a2d2c912826e2","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_1","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:6703bd5d40da3a55a11f5d7f","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:1","template_slot_ref":"slot:input:803a893f2181d123b9ed","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OPERATION","candidate_element_ref":"OPERATION_2_PARSE_KEY","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:688803f33b1c63828fea3efe","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OPERATION","target_semantic_ref":"SYNTHETIC_PARSER","template_slot_ref":"slot:operation:67cc1b14563ee4ea9bd6","verified_fact_refs":["F_RC_OPERATION_PARSE_ENCODED_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_7","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:77705536b0f608a72a5a69d7","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:7","template_slot_ref":"slot:input:251ccbb135a378db4d1b","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_8","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:81fb34e4a1afb993fb0cab3c","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:8","template_slot_ref":"slot:input:8951c53fff5cf9e73c9a","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_13","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:8a62cafd0e0dd0e6ab7b5f1c","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:13","template_slot_ref":"slot:input:5b3a54824a7b8fd357d9","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OPERATION","candidate_element_ref":"OPERATION_4_PARSE_KEY","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:941be014b3fcb0cb59fba425","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OPERATION","target_semantic_ref":"SYNTHETIC_PARSER","template_slot_ref":"slot:operation:577dbc20781b2130c912","verified_fact_refs":["F_RC_OPERATION_PARSE_ENCODED_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OPERATION","candidate_element_ref":"OPERATION_1_PARSE_KEY","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:9bcc4608b2bdfdc23de79e17","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OPERATION","target_semantic_ref":"SYNTHETIC_PARSER","template_slot_ref":"slot:operation:68ac01c4ea6632ef1bb7","verified_fact_refs":["F_RC_OPERATION_PARSE_ENCODED_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_5","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:9d4e0b05d02b8b7e6f195d62","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:5","template_slot_ref":"slot:input:7fa3507aa043ee3695ed","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_0","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:a3de80b36f77eac064bca8d9","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:0","template_slot_ref":"slot:input:4b5e699a578f1ec21361","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_3","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:c1a524e1b9142f64c0d3a0d8","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:3","template_slot_ref":"slot:input:f83711485e78be84cbaf","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OBSERVATION","candidate_element_ref":"OBSERVATION_0_PARSE_OUTCOME","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:d33311708a6f111ee3df3d65","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OBSERVATION","target_semantic_ref":"SYNTHETIC_PARSE_CHANNEL","template_slot_ref":"slot:observation:370b57aaeead099383a3","verified_fact_refs":["F_RO_OBSERVABLE_PARSE_OUTCOME"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OPERATION","candidate_element_ref":"OPERATION_3_PARSE_KEY","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:deae4808f688986a346f15d8","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OPERATION","target_semantic_ref":"SYNTHETIC_PARSER","template_slot_ref":"slot:operation:2634094dc2a8d2d8beee","verified_fact_refs":["F_RC_OPERATION_PARSE_ENCODED_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_2","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:df82ab7ccab2523f192998e5","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:2","template_slot_ref":"slot:input:45be527c191c18ba0883","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INTERVENTION","candidate_element_ref":"INTERVENTION_0","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:e097dea77e6f586237d0e2c9","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INTERVENTION","target_semantic_ref":"parameter:0","template_slot_ref":"slot:intervention:d704008ccffae37e3052","verified_fact_refs":["F_RC_INTERVENTION_APPEND_TRAILING_DATA"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"INPUT","candidate_element_ref":"INPUT_4","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:ed56e931204359c2d23939b4","occurrence_index":0,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"INPUT","target_semantic_ref":"parameter:4","template_slot_ref":"slot:input:b2fc37efec7a9542349a","verified_fact_refs":["F_RC_OBJECT_RSA_DER_INPUT"]} */

/* CIPHERLENS_MAPPING {"adaptation_hole_refs":[],"candidate_element_kind":"OBSERVATION","candidate_element_ref":"OBSERVATION_2_INPUT_LENGTH","evidence_refs":["SYNTHETIC_FIXTURE"],"mapping_id":"mapping:fd7d31f596060dd94cd91dcb","occurrence_index":1,"render_disposition":"DIRECT_SUBSTITUTION","slot_kind":"OBSERVATION","target_semantic_ref":"SYNTHETIC_PARSE_CHANNEL","template_slot_ref":"slot:observation:370b57aaeead099383a3","verified_fact_refs":["F_RO_OBSERVABLE_INPUT_LENGTH"]} */

/* CIPHERLENS_IDENTITY {"evidence_refs":["SYNTHETIC_FIXTURE"],"identity_group_ref":"identity:rsa_der_input","identity_realization_id":"identity-realization:2bd0e4d17089bd60c0a6b6cc","lifetime_region":"candidate-run","observation_binding_refs":["OBSERVATION_0_PARSE_OUTCOME","OBSERVATION_1_CONSUMED_LENGTH","OBSERVATION_2_INPUT_LENGTH"],"operation_binding_refs":["OPERATION_0_PARSE_KEY","OPERATION_1_PARSE_KEY","OPERATION_2_PARSE_KEY","OPERATION_3_PARSE_KEY","OPERATION_4_PARSE_KEY"],"ownership":"CALLER_OWNED","storage_ref":"storage:2bd0e4d17089bd60c0a6b6cc","subject_binding_refs":["SUBJECT_0_RSA_DER_INPUT","SUBJECT_CHANNEL_0"]} */

/* CipherLens deterministic build metadata; registry=cipherlens.programmatic_completion_registry.v0.1; hole=hole:build-metadata */

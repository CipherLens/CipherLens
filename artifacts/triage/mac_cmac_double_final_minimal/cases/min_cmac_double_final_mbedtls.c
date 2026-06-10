#include <psa/crypto.h>

#include <stdio.h>
#include <string.h>

static const unsigned char key128[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char key256[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char msg[17] = {
    0x6d, 0x61, 0x63, 0x20, 0x6c, 0x69, 0x66, 0x65,
    0x63, 0x79, 0x63, 0x6c, 0x65, 0x20, 0x6d, 0x73,
    0x67
};

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", label);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static void run_case(const char *case_name,
                     const unsigned char *key,
                     size_t key_len,
                     int do_update)
{
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    psa_key_id_t key_id = 0;
    unsigned char out1[64];
    unsigned char out2[64];
    size_t mac_len1 = 111;
    size_t mac_len2 = 222;
    psa_status_t import_status;
    psa_status_t setup_status;
    psa_status_t update_status = PSA_SUCCESS;
    psa_status_t first_finish_status;
    psa_status_t second_finish_status;
    psa_status_t abort_status;

    memset(out1, 0xa5, sizeof(out1));
    memset(out2, 0x5a, sizeof(out2));

    printf("case=%s key_len=%zu do_update=%d\n", case_name, key_len, do_update);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, key_len * 8);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_CMAC);

    import_status = psa_import_key(&attrs, key, key_len, &key_id);
    setup_status = import_status == PSA_SUCCESS
                       ? psa_mac_sign_setup(&op, key_id, PSA_ALG_CMAC)
                       : import_status;
    if (setup_status == PSA_SUCCESS && do_update)
        update_status = psa_mac_update(&op, msg, sizeof(msg));
    first_finish_status = setup_status == PSA_SUCCESS && update_status == PSA_SUCCESS
                              ? psa_mac_sign_finish(&op, out1, sizeof(out1), &mac_len1)
                              : setup_status;
    second_finish_status = first_finish_status == PSA_SUCCESS
                               ? psa_mac_sign_finish(&op, out2, sizeof(out2), &mac_len2)
                               : first_finish_status;
    abort_status = psa_mac_abort(&op);

    printf("import_status=%d\n", (int)import_status);
    printf("setup_status=%d\n", (int)setup_status);
    printf("update_status=%d\n", (int)update_status);
    printf("first_finish_status=%d\n", (int)first_finish_status);
    printf("second_finish_status=%d\n", (int)second_finish_status);
    printf("mac_len1=%zu\n", mac_len1);
    printf("mac_len2=%zu\n", mac_len2);
    print_hex("out1_hex", out1, mac_len1 <= sizeof(out1) ? mac_len1 : 0);
    print_hex("out2_hex", out2, mac_len2 <= sizeof(out2) ? mac_len2 : 0);
    printf("abort_status=%d\n\n", (int)abort_status);

    if (key_id != 0)
        psa_destroy_key(key_id);
}

int main(void)
{
    psa_status_t init_status = psa_crypto_init();
    printf("psa_crypto_init=%d\n", (int)init_status);
    if (init_status != PSA_SUCCESS)
        return 1;

    run_case("aes128_setup_final_final", key128, sizeof(key128), 0);
    run_case("aes128_setup_update_final_final", key128, sizeof(key128), 1);
    run_case("aes256_setup_final_final", key256, sizeof(key256), 0);
    run_case("aes256_setup_update_final_final", key256, sizeof(key256), 1);
    return 0;
}

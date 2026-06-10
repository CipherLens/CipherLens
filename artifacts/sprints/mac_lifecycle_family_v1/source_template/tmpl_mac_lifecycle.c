/*
 * Normalized source template skeleton for MAC lifecycle migration.
 *
 * This file is not a final harness. It preserves lifecycle structure and
 * mutation-relevant placeholders for recipe-slot binding.
 */

#include <stddef.h>
#include <stdint.h>

#define MAC_INIT_API MAC_INIT_API
#define MAC_UPDATE_API MAC_UPDATE_API
#define MAC_FINAL_API MAC_FINAL_API
#define MAC_RESET_API MAC_RESET_API
#define MAC_FREE_API MAC_FREE_API
#define MAC_ALGORITHM MAC_ALGORITHM

int mac_lifecycle_template(void)
{
    unsigned char key[] = KEY_BUFFER;
    unsigned char input[] = INPUT_BUFFER;
    unsigned char mac[64];
    size_t mac_len = 0;

    MAC_INIT_API(MAC_ALGORITHM, key, sizeof(key));
    MAC_UPDATE_API(input, sizeof(input));
    MAC_FINAL_API(mac, sizeof(mac), &mac_len);

    FINAL_AFTER_FINAL_ACTION;
    UPDATE_AFTER_FINAL_ACTION;

    EXPECTED_STATE_BEHAVIOR;

    MAC_FREE_API();
    return 0;
}

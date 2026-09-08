/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_psk.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>

int main(void)
{
    uint8_t payload[GOODIX_PSK_WRITE_PAYLOAD_SIZE];
    uint8_t key[GOODIX_PSK_PMK_HASH_SIZE];
    uint8_t status[GOODIX_PSK_PMK_STATUS_SIZE];
    bool matches = true;
    GoodixPskChunk chunk;

    assert(goodix_psk_community_pmk_hash() != NULL);
    assert(goodix_psk_community_white_box() != NULL);
    goodix_psk_community_tls_key(key);
    for (size_t i = 0; i < sizeof(key); i++)
        assert(key[i] == 0);

    assert(goodix_psk_build_community_write(payload) == GOODIX_PSK_OK);
    assert(payload[0] == 0x03 && payload[1] == 0x00 && payload[2] == 0x01 &&
           payload[3] == 0xbb);
    assert(payload[4] == 96 && payload[5] == 0 && payload[6] == 0 &&
           payload[7] == 0);
    assert(memcmp(payload + 8, goodix_psk_community_white_box(),
                  GOODIX_PSK_WHITE_BOX_SIZE) == 0);

    memset(status, 0, sizeof(status));
    status[1] = 0x07;
    status[2] = 0x00;
    status[3] = 0x02;
    status[4] = 0xbb;
    status[5] = 32;
    memcpy(status + 9, goodix_psk_community_pmk_hash(),
           GOODIX_PSK_PMK_HASH_SIZE);
    assert(goodix_psk_parse_pmk_status(status, sizeof(status), &matches) ==
           GOODIX_PSK_OK);
    assert(matches);
    status[9] ^= 0x01;
    assert(goodix_psk_parse_pmk_status(status, sizeof(status), &matches) ==
           GOODIX_PSK_OK);
    assert(!matches);

    status[0] = 1;
    assert(goodix_psk_parse_pmk_status(status, sizeof(status), &matches) ==
           GOODIX_PSK_DEVICE_ERROR);

    assert(goodix_psk_parse_write_response((const uint8_t[]){0}, 1) ==
           GOODIX_PSK_OK);
    assert(goodix_psk_parse_write_response((const uint8_t[]){1}, 1) ==
           GOODIX_PSK_DEVICE_ERROR);

    assert(goodix_psk_parse_read_response(status, sizeof(status),
                                          GOODIX_PSK_PMK_TAG,
                                          GOODIX_PSK_PMK_HASH_SIZE,
                                          &chunk) == GOODIX_PSK_DEVICE_ERROR);
}

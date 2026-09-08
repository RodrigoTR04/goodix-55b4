/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GOODIX_PSK_VENDOR_BLOB_TAG UINT32_C(0xbb010002)
#define GOODIX_PSK_VENDOR_BLOB_SIZE 324U
#define GOODIX_PSK_READ_CHUNK_SIZE 256U
#define GOODIX_PSK_READ_REQUEST_SIZE 16U
#define GOODIX_PSK_READ_RESPONSE_HEADER_SIZE 9U
#define GOODIX_PSK_PMK_TAG UINT32_C(0xbb020007)
#define GOODIX_PSK_WRITE_TAG UINT32_C(0xbb010003)
#define GOODIX_PSK_PMK_HASH_SIZE 32U
#define GOODIX_PSK_WHITE_BOX_SIZE 96U
#define GOODIX_PSK_WRITE_PAYLOAD_SIZE (8U + GOODIX_PSK_WHITE_BOX_SIZE)
#define GOODIX_PSK_PMK_STATUS_SIZE (GOODIX_PSK_READ_RESPONSE_HEADER_SIZE + GOODIX_PSK_PMK_HASH_SIZE)

typedef enum {
    GOODIX_PSK_OK = 0,
    GOODIX_PSK_INVALID_ARGUMENT,
    GOODIX_PSK_INVALID_LENGTH,
    GOODIX_PSK_DEVICE_ERROR,
    GOODIX_PSK_UNEXPECTED_TAG,
} GoodixPskResult;

typedef struct {
    const uint8_t *data;
    size_t length;
} GoodixPskChunk;

GoodixPskResult goodix_psk_build_read_request(
    uint32_t length,
    uint32_t offset,
    uint32_t tag,
    uint8_t request[GOODIX_PSK_READ_REQUEST_SIZE]);

GoodixPskResult goodix_psk_parse_read_response(const uint8_t *response,
                                               size_t response_length,
                                               uint32_t expected_tag,
                                               size_t expected_length,
                                               GoodixPskChunk *chunk);

/* Public community material from mpi3d/goodix-fp-dump (MIT). Writing the
 * white-box makes the device accept an all-zero TLS PSK. This is not a
 * host-specific Windows pairing key. */
const uint8_t *goodix_psk_community_pmk_hash(void);
const uint8_t *goodix_psk_community_white_box(void);
void goodix_psk_community_tls_key(uint8_t key[GOODIX_PSK_PMK_HASH_SIZE]);

GoodixPskResult goodix_psk_parse_pmk_status(const uint8_t *response,
                                            size_t response_length,
                                            bool *matches_community);

GoodixPskResult goodix_psk_build_community_write(
    uint8_t payload[GOODIX_PSK_WRITE_PAYLOAD_SIZE]);

GoodixPskResult goodix_psk_parse_write_response(const uint8_t *response,
                                                size_t response_length);

bool goodix_psk_is_canonical_dpapi_blob(const uint8_t *blob,
                                        size_t blob_length);

const char *goodix_psk_result_string(GoodixPskResult result);

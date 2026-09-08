/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_psk.h"

#include <string.h>

static uint32_t
read_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void
write_le32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value & 0xffU);
    data[1] = (uint8_t)((value >> 8) & 0xffU);
    data[2] = (uint8_t)((value >> 16) & 0xffU);
    data[3] = (uint8_t)((value >> 24) & 0xffU);
}

GoodixPskResult
goodix_psk_build_read_request(
    uint32_t length,
    uint32_t offset,
    uint32_t tag,
    uint8_t request[GOODIX_PSK_READ_REQUEST_SIZE])
{
    if (request == NULL)
        return GOODIX_PSK_INVALID_ARGUMENT;
    if (length == 0 || length > GOODIX_PSK_READ_CHUNK_SIZE ||
        offset > UINT32_MAX - length)
        return GOODIX_PSK_INVALID_LENGTH;

    write_le32(request, length);
    write_le32(request + 4, offset);
    write_le32(request + 8, tag);
    write_le32(request + 12, 0);
    return GOODIX_PSK_OK;
}

/* SHA-256 PMK hash published by community GF32xx firmware after the white-box
 * write; TLS then uses 32 zero bytes. */
static const uint8_t community_pmk_hash[GOODIX_PSK_PMK_HASH_SIZE] = {
    0x81, 0xb8, 0xff, 0x49, 0x06, 0x12, 0x02, 0x2a,
    0x12, 0x1a, 0x94, 0x49, 0xee, 0x3a, 0xad, 0x27,
    0x92, 0xf3, 0x2b, 0x9f, 0x31, 0x41, 0x18, 0x2c,
    0xd0, 0x10, 0x19, 0x94, 0x5e, 0xe5, 0x03, 0x61,
};

static const uint8_t community_white_box[GOODIX_PSK_WHITE_BOX_SIZE] = {
    0xec, 0x35, 0xae, 0x3a, 0xbb, 0x45, 0xed, 0x3f, 0x12, 0xc4, 0x75, 0x1f,
    0x1e, 0x5c, 0x2c, 0xc0, 0x5b, 0x3c, 0x54, 0x52, 0xe9, 0x10, 0x4d, 0x9f,
    0x2a, 0x31, 0x18, 0x64, 0x4f, 0x37, 0xa0, 0x4b, 0x6f, 0xd6, 0x6b, 0x1d,
    0x97, 0xcf, 0x80, 0xf1, 0x34, 0x5f, 0x76, 0xc8, 0x4f, 0x03, 0xff, 0x30,
    0xbb, 0x51, 0xbf, 0x30, 0x8f, 0x2a, 0x98, 0x75, 0xc4, 0x1e, 0x65, 0x92,
    0xcd, 0x2a, 0x2f, 0x9e, 0x60, 0x80, 0x9b, 0x17, 0xb5, 0x31, 0x60, 0x37,
    0xb6, 0x9b, 0xb2, 0xfa, 0x5d, 0x4c, 0x8a, 0xc3, 0x1e, 0xdb, 0x33, 0x94,
    0x04, 0x6e, 0xc0, 0x6b, 0xbd, 0xac, 0xc5, 0x7d, 0xa6, 0xa7, 0x56, 0xc5,
};

const uint8_t *
goodix_psk_community_pmk_hash(void)
{
    return community_pmk_hash;
}

const uint8_t *
goodix_psk_community_white_box(void)
{
    return community_white_box;
}

void
goodix_psk_community_tls_key(uint8_t key[GOODIX_PSK_PMK_HASH_SIZE])
{
    if (key != NULL)
        memset(key, 0, GOODIX_PSK_PMK_HASH_SIZE);
}

GoodixPskResult
goodix_psk_parse_pmk_status(const uint8_t *response,
                            size_t response_length,
                            bool *matches_community)
{
    GoodixPskChunk chunk;
    GoodixPskResult result;

    if (matches_community == NULL)
        return GOODIX_PSK_INVALID_ARGUMENT;
    *matches_community = false;
    result = goodix_psk_parse_read_response(response, response_length,
                                            GOODIX_PSK_PMK_TAG,
                                            GOODIX_PSK_PMK_HASH_SIZE,
                                            &chunk);
    if (result != GOODIX_PSK_OK)
        return result;
    *matches_community = memcmp(chunk.data, community_pmk_hash,
                                GOODIX_PSK_PMK_HASH_SIZE) == 0;
    return GOODIX_PSK_OK;
}

GoodixPskResult
goodix_psk_build_community_write(uint8_t payload[GOODIX_PSK_WRITE_PAYLOAD_SIZE])
{
    if (payload == NULL)
        return GOODIX_PSK_INVALID_ARGUMENT;
    write_le32(payload, GOODIX_PSK_WRITE_TAG);
    write_le32(payload + 4, GOODIX_PSK_WHITE_BOX_SIZE);
    memcpy(payload + 8, community_white_box, GOODIX_PSK_WHITE_BOX_SIZE);
    return GOODIX_PSK_OK;
}

GoodixPskResult
goodix_psk_parse_write_response(const uint8_t *response, size_t response_length)
{
    if (response == NULL || response_length < 1)
        return GOODIX_PSK_INVALID_LENGTH;
    if (response[0] != 0)
        return GOODIX_PSK_DEVICE_ERROR;
    return GOODIX_PSK_OK;
}

GoodixPskResult
goodix_psk_parse_read_response(const uint8_t *response,
                               size_t response_length,
                               uint32_t expected_tag,
                               size_t expected_length,
                               GoodixPskChunk *chunk)
{
    if (response == NULL || chunk == NULL)
        return GOODIX_PSK_INVALID_ARGUMENT;
    if (expected_length == 0 ||
        expected_length > GOODIX_PSK_VENDOR_BLOB_SIZE ||
        response_length < GOODIX_PSK_READ_RESPONSE_HEADER_SIZE)
        return GOODIX_PSK_INVALID_LENGTH;
    if (response[0] != 0)
        return GOODIX_PSK_DEVICE_ERROR;
    if (read_le32(response + 1) != expected_tag)
        return GOODIX_PSK_UNEXPECTED_TAG;

    uint32_t declared_length = read_le32(response + 5);
    if (declared_length != expected_length ||
        response_length !=
            GOODIX_PSK_READ_RESPONSE_HEADER_SIZE + declared_length)
        return GOODIX_PSK_INVALID_LENGTH;

    chunk->data = response + GOODIX_PSK_READ_RESPONSE_HEADER_SIZE;
    chunk->length = declared_length;
    return GOODIX_PSK_OK;
}

bool
goodix_psk_is_canonical_dpapi_blob(const uint8_t *blob, size_t blob_length)
{
    static const uint8_t dpapi_header[16] = {
        0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf,
        0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0,
    };

    return blob != NULL && blob_length == GOODIX_PSK_VENDOR_BLOB_SIZE &&
           memcmp(blob, dpapi_header, sizeof(dpapi_header)) == 0;
}

const char *
goodix_psk_result_string(GoodixPskResult result)
{
    switch (result) {
    case GOODIX_PSK_OK:
        return "success";
    case GOODIX_PSK_INVALID_ARGUMENT:
        return "invalid argument";
    case GOODIX_PSK_INVALID_LENGTH:
        return "invalid length";
    case GOODIX_PSK_DEVICE_ERROR:
        return "device-reported failure";
    case GOODIX_PSK_UNEXPECTED_TAG:
        return "unexpected slot tag";
    }
    return "unknown PSK error";
}

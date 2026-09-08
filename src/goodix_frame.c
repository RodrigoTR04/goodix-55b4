/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_frame.h"
#include "goodix_protocol.h"
#include <openssl/crypto.h>
#include <string.h>

GoodixFrameResult
goodix_frame_consume(GoodixTlsSession *tls, uint8_t flags,
                      const uint8_t *payload, size_t length,
                      GoodixFrameMetadata *metadata)
{
    return goodix_frame_consume_sink(tls, flags, payload, length, NULL, NULL,
                                     metadata);
}

GoodixFrameResult
goodix_frame_consume_sink(GoodixTlsSession *tls, uint8_t flags,
                          const uint8_t *payload, size_t length,
                          GoodixFramePlaintextSink sink, void *user_data,
                          GoodixFrameMetadata *metadata)
{
    GoodixFrameMetadata checked = {0};
    uint8_t plaintext[4096] = {0};
    GoodixFrameResult result = GOODIX_FRAME_INVALID_WRAPPER;
    if (metadata == NULL)
        return result;
    memset(metadata, 0, sizeof(*metadata));
    if (tls == NULL || !goodix_tls_session_is_established(tls) ||
        flags != GOODIX_TLS_DATA_FLAG || payload == NULL ||
        length <= GOODIX_FRAME_PREFIX_SIZE || length > GOODIX_FRAME_MAX_SIZE)
        goto out;
    /* Validate every TLS 1.2 application record before feeding any bytes.
     * AES-CBC ciphertext includes an explicit IV, MAC and padding. */
    for (size_t offset = GOODIX_FRAME_PREFIX_SIZE; offset < length;) {
        if (length - offset < 5) {
            result = GOODIX_FRAME_INVALID_TLS_RECORD;
            goto out;
        }
        const uint8_t *record = payload + offset;
        size_t size = ((size_t)record[3] << 8) | record[4];
        if (record[0] != 23 || record[1] != 3 || record[2] != 3 ||
            size < 64 || size > 18432 || size % 16 != 0 ||
            size > length - offset - 5) {
            result = GOODIX_FRAME_INVALID_TLS_RECORD;
            goto out;
        }
        checked.tls_records++;
        offset += 5 + size;
    }
    for (size_t offset = GOODIX_FRAME_PREFIX_SIZE; offset < length;) {
        size_t size = 5 + ((size_t)payload[offset + 3] << 8) + payload[offset + 4];
        if (goodix_tls_session_feed(tls, payload + offset, size) != GOODIX_TLS_OK) {
            result = GOODIX_FRAME_AUTHENTICATION_FAILED;
            goto out;
        }
        size_t before = checked.plaintext_bytes;
        for (;;) {
            size_t count = 0;
            GoodixTlsResult r = goodix_tls_session_read(tls, plaintext, sizeof(plaintext), &count);
            if (r == GOODIX_TLS_WANT_INPUT)
            {
                OPENSSL_cleanse(plaintext, sizeof(plaintext));
                break;
            }
            if (r != GOODIX_TLS_OK || count == 0) {
                OPENSSL_cleanse(plaintext, sizeof(plaintext));
                result = GOODIX_FRAME_AUTHENTICATION_FAILED;
                goto out;
            }
            if (count > GOODIX_FRAME_MAX_SIZE - checked.plaintext_bytes) {
                OPENSSL_cleanse(plaintext, sizeof(plaintext));
                result = GOODIX_FRAME_INVALID_PLAINTEXT_LENGTH;
                goto out;
            }
            if (sink != NULL && !sink(user_data, plaintext, count)) {
                OPENSSL_cleanse(plaintext, sizeof(plaintext));
                result = GOODIX_FRAME_SINK_FAILED;
                goto out;
            }
            checked.plaintext_bytes += count;
            OPENSSL_cleanse(plaintext, sizeof(plaintext));
        }
        if (checked.plaintext_bytes == before || goodix_tls_session_pending_output(tls)) {
            result = GOODIX_FRAME_INVALID_PLAINTEXT_LENGTH;
            goto out;
        }
        offset += size;
    }
    checked.wrapper_bytes = length + 4;
    checked.prefix_bytes = GOODIX_FRAME_PREFIX_SIZE;
    checked.tls_bytes = length - GOODIX_FRAME_PREFIX_SIZE;
    checked.format.length_matches =
        checked.plaintext_bytes == GOODIX_FORMAT_PLAINTEXT_BYTES;
    *metadata = checked;
    result = GOODIX_FRAME_OK;
out:
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    return result;
}

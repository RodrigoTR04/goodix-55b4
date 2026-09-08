/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include "goodix_tls.h"
#include "goodix_format.h"
#include <stdint.h>

#define GOODIX_FRAME_PREFIX_SIZE 9
#define GOODIX_FRAME_MAX_SIZE UINT16_MAX

typedef struct {
    size_t wrapper_bytes;
    size_t prefix_bytes;
    size_t tls_bytes;
    size_t tls_records;
    size_t plaintext_bytes;
    GoodixFormatMetadata format;
} GoodixFrameMetadata;

typedef enum {
    GOODIX_FRAME_OK,
    GOODIX_FRAME_INVALID_WRAPPER,
    GOODIX_FRAME_INVALID_TLS_RECORD,
    GOODIX_FRAME_AUTHENTICATION_FAILED,
    GOODIX_FRAME_INVALID_PLAINTEXT_LENGTH,
    GOODIX_FRAME_SINK_FAILED,
} GoodixFrameResult;

/* Plaintext is borrowed for the duration of this callback. A sink must copy or
 * consume it synchronously and return false when it cannot accept more bytes. */
typedef bool (*GoodixFramePlaintextSink)(void *user_data,
    const uint8_t *plaintext, size_t length);

/* The prefix is opaque: only its boundary is established by public 55x4
 * interoperability evidence. No prefix values or plaintext are exposed by
 * this one-shot wrapper. Caller owns/wipes the encrypted input and destroys
 * TLS after this operation (on success and failure), discarding TLS-owned
 * buffers as well. Metadata is zero on failure. Output plaintext is wiped
 * after every read. The sink variant borrows each plaintext chunk until its
 * callback returns and is the bounded multi-frame handoff used by capture. */
GoodixFrameResult goodix_frame_consume(GoodixTlsSession *tls, uint8_t flags,
    const uint8_t *payload, size_t length, GoodixFrameMetadata *metadata);
GoodixFrameResult goodix_frame_consume_sink(GoodixTlsSession *tls, uint8_t flags,
    const uint8_t *payload, size_t length, GoodixFramePlaintextSink sink,
    void *user_data, GoodixFrameMetadata *metadata);

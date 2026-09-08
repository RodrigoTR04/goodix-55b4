/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct GoodixTransport GoodixTransport;

typedef enum {
    GOODIX_TRANSPORT_OK = 0,
    GOODIX_TRANSPORT_INVALID_ARGUMENT,
    GOODIX_TRANSPORT_BUSY,
    GOODIX_TRANSPORT_IDLE,
    GOODIX_TRANSPORT_IO_ERROR,
    GOODIX_TRANSPORT_PROTOCOL_ERROR,
    GOODIX_TRANSPORT_CANCELLED,
} GoodixTransportResult;

/* The submitted block remains valid until goodix_transport_out_complete(). */
typedef void (*GoodixTransportSubmit)(void *user_data,
                                     const uint8_t *block,
                                     size_t block_length);

/* Frame data is borrowed and remains valid only for the callback. */
typedef void (*GoodixTransportFrame)(void *user_data,
                                    uint8_t flags,
                                    const uint8_t *data,
                                    size_t data_length);

typedef void (*GoodixTransportDone)(void *user_data,
                                   GoodixTransportResult result);

GoodixTransport *goodix_transport_new(GoodixTransportSubmit submit,
                                      GoodixTransportFrame frame,
                                      GoodixTransportDone done,
                                      void *user_data);

void goodix_transport_free(GoodixTransport *transport);

GoodixTransportResult goodix_transport_send(GoodixTransport *transport,
                                            const uint8_t *wire,
                                            size_t wire_length);

GoodixTransportResult goodix_transport_out_complete(
    GoodixTransport *transport,
    bool success);

GoodixTransportResult goodix_transport_feed(GoodixTransport *transport,
                                            const uint8_t *bytes,
                                            size_t byte_count);

void goodix_transport_cancel(GoodixTransport *transport);

bool goodix_transport_is_sending(const GoodixTransport *transport);

/* The physical reader sends compact IN frames; OUT remains block padded.
 * Select before feeding input. The default retains padded fixture support. */
void goodix_transport_set_compact_input(GoodixTransport *transport);

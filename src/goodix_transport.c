/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_transport.h"

#include "goodix_protocol.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define GOODIX_TRANSPORT_MAX_WIRE_SIZE                                      \
    ((UINT16_MAX + 4U + GOODIX_PROTOCOL_USB_BLOCK_SIZE - 1U) &              \
     ~(GOODIX_PROTOCOL_USB_BLOCK_SIZE - 1U))

struct GoodixTransport {
    GoodixTransportSubmit submit;
    GoodixTransportFrame frame;
    GoodixTransportDone done;
    void *user_data;

    uint8_t *out_data;
    size_t out_length;
    size_t out_offset;
    size_t out_block_length;

    uint8_t in_data[GOODIX_TRANSPORT_MAX_WIRE_SIZE];
    size_t in_length;
    size_t in_expected;
    bool compact_input;
};

static void
clear_bytes(void *data, size_t length)
{
    volatile uint8_t *bytes = data;

    while (length-- != 0)
        *bytes++ = 0;
}

static void
clear_out(GoodixTransport *transport)
{
    if (transport->out_data != NULL) {
        clear_bytes(transport->out_data, transport->out_length);
        free(transport->out_data);
    }
    transport->out_data = NULL;
    transport->out_length = 0;
    transport->out_offset = 0;
    transport->out_block_length = 0;
}

static GoodixTransportResult
finish_out(GoodixTransport *transport, GoodixTransportResult result)
{
    GoodixTransportDone done = transport->done;
    void *user_data = transport->user_data;

    clear_out(transport);
    done(user_data, result);
    return result;
}

static void
submit_next(GoodixTransport *transport)
{
    size_t remaining = transport->out_length - transport->out_offset;

    transport->out_block_length = remaining;
    if (transport->out_block_length > GOODIX_PROTOCOL_USB_BLOCK_SIZE)
        transport->out_block_length = GOODIX_PROTOCOL_USB_BLOCK_SIZE;

    transport->submit(transport->user_data,
                      transport->out_data + transport->out_offset,
                      transport->out_block_length);
}

GoodixTransport *
goodix_transport_new(GoodixTransportSubmit submit,
                     GoodixTransportFrame frame,
                     GoodixTransportDone done,
                     void *user_data)
{
    GoodixTransport *transport;

    if (submit == NULL || frame == NULL || done == NULL)
        return NULL;

    transport = calloc(1, sizeof(*transport));
    if (transport == NULL)
        return NULL;

    transport->submit = submit;
    transport->frame = frame;
    transport->done = done;
    transport->user_data = user_data;
    return transport;
}

void
goodix_transport_free(GoodixTransport *transport)
{
    if (transport == NULL)
        return;

    clear_out(transport);
    clear_bytes(transport->in_data, sizeof(transport->in_data));
    clear_bytes(transport, sizeof(*transport));
    free(transport);
}

GoodixTransportResult
goodix_transport_send(GoodixTransport *transport,
                      const uint8_t *wire,
                      size_t wire_length)
{
    if (transport == NULL || wire == NULL || wire_length == 0)
        return GOODIX_TRANSPORT_INVALID_ARGUMENT;
    if (transport->out_data != NULL)
        return GOODIX_TRANSPORT_BUSY;

    transport->out_data = malloc(wire_length);
    if (transport->out_data == NULL)
        return GOODIX_TRANSPORT_IO_ERROR;

    memcpy(transport->out_data, wire, wire_length);
    transport->out_length = wire_length;
    submit_next(transport);
    return GOODIX_TRANSPORT_OK;
}

GoodixTransportResult
goodix_transport_out_complete(GoodixTransport *transport, bool success)
{
    if (transport == NULL)
        return GOODIX_TRANSPORT_INVALID_ARGUMENT;
    if (transport->out_data == NULL || transport->out_block_length == 0)
        return GOODIX_TRANSPORT_IDLE;
    if (!success)
        return finish_out(transport, GOODIX_TRANSPORT_IO_ERROR);

    transport->out_offset += transport->out_block_length;
    transport->out_block_length = 0;
    if (transport->out_offset == transport->out_length)
        return finish_out(transport, GOODIX_TRANSPORT_OK);

    submit_next(transport);
    return GOODIX_TRANSPORT_OK;
}

static bool
header_is_valid(const uint8_t *header)
{
    return (uint8_t)(header[0] + header[1] + header[2]) == header[3];
}

static size_t
header_wire_length(const uint8_t *header, bool compact)
{
    size_t payload_length = (size_t)header[1] | ((size_t)header[2] << 8);

    return compact ? payload_length + 4U : goodix_outer_wire_size(payload_length);
}

static void
clear_in(GoodixTransport *transport)
{
    clear_bytes(transport->in_data, transport->in_length);
    transport->in_length = 0;
    transport->in_expected = 0;
}

GoodixTransportResult
goodix_transport_feed(GoodixTransport *transport,
                      const uint8_t *bytes,
                      size_t byte_count)
{
    if (transport == NULL || (bytes == NULL && byte_count != 0))
        return GOODIX_TRANSPORT_INVALID_ARGUMENT;

    while (byte_count != 0) {
        size_t wanted;
        size_t copied;

        if (transport->in_length < 4U)
            wanted = 4U - transport->in_length;
        else
            wanted = transport->in_expected - transport->in_length;

        copied = byte_count < wanted ? byte_count : wanted;
        memcpy(transport->in_data + transport->in_length, bytes, copied);
        transport->in_length += copied;
        bytes += copied;
        byte_count -= copied;

        if (transport->in_length == 4U && transport->in_expected == 0) {
            if (!header_is_valid(transport->in_data)) {
                clear_in(transport);
                return GOODIX_TRANSPORT_PROTOCOL_ERROR;
            }
            transport->in_expected = header_wire_length(transport->in_data, transport->compact_input);
            if (transport->in_expected < 4U ||
                transport->in_expected > sizeof(transport->in_data)) {
                clear_in(transport);
                return GOODIX_TRANSPORT_PROTOCOL_ERROR;
            }
        }

        if (transport->in_expected != 0 &&
            transport->in_length == transport->in_expected) {
            GoodixOuterFrame frame;

            if (goodix_protocol_parse_outer(transport->in_data,
                                            transport->in_length,
                                            &frame) != GOODIX_PROTOCOL_OK) {
                clear_in(transport);
                return GOODIX_TRANSPORT_PROTOCOL_ERROR;
            }
            transport->frame(transport->user_data,
                             frame.flags,
                             frame.data,
                             frame.length);
            clear_in(transport);
        }
    }

    return GOODIX_TRANSPORT_OK;
}

void
goodix_transport_cancel(GoodixTransport *transport)
{
    if (transport == NULL)
        return;

    clear_in(transport);
    if (transport->out_data != NULL)
        finish_out(transport, GOODIX_TRANSPORT_CANCELLED);
}

bool
goodix_transport_is_sending(const GoodixTransport *transport)
{
    return transport != NULL && transport->out_data != NULL;
}

void goodix_transport_set_compact_input(GoodixTransport *transport)
{
    if (transport != NULL && transport->in_length == 0)
        transport->compact_input = true;
}

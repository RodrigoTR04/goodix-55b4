/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_protocol.h"

#include <limits.h>
#include <string.h>

static uint16_t
read_le16(const uint8_t *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static void
write_le16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value & 0xffU);
    data[1] = (uint8_t)(value >> 8);
}

static uint8_t
byte_sum(const uint8_t *data, size_t length)
{
    uint8_t sum = 0;

    for (size_t i = 0; i < length; i++)
        sum = (uint8_t)(sum + data[i]);
    return sum;
}

size_t
goodix_outer_wire_size(size_t payload_length)
{
    if (payload_length > UINT16_MAX)
        return 0;

    size_t unpadded = 4U + payload_length;
    return (unpadded + GOODIX_PROTOCOL_USB_BLOCK_SIZE - 1U) &
           ~(size_t)(GOODIX_PROTOCOL_USB_BLOCK_SIZE - 1U);
}

size_t
goodix_protocol_wire_size(size_t payload_length)
{
    if (payload_length > UINT16_MAX - 4U)
        return 0;
    return goodix_outer_wire_size(3U + payload_length + 1U);
}

static void
build_outer_header(uint8_t flags, size_t payload_length, uint8_t *wire)
{
    wire[0] = flags;
    write_le16(wire + 1, (uint16_t)payload_length);
    wire[3] = byte_sum(wire, 3);
}

GoodixProtocolResult
goodix_protocol_build_outer(uint8_t flags,
                            const uint8_t *payload,
                            size_t payload_length,
                            uint8_t *wire,
                            size_t wire_capacity,
                            size_t *wire_length)
{
    if (wire == NULL || wire_length == NULL ||
        (payload == NULL && payload_length != 0))
        return GOODIX_PROTOCOL_INVALID_ARGUMENT;

    size_t required = goodix_outer_wire_size(payload_length);
    if (required == 0)
        return GOODIX_PROTOCOL_INVALID_LENGTH;
    if (wire_capacity < required)
        return GOODIX_PROTOCOL_BUFFER_TOO_SMALL;

    memset(wire, 0, required);
    build_outer_header(flags, payload_length, wire);
    if (payload_length != 0)
        memcpy(wire + 4, payload, payload_length);
    *wire_length = required;
    return GOODIX_PROTOCOL_OK;
}

GoodixProtocolResult
goodix_protocol_build_command(uint8_t command,
                              const uint8_t *payload,
                              size_t payload_length,
                              bool use_checksum,
                              uint8_t *wire,
                              size_t wire_capacity,
                              size_t *wire_length)
{
    if (wire == NULL || wire_length == NULL ||
        (payload == NULL && payload_length != 0))
        return GOODIX_PROTOCOL_INVALID_ARGUMENT;

    size_t required = goodix_protocol_wire_size(payload_length);
    if (required == 0)
        return GOODIX_PROTOCOL_INVALID_LENGTH;
    if (wire_capacity < required)
        return GOODIX_PROTOCOL_BUFFER_TOO_SMALL;

    memset(wire, 0, required);
    size_t inner_length = 3U + payload_length + 1U;
    build_outer_header(GOODIX_PROTOCOL_FLAG, inner_length, wire);

    uint8_t *inner = wire + 4;
    inner[0] = command;
    write_le16(inner + 1, (uint16_t)(payload_length + 1U));
    if (payload_length != 0)
        memcpy(inner + 3, payload, payload_length);
    inner[3 + payload_length] =
        use_checksum ? (uint8_t)(0xaaU - byte_sum(inner, 3 + payload_length))
                     : GOODIX_PROTOCOL_NULL_CHECKSUM;

    *wire_length = required;
    return GOODIX_PROTOCOL_OK;
}

GoodixProtocolResult
goodix_protocol_parse_outer(const uint8_t *wire,
                            size_t wire_length,
                            GoodixOuterFrame *frame)
{
    if (wire == NULL || frame == NULL)
        return GOODIX_PROTOCOL_INVALID_ARGUMENT;
    if (wire_length < 4)
        return GOODIX_PROTOCOL_INVALID_LENGTH;
    if (byte_sum(wire, 3) != wire[3])
        return GOODIX_PROTOCOL_INVALID_CHECKSUM;

    size_t data_length = read_le16(wire + 1);
    if (data_length > wire_length - 4U)
        return GOODIX_PROTOCOL_INVALID_LENGTH;

    frame->flags = wire[0];
    frame->data = wire + 4;
    frame->length = data_length;
    return GOODIX_PROTOCOL_OK;
}

GoodixProtocolResult
goodix_protocol_parse_message(const uint8_t *data,
                              size_t data_length,
                              GoodixProtocolMessage *message)
{
    if (data == NULL || message == NULL)
        return GOODIX_PROTOCOL_INVALID_ARGUMENT;
    if (data_length < 4)
        return GOODIX_PROTOCOL_INVALID_LENGTH;

    size_t length_field = read_le16(data + 1);
    if (length_field < 1U || length_field != data_length - 3U)
        return GOODIX_PROTOCOL_INVALID_LENGTH;

    size_t payload_length = length_field - 1U;
    uint8_t actual_checksum = data[3 + payload_length];
    uint8_t expected_checksum =
        (uint8_t)(0xaaU - byte_sum(data, 3 + payload_length));
    if (actual_checksum != expected_checksum &&
        actual_checksum != GOODIX_PROTOCOL_NULL_CHECKSUM)
        return GOODIX_PROTOCOL_INVALID_CHECKSUM;

    message->command = data[0];
    message->payload = data + 3;
    message->payload_length = payload_length;
    return GOODIX_PROTOCOL_OK;
}

GoodixProtocolResult
goodix_protocol_expect_message(const GoodixProtocolMessage *message,
                               uint8_t expected_command)
{
    if (message == NULL)
        return GOODIX_PROTOCOL_INVALID_ARGUMENT;
    if (message->command != expected_command)
        return GOODIX_PROTOCOL_UNEXPECTED_COMMAND;
    return GOODIX_PROTOCOL_OK;
}

GoodixProtocolResult
goodix_protocol_expect_ack(const GoodixProtocolMessage *message,
                           uint8_t expected_command,
                           uint8_t *status)
{
    if (message == NULL)
        return GOODIX_PROTOCOL_INVALID_ARGUMENT;
    if (message->command != GOODIX_PROTOCOL_ACK ||
        message->payload_length < 2U ||
        message->payload[0] != expected_command)
        return GOODIX_PROTOCOL_UNEXPECTED_COMMAND;

    if (status != NULL)
        *status = message->payload[1];
    if ((message->payload[1] & 0x01U) == 0)
        return GOODIX_PROTOCOL_NEGATIVE_ACK;
    return GOODIX_PROTOCOL_OK;
}

const char *
goodix_protocol_result_string(GoodixProtocolResult result)
{
    switch (result) {
    case GOODIX_PROTOCOL_OK:
        return "success";
    case GOODIX_PROTOCOL_INVALID_ARGUMENT:
        return "invalid argument";
    case GOODIX_PROTOCOL_BUFFER_TOO_SMALL:
        return "buffer too small";
    case GOODIX_PROTOCOL_INVALID_LENGTH:
        return "invalid length";
    case GOODIX_PROTOCOL_INVALID_CHECKSUM:
        return "invalid checksum";
    case GOODIX_PROTOCOL_UNEXPECTED_COMMAND:
        return "unexpected command";
    case GOODIX_PROTOCOL_NEGATIVE_ACK:
        return "negative acknowledgement";
    }
    return "unknown protocol error";
}

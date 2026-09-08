/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GOODIX_PROTOCOL_FLAG 0xa0
#define GOODIX_TLS_FLAG 0xb0
#define GOODIX_TLS_DATA_FLAG 0xb2
#define GOODIX_PROTOCOL_ACK 0xb0
#define GOODIX_PROTOCOL_NULL_CHECKSUM 0x88
#define GOODIX_PROTOCOL_USB_BLOCK_SIZE 64

typedef enum {
    GOODIX_PROTOCOL_OK = 0,
    GOODIX_PROTOCOL_INVALID_ARGUMENT,
    GOODIX_PROTOCOL_BUFFER_TOO_SMALL,
    GOODIX_PROTOCOL_INVALID_LENGTH,
    GOODIX_PROTOCOL_INVALID_CHECKSUM,
    GOODIX_PROTOCOL_UNEXPECTED_COMMAND,
    GOODIX_PROTOCOL_NEGATIVE_ACK,
} GoodixProtocolResult;

/* Views returned by the parsers borrow memory from their input buffer. */
typedef struct {
    uint8_t flags;
    const uint8_t *data;
    size_t length;
} GoodixOuterFrame;

typedef struct {
    uint8_t command;
    const uint8_t *payload;
    size_t payload_length;
} GoodixProtocolMessage;

size_t goodix_protocol_wire_size(size_t payload_length);

size_t goodix_outer_wire_size(size_t payload_length);

GoodixProtocolResult goodix_protocol_build_outer(uint8_t flags,
                                                 const uint8_t *payload,
                                                 size_t payload_length,
                                                 uint8_t *wire,
                                                 size_t wire_capacity,
                                                 size_t *wire_length);

GoodixProtocolResult goodix_protocol_build_command(uint8_t command,
                                                   const uint8_t *payload,
                                                   size_t payload_length,
                                                   bool use_checksum,
                                                   uint8_t *wire,
                                                   size_t wire_capacity,
                                                   size_t *wire_length);

GoodixProtocolResult goodix_protocol_parse_outer(const uint8_t *wire,
                                                 size_t wire_length,
                                                 GoodixOuterFrame *frame);

GoodixProtocolResult goodix_protocol_parse_message(
    const uint8_t *data,
    size_t data_length,
    GoodixProtocolMessage *message);

GoodixProtocolResult goodix_protocol_expect_message(
    const GoodixProtocolMessage *message,
    uint8_t expected_command);

GoodixProtocolResult goodix_protocol_expect_ack(
    const GoodixProtocolMessage *message,
    uint8_t expected_command,
    uint8_t *status);

const char *goodix_protocol_result_string(GoodixProtocolResult result);

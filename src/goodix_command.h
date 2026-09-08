/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "goodix_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    GOODIX_COMMAND_WAITING_ACK = 0,
    GOODIX_COMMAND_WAITING_REPLY,
    GOODIX_COMMAND_COMPLETE,
    GOODIX_COMMAND_FAILED,
} GoodixCommandState;

typedef enum {
    GOODIX_COMMAND_ACCEPTED = 0,
    GOODIX_COMMAND_FINISHED,
    GOODIX_COMMAND_INVALID_STATE,
    GOODIX_COMMAND_UNEXPECTED_FLAGS,
    GOODIX_COMMAND_PROTOCOL_ERROR,
} GoodixCommandResult;

typedef struct {
    uint8_t command;
    uint8_t reply_command;
    bool expects_reply;
    GoodixCommandState state;
    GoodixProtocolResult protocol_error;
} GoodixCommand;

void goodix_command_init(GoodixCommand *command,
                         uint8_t command_id,
                         bool expects_reply,
                         uint8_t reply_command);

GoodixCommandResult goodix_command_feed(GoodixCommand *command,
                                        uint8_t outer_flags,
                                        const uint8_t *data,
                                        size_t data_length,
                                        GoodixProtocolMessage *reply);

const char *goodix_command_result_string(GoodixCommandResult result);

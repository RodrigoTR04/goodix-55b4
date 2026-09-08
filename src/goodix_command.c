/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_command.h"

void
goodix_command_init(GoodixCommand *command,
                    uint8_t command_id,
                    bool expects_reply,
                    uint8_t reply_command)
{
    if (command == NULL)
        return;
    command->command = command_id;
    command->reply_command = reply_command;
    command->expects_reply = expects_reply;
    command->state = GOODIX_COMMAND_WAITING_ACK;
    command->protocol_error = GOODIX_PROTOCOL_OK;
}

GoodixCommandResult
goodix_command_feed(GoodixCommand *command,
                    uint8_t outer_flags,
                    const uint8_t *data,
                    size_t data_length,
                    GoodixProtocolMessage *reply)
{
    if (command == NULL || data == NULL)
        return GOODIX_COMMAND_INVALID_STATE;
    if (command->state == GOODIX_COMMAND_COMPLETE ||
        command->state == GOODIX_COMMAND_FAILED)
        return GOODIX_COMMAND_INVALID_STATE;
    if (outer_flags != GOODIX_PROTOCOL_FLAG) {
        command->state = GOODIX_COMMAND_FAILED;
        return GOODIX_COMMAND_UNEXPECTED_FLAGS;
    }

    GoodixProtocolMessage message;
    command->protocol_error =
        goodix_protocol_parse_message(data, data_length, &message);
    if (command->protocol_error != GOODIX_PROTOCOL_OK)
        goto protocol_error;

    if (command->state == GOODIX_COMMAND_WAITING_ACK) {
        command->protocol_error =
            goodix_protocol_expect_ack(&message, command->command, NULL);
        if (command->protocol_error != GOODIX_PROTOCOL_OK)
            goto protocol_error;
        if (command->expects_reply) {
            command->state = GOODIX_COMMAND_WAITING_REPLY;
            return GOODIX_COMMAND_ACCEPTED;
        }
        command->state = GOODIX_COMMAND_COMPLETE;
        return GOODIX_COMMAND_FINISHED;
    }

    command->protocol_error =
        goodix_protocol_expect_message(&message, command->reply_command);
    if (command->protocol_error != GOODIX_PROTOCOL_OK)
        goto protocol_error;
    if (reply != NULL)
        *reply = message;
    command->state = GOODIX_COMMAND_COMPLETE;
    return GOODIX_COMMAND_FINISHED;

protocol_error:
    command->state = GOODIX_COMMAND_FAILED;
    return GOODIX_COMMAND_PROTOCOL_ERROR;
}

const char *
goodix_command_result_string(GoodixCommandResult result)
{
    switch (result) {
    case GOODIX_COMMAND_ACCEPTED:
        return "message accepted";
    case GOODIX_COMMAND_FINISHED:
        return "command complete";
    case GOODIX_COMMAND_INVALID_STATE:
        return "invalid command state";
    case GOODIX_COMMAND_UNEXPECTED_FLAGS:
        return "unexpected outer flags";
    case GOODIX_COMMAND_PROTOCOL_ERROR:
        return "protocol error";
    }
    return "unknown command error";
}

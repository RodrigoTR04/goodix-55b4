/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_session.h"
#include "goodix_calibration.h"
#include "goodix_command.h"
#include "goodix_format.h"
#include "goodix_psk.h"
#include <stdlib.h>
#include <string.h>

#define GOODIX_SESSION_CAPTURE_TIMEOUT_MS 15000U
#define GOODIX_SESSION_TOUCH_TIMEOUT_MS 120000U

struct GoodixSession {
    GoodixActivationProfile profiles[2];
    GoodixActivation *activation;
    GoodixTransport *transport;
    GoodixTlsSession *tls;
    GoodixCommand command;
    GoodixConfigCalibration calibration;
    GoodixSessionState state;
    GoodixActivationActionKind action;
    uint64_t deadline;
    uint64_t nop_limit;
    bool nop_input;
    bool started;
    bool replied;
    bool stopped;
    bool cancel_requested;
    bool frame_requested;
    bool frame_acked;
    bool frame_received;
    GoodixFrameMetadata frame_metadata;
    GoodixFrameResult frame_result;
    bool capture_mode;
    bool capture_command_pending;
    bool capture_frame_expected;
    bool capture_frame_acked;
    uint8_t capture_command;
    uint64_t capture_deadline;
    uint8_t capture_plaintext[GOODIX_FORMAT_PLAINTEXT_BYTES];
    size_t capture_plaintext_length;
    GoodixSessionCaptureReply capture_reply;
    GoodixSessionCaptureFrame capture_frame;
    void *capture_user_data;
    char firmware[64];
    GoodixTransportSubmit submit;
    void *user_data;
    bool provision_community;
};

static void wipe(void *data, size_t size)
{
    volatile uint8_t *p = data;
    while (size--)
        *p++ = 0;
}

static bool
capture_store_plaintext(void *user_data, const uint8_t *bytes, size_t length)
{
    GoodixSession *s = user_data;

    if (bytes == NULL || length > GOODIX_FORMAT_PLAINTEXT_BYTES -
        s->capture_plaintext_length)
        return false;
    memcpy(s->capture_plaintext + s->capture_plaintext_length, bytes, length);
    s->capture_plaintext_length += length;
    return true;
}

static void
capture_clear(GoodixSession *s)
{
    wipe(s->capture_plaintext, sizeof(s->capture_plaintext));
    s->capture_plaintext_length = 0;
    s->capture_mode = false;
    s->capture_command_pending = false;
    s->capture_frame_expected = false;
    s->capture_frame_acked = false;
    s->capture_command = 0;
    s->capture_deadline = 0;
}

static bool
capture_command_allowed(uint8_t command, bool expects_reply)
{
    switch (command) {
    case 0x32:
    case 0x34:
    case 0x36:
        return expects_reply;
    case 0x20:
    case 0x60:
        return !expects_reply;
    default:
        return false;
    }
}

static uint64_t
capture_timeout_ms(uint8_t command)
{
    if (command == 0x32 || command == 0x34)
        return GOODIX_SESSION_TOUCH_TIMEOUT_MS;
    return GOODIX_SESSION_CAPTURE_TIMEOUT_MS;
}

void goodix_session_fail(GoodixSession *s, bool cancelled)
{
    if (s->state == GOODIX_SESSION_FINISHED ||
        s->state == GOODIX_SESSION_STOPPING)
        return;
    if (cancelled && s->cancel_requested)
        return;
    if (cancelled && s->state == GOODIX_SESSION_RUNNING &&
        (s->action == GOODIX_ACTIVATION_REQUEST_TLS ||
         s->action == GOODIX_ACTIVATION_EXCHANGE_TLS ||
         s->action == GOODIX_ACTIVATION_WAIT_TLS_QUIET ||
         s->action == GOODIX_ACTIVATION_NOTIFY_TLS_ESTABLISHED)) {
        /* Abandoning this firmware mid-handshake triggers a USB reconnect.
         * Finish only the bounded handshake, then idle, with no config upload. */
        s->cancel_requested = true;
        return;
    }
    if (s->state == GOODIX_SESSION_ACTIVE || s->state == GOODIX_SESSION_CAPTURING)
        capture_clear(s);
    if (s->state == GOODIX_SESSION_ACTIVE || s->state == GOODIX_SESSION_CAPTURING)
        goodix_activation_deactivate(s->activation);
    goodix_activation_advance(s->activation, cancelled ?
        GOODIX_ACTIVATION_EVENT_CANCELLED : GOODIX_ACTIVATION_EVENT_IO_FAILED,
        NULL);
    s->started = false;
    s->frame_received = false;
    memset(&s->frame_metadata, 0, sizeof(s->frame_metadata));
    s->state = GOODIX_SESSION_STOPPING;
}

static void done(void *data, GoodixTransportResult result)
{
    GoodixSession *s = data;
    if (result != GOODIX_TRANSPORT_OK && result != GOODIX_TRANSPORT_CANCELLED)
        goodix_session_fail(s, false);
}

static void received(void *data, uint8_t flags, const uint8_t *bytes, size_t size)
{
    GoodixSession *s = data;
    GoodixProtocolMessage reply = {0};
    GoodixCommandResult result;
    if (s->state == GOODIX_SESSION_CAPTURING && s->capture_mode) {
        if (s->capture_command_pending && flags == GOODIX_PROTOCOL_FLAG) {
            result = goodix_command_feed(&s->command, flags, bytes, size,
                                         &reply);
            if (result == GOODIX_COMMAND_ACCEPTED)
                return;
            if (result == GOODIX_COMMAND_FINISHED) {
                GoodixSessionCaptureReply callback = s->capture_reply;
                void *user_data = s->capture_user_data;
                uint8_t command = s->capture_command;
                bool frame_expected = s->capture_frame_expected;

                s->capture_command_pending = false;
                s->capture_frame_acked = frame_expected;
                s->capture_deadline = frame_expected ? s->capture_deadline : 0;
                if (!frame_expected) {
                    s->capture_mode = false;
                    s->state = GOODIX_SESSION_ACTIVE;
                }
                if (callback != NULL)
                    callback(user_data, command, true,
                             reply.payload, reply.payload_length);
                return;
            }
            goodix_session_fail(s, false);
            return;
        }
        if (s->capture_frame_expected && s->capture_frame_acked &&
            flags == GOODIX_TLS_DATA_FLAG) {
            GoodixFrameMetadata metadata;
            GoodixFrameResult frame_result;
            GoodixSessionCaptureFrame callback = s->capture_frame;
            void *user_data = s->capture_user_data;
            bool success;

            s->capture_plaintext_length = 0;
            frame_result = goodix_frame_consume_sink(
                s->tls, flags, bytes, size, capture_store_plaintext, s,
                &metadata);
            success = frame_result == GOODIX_FRAME_OK &&
                metadata.plaintext_bytes == GOODIX_FORMAT_PLAINTEXT_BYTES &&
                s->capture_plaintext_length == GOODIX_FORMAT_PLAINTEXT_BYTES;
            s->capture_mode = false;
            s->capture_command_pending = false;
            s->capture_frame_expected = false;
            s->capture_frame_acked = false;
            s->capture_deadline = 0;
            s->state = GOODIX_SESSION_ACTIVE;
            if (callback != NULL)
                callback(user_data, success,
                         success ? s->capture_plaintext : NULL,
                         success ? s->capture_plaintext_length : 0);
            wipe(s->capture_plaintext, sizeof(s->capture_plaintext));
            s->capture_plaintext_length = 0;
            if (!success && callback == NULL)
                goodix_session_fail(s, false);
            return;
        }
        goodix_session_fail(s, false);
        return;
    }
    if (s->state == GOODIX_SESSION_CAPTURING) {
        if (!s->frame_acked && flags == GOODIX_PROTOCOL_FLAG) {
            if (goodix_command_feed(&s->command, flags, bytes, size, NULL) == GOODIX_COMMAND_FINISHED)
                s->frame_acked = true;
            else
                goodix_session_fail(s, false);
        } else if (s->frame_acked && !s->frame_received && flags == GOODIX_TLS_DATA_FLAG) {
            s->frame_result = goodix_frame_consume(s->tls, flags, bytes, size, &s->frame_metadata);
            /* This is one-shot research: destroy TLS-owned buffers immediately. */
            goodix_tls_session_free(s->tls);
            s->tls = NULL;
            if (s->frame_result == GOODIX_FRAME_OK)
                s->frame_received = true;
            else
                goodix_session_fail(s, false);
        } else {
            goodix_session_fail(s, false);
        }
        return;
    }
    if (s->state != GOODIX_SESSION_RUNNING)
        return;
    if (s->action == GOODIX_ACTIVATION_START_RECEIVE)
        return; /* Queued traffic before the initial housekeeping action. */
    if (s->action == GOODIX_ACTIVATION_NOP) {
        s->nop_input = true;
        return; /* Drain stale replies; NOP has no mandatory response. */
    }
    if (flags == GOODIX_TLS_FLAG &&
        (s->action == GOODIX_ACTIVATION_EXCHANGE_TLS ||
         (s->action == GOODIX_ACTIVATION_REQUEST_TLS && s->replied))) {
        GoodixTlsResult r = goodix_tls_session_feed(s->tls, bytes, size);
        if (r != GOODIX_TLS_OK && r != GOODIX_TLS_WANT_INPUT &&
            r != GOODIX_TLS_ESTABLISHED)
            goodix_session_fail(s, false);
        return;
    }
    uint8_t command;
    if (!s->started || s->replied ||
        !goodix_activation_action_command(s->action, &command)) {
        goodix_session_fail(s, false);
        return;
    }
    result = goodix_command_feed(&s->command, flags, bytes, size, &reply);
    if (result == GOODIX_COMMAND_ACCEPTED)
        return;
    if (result != GOODIX_COMMAND_FINISHED) {
        goodix_session_fail(s, false);
        return;
    }
    switch (s->action) {
    case GOODIX_ACTIVATION_QUERY_FIRMWARE:
        if (reply.payload_length == 0 || reply.payload_length >= sizeof(s->firmware))
            goto bad;
        memcpy(s->firmware, reply.payload, reply.payload_length);
        s->firmware[reply.payload_length] = 0;
        /* Reject suffix bytes after the first NUL, too. */
        for (size_t i = strlen(s->firmware); i < reply.payload_length; i++)
            if (reply.payload[i] != 0)
                goto bad;
        break;
    case GOODIX_ACTIVATION_READ_PSK_STATUS: {
        bool matches_community = false;

        if (goodix_psk_parse_pmk_status(reply.payload, reply.payload_length,
                                        &matches_community) != GOODIX_PSK_OK)
            goto bad;
        if (goodix_activation_set_community_psk_write(
                s->activation,
                s->provision_community && !matches_community) !=
            GOODIX_ACTIVATION_OK)
            goto bad;
        break;
    }
    case GOODIX_ACTIVATION_WRITE_PSK:
        if (goodix_psk_parse_write_response(reply.payload,
                                            reply.payload_length) !=
            GOODIX_PSK_OK)
            goto bad;
        break;
    case GOODIX_ACTIVATION_RESET_SENSOR:
        if (reply.payload_length < 3 || reply.payload[0] != 1)
            goto bad;
        break;
    case GOODIX_ACTIVATION_READ_OTP:
        if (goodix_calibration_decode_gf3208(reply.payload, reply.payload_length,
                                            &s->calibration) != GOODIX_CALIBRATION_OK)
            goto bad;
        break;
    case GOODIX_ACTIVATION_UPLOAD_CONFIG:
        if (reply.payload_length < 1 || reply.payload[0] != 1)
            goto bad;
        break;
    default:
        break;
    }
    s->replied = true;
    return;
bad:
    goodix_session_fail(s, false);
}

static void submit(void *data, const uint8_t *bytes, size_t size)
{
    GoodixSession *s = data;
    s->submit(s->user_data, bytes, size);
}

GoodixSession *goodix_session_new(const uint8_t *psk, size_t length,
                                 bool provision_community,
                                 GoodixTransportSubmit callback, void *user_data)
{
    GoodixSession *s;
    GoodixActivationDiscovery discovery = {
        .command_timeout_ms = 5000, .nop_timeout_ms = 100,
    };
    if (callback == NULL)
        return NULL;
    s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->submit = callback;
    s->user_data = user_data;
    s->provision_community = provision_community;
    s->profiles[0] = goodix_activation_profile_55b4();
    s->profiles[1] = s->profiles[0];
    /* 55b4 units may report this alternate identity after transient
     * initialization. No prefix or other revision is accepted. */
    s->profiles[1].firmware = "GF3268_RTSEC_APP_10042";
    if (goodix_activation_new(&discovery, s->profiles, 2, &s->activation) !=
        GOODIX_ACTIVATION_OK)
        goto bad;
    if (goodix_tls_session_new(psk, length, &s->tls) != GOODIX_TLS_OK)
        goto bad;
    s->transport = goodix_transport_new(submit, received, done, s);
    if (!s->transport)
        goto bad;
    goodix_transport_set_compact_input(s->transport);
    return s;
bad:
    goodix_session_free(s);
    return NULL;
}

void goodix_session_free(GoodixSession *s)
{
    if (!s)
        return;
    goodix_activation_free(s->activation);
    goodix_tls_session_free(s->tls);
    goodix_transport_free(s->transport);
    capture_clear(s);
    wipe(s, sizeof(*s));
    free(s);
}

static bool send_command(GoodixSession *s, const GoodixActivationAction *action)
{
    uint8_t command, wire[320], payload[8] = {0};
    uint8_t write_payload[GOODIX_PSK_WRITE_PAYLOAD_SIZE];
    const uint8_t *body = payload;
    size_t length = 2, wire_length = 0;
    bool reply = true;
    if (!goodix_activation_action_command(action->kind, &command))
        return false;
    switch (action->kind) {
    case GOODIX_ACTIVATION_NOP:
        length = 4; reply = false;
        break;
    case GOODIX_ACTIVATION_REQUEST_TLS:
    case GOODIX_ACTIVATION_NOTIFY_TLS_ESTABLISHED:
        reply = false;
        break;
    case GOODIX_ACTIVATION_READ_PSK_STATUS:
        payload[0] = 7; payload[2] = 2; payload[3] = 0xbb; length = 8;
        break;
    case GOODIX_ACTIVATION_WRITE_PSK:
        if (!s->provision_community ||
            goodix_psk_build_community_write(write_payload) != GOODIX_PSK_OK)
            return false;
        body = write_payload;
        length = sizeof(write_payload);
        break;
    case GOODIX_ACTIVATION_RESET_SENSOR:
        payload[0] = 5; payload[1] = 20;
        break;
    case GOODIX_ACTIVATION_MCU_IDLE:
        /* Public 55x4 idle layout; acceptance is hardware-qualified separately. */
        payload[0] = 20; reply = false;
        break;
    case GOODIX_ACTIVATION_UPLOAD_CONFIG:
        body = action->configuration; length = action->configuration_length;
        break;
    case GOODIX_ACTIVATION_QUERY_FIRMWARE:
    case GOODIX_ACTIVATION_READ_OTP:
        break;
    default:
        return false; /* Candidate planner actions are not executable here. */
    }
    goodix_command_init(&s->command, command, reply, command);
    bool ok = goodix_protocol_build_command(command, body, length,
        action->kind != GOODIX_ACTIVATION_NOP, wire,
        sizeof(wire), &wire_length) == GOODIX_PROTOCOL_OK &&
        goodix_transport_send(s->transport, wire, wire_length) == GOODIX_TRANSPORT_OK;
    wipe(wire, sizeof(wire));
    wipe(write_payload, sizeof(write_payload));
    return ok;
}

static bool send_tls(GoodixSession *s)
{
    size_t length = goodix_tls_session_pending_output(s->tls);
    size_t capacity = goodix_outer_wire_size(length), wire_length = 0;
    uint8_t *plain = malloc(length), *wire = malloc(capacity);
    bool ok = plain && wire && capacity &&
        goodix_tls_session_take_output(s->tls, plain, length, &length) == GOODIX_TLS_OK &&
        goodix_protocol_build_outer(GOODIX_TLS_FLAG, plain, length, wire, capacity,
                                     &wire_length) == GOODIX_PROTOCOL_OK &&
        goodix_transport_send(s->transport, wire, wire_length) == GOODIX_TRANSPORT_OK;
    if (plain) { wipe(plain, length); free(plain); }
    if (wire) { wipe(wire, capacity); free(wire); }
    return ok;
}

void goodix_session_tick(GoodixSession *s, uint64_t now)
{
    GoodixActivationAction action;
    if (s->state == GOODIX_SESSION_CAPTURING && s->capture_mode) {
        if (now >= s->capture_deadline) {
            capture_clear(s);
            goodix_activation_deactivate(s->activation);
            goodix_activation_advance(s->activation,
                GOODIX_ACTIVATION_EVENT_TIMED_OUT, NULL);
            s->started = false;
            s->state = GOODIX_SESSION_STOPPING;
        }
        return;
    }
    if (s->state == GOODIX_SESSION_CAPTURING) {
        if (s->frame_received && !goodix_transport_is_sending(s->transport)) {
            s->state = GOODIX_SESSION_ACTIVE;
        } else if (now >= s->deadline) {
            goodix_activation_deactivate(s->activation);
            goodix_activation_advance(s->activation, GOODIX_ACTIVATION_EVENT_TIMED_OUT, NULL);
            s->started = false;
            s->frame_received = false;
            memset(&s->frame_metadata, 0, sizeof(s->frame_metadata));
            s->state = GOODIX_SESSION_STOPPING;
        }
        return;
    }
    if (s->state == GOODIX_SESSION_ACTIVE || s->state == GOODIX_SESSION_FINISHED)
        return;
    for (unsigned steps = 0; steps < 24; steps++) {
        if (!goodix_activation_current(s->activation, &action)) {
            s->state = goodix_activation_outcome(s->activation) == GOODIX_ACTIVATION_ACTIVATED ?
                GOODIX_SESSION_ACTIVE : GOODIX_SESSION_FINISHED;
            return;
        }
        s->action = action.kind;
        if (action.kind == GOODIX_ACTIVATION_STOP_IO) {
            s->state = GOODIX_SESSION_STOPPING;
            if (!s->stopped)
                return;
            goodix_transport_cancel(s->transport);
        } else if (action.kind == GOODIX_ACTIVATION_CLEAR_SECRETS) {
            goodix_tls_session_free(s->tls); s->tls = NULL;
            wipe(&s->calibration, sizeof(s->calibration));
        } else if (action.kind == GOODIX_ACTIVATION_START_RECEIVE) {
            /* Adapter queues IN before its first tick. */
        } else if (action.kind == GOODIX_ACTIVATION_BUILD_CONFIG) {
            uint8_t configuration[GOODIX_CONFIG_SIZE];
            bool ok = goodix_config_build_55b4(&s->calibration, configuration,
                         sizeof(configuration)) == GOODIX_CONFIG_OK &&
                goodix_activation_set_configuration(s->activation, configuration,
                         sizeof(configuration)) == GOODIX_ACTIVATION_OK;
            wipe(configuration, sizeof(configuration));
            wipe(&s->calibration, sizeof(s->calibration));
            if (!ok) { goodix_session_fail(s, false); continue; }
        } else {
            if (!s->started) {
                s->deadline = now + (action.wait_ms ? action.wait_ms : action.timeout_ms);
                s->started = true;
                s->replied = false;
                s->nop_limit = now + 5000;
                s->nop_input = false;
                if (action.kind != GOODIX_ACTIVATION_EXCHANGE_TLS &&
                    action.kind != GOODIX_ACTIVATION_WAIT_TLS_QUIET &&
                    !send_command(s, &action)) {
                    goodix_session_fail(s, false); continue;
                }
            }
            if (action.kind == GOODIX_ACTIVATION_NOP) {
                if (s->nop_input) {
                    s->deadline = now + action.timeout_ms;
                    s->nop_input = false;
                }
                if (now >= s->nop_limit) {
                    goodix_activation_advance(s->activation,
                        GOODIX_ACTIVATION_EVENT_TIMED_OUT, NULL);
                    s->started = false;
                    continue;
                }
            }
            if (action.kind == GOODIX_ACTIVATION_EXCHANGE_TLS &&
                !goodix_transport_is_sending(s->transport)) {
                if (goodix_tls_session_pending_output(s->tls)) {
                    if (!send_tls(s)) { goodix_session_fail(s, false); continue; }
                } else if (goodix_tls_session_is_established(s->tls)) {
                    s->replied = true;
                }
            }
            if (action.kind == GOODIX_ACTIVATION_WAIT_TLS_QUIET)
                s->replied = now >= s->deadline;
            if (!s->replied || goodix_transport_is_sending(s->transport)) {
                if (now < s->deadline)
                    return;
                if (action.kind != GOODIX_ACTIVATION_NOP ||
                    goodix_transport_is_sending(s->transport)) {
                    goodix_activation_advance(s->activation,
                        GOODIX_ACTIVATION_EVENT_TIMED_OUT, NULL);
                    s->started = false;
                    continue;
                }
                /* Discard any incomplete stale frame only after a quiet window. */
                goodix_transport_cancel(s->transport);
            }
        }
        if (s->cancel_requested && action.kind == GOODIX_ACTIVATION_NOTIFY_TLS_ESTABLISHED) {
            if (goodix_activation_cancel_after_tls(s->activation) != GOODIX_ACTIVATION_OK)
                goodix_session_fail(s, false);
            s->started = false;
            continue;
        }
        if (goodix_activation_advance(s->activation, GOODIX_ACTIVATION_EVENT_SUCCEEDED,
            action.kind == GOODIX_ACTIVATION_QUERY_FIRMWARE ? s->firmware : NULL) !=
            GOODIX_ACTIVATION_OK) {
            goodix_session_fail(s, false);
        }
        s->started = false;
    }
}

void goodix_session_feed(GoodixSession *s, const uint8_t *data, size_t size)
{
    if ((s->state == GOODIX_SESSION_RUNNING || s->state == GOODIX_SESSION_CAPTURING) &&
        goodix_transport_feed(s->transport, data, size) != GOODIX_TRANSPORT_OK)
        goodix_session_fail(s, false);
}
void goodix_session_out_complete(GoodixSession *s, bool success)
{
    if (s->state == GOODIX_SESSION_RUNNING || s->state == GOODIX_SESSION_CAPTURING)
        goodix_transport_out_complete(s->transport, success);
}
void goodix_session_deactivate(GoodixSession *s)
{
    if (s->state != GOODIX_SESSION_ACTIVE && s->state != GOODIX_SESSION_CAPTURING)
        return;
    capture_clear(s);
    goodix_activation_deactivate(s->activation);
    s->started = false;
    s->state = GOODIX_SESSION_RUNNING;
}
void goodix_session_stopped(GoodixSession *s) { s->stopped = true; }
GoodixSessionState goodix_session_state(const GoodixSession *s) { return s->state; }
GoodixActivationOutcome goodix_session_outcome(const GoodixSession *s)
{ return goodix_activation_outcome(s->activation); }
GoodixActivationActionKind goodix_session_action(const GoodixSession *s) { return s->action; }

bool
goodix_session_capture_configure(GoodixSession *s,
                                 GoodixSessionCaptureReply reply,
                                 GoodixSessionCaptureFrame frame,
                                 void *user_data)
{
    if (s == NULL || reply == NULL || frame == NULL ||
        s->state != GOODIX_SESSION_ACTIVE || s->capture_mode)
        return false;
    s->capture_reply = reply;
    s->capture_frame = frame;
    s->capture_user_data = user_data;
    return true;
}

bool
goodix_session_capture_command(GoodixSession *s, uint8_t command,
                               const uint8_t *payload, size_t payload_length,
                               bool expects_reply, uint64_t now_ms)
{
    size_t capacity;
    size_t wire_length = 0;
    uint8_t *wire;
    bool ok;

    if (s == NULL || s->state != GOODIX_SESSION_ACTIVE ||
        s->capture_reply == NULL || s->capture_frame == NULL ||
        s->capture_mode || goodix_transport_is_sending(s->transport) ||
        (payload == NULL && payload_length != 0) ||
        !capture_command_allowed(command, expects_reply))
        return false;
    capacity = goodix_protocol_wire_size(payload_length);
    if (capacity == 0)
        return false;
    wire = malloc(capacity);
    if (wire == NULL)
        return false;
    ok = goodix_protocol_build_command(command, payload, payload_length, true,
                                       wire, capacity, &wire_length) ==
        GOODIX_PROTOCOL_OK;
    if (ok) {
        s->capture_mode = true;
        s->capture_command_pending = true;
        s->capture_command = command;
        s->capture_frame_expected = command == 0x20;
        s->capture_frame_acked = false;
        s->capture_deadline = now_ms + capture_timeout_ms(command);
        s->capture_plaintext_length = 0;
        s->state = GOODIX_SESSION_CAPTURING;
        goodix_command_init(&s->command, command, expects_reply, command);
        ok = goodix_transport_send(s->transport, wire, wire_length) ==
            GOODIX_TRANSPORT_OK;
        if (!ok) {
            capture_clear(s);
            s->state = GOODIX_SESSION_ACTIVE;
        }
    }
    wipe(wire, capacity);
    free(wire);
    return ok;
}

bool
goodix_session_capture_busy(const GoodixSession *s)
{
    return s != NULL && s->capture_mode;
}

bool goodix_session_capture_metadata(GoodixSession *s, uint64_t now)
{
    uint8_t wire[64]; size_t length = 0;
    const uint8_t request[] = {1, 0};
    if (s == NULL || s->state != GOODIX_SESSION_ACTIVE || s->frame_requested ||
        !goodix_tls_session_is_established(s->tls))
        return false;
    if (goodix_protocol_build_command(0x20, request, sizeof(request), true,
        wire, sizeof(wire), &length) != GOODIX_PROTOCOL_OK)
        return false;
    s->frame_requested = true;
    s->frame_result = GOODIX_FRAME_INVALID_WRAPPER;
    s->state = GOODIX_SESSION_CAPTURING;
    s->deadline = now + 5000;
    goodix_command_init(&s->command, 0x20, false, 0x20);
    bool ok = goodix_transport_send(s->transport, wire, length) == GOODIX_TRANSPORT_OK;
    wipe(wire, sizeof(wire));
    if (!ok) goodix_session_fail(s, false);
    return ok;
}
bool goodix_session_frame_metadata(const GoodixSession *s, GoodixFrameMetadata *metadata)
{
    if (metadata == NULL) return false;
    memset(metadata, 0, sizeof(*metadata));
    if (s == NULL || !s->frame_received) return false;
    *metadata = s->frame_metadata;
    return true;
}
GoodixFrameResult goodix_session_frame_result(const GoodixSession *s)
{
    return s->frame_result;
}

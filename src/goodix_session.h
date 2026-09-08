/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include "goodix_activation.h"
#include "goodix_transport.h"
#include "goodix_tls.h"
#include "goodix_frame.h"

typedef struct GoodixSession GoodixSession;
typedef enum {
    GOODIX_SESSION_RUNNING,
    GOODIX_SESSION_ACTIVE,
    GOODIX_SESSION_STOPPING,
    GOODIX_SESSION_FINISHED,
    GOODIX_SESSION_CAPTURING,
} GoodixSessionState;

/* Capture callbacks borrow reply and plaintext bytes until they return. A
 * callback must consume them synchronously; the session wipes the frame after
 * the callback. These hooks keep the transport/TLS boundary independent from
 * the finger-cycle planner and from libfprint. */
typedef void (*GoodixSessionCaptureReply)(void *user_data, uint8_t command,
    bool success, const uint8_t *reply, size_t reply_length);
typedef void (*GoodixSessionCaptureFrame)(void *user_data, bool success,
    const uint8_t *plaintext, size_t plaintext_length);

/* Single-threaded, incremental engine. submit must queue an asynchronous USB
 * block and must not call back inline. Call tick after input/output callbacks
 * and periodically (monotonic milliseconds). No callback prints payloads.
 * STOPPING requires cancelling AND draining every USB transfer before stopped.
 * Free only after that drain. A new session is required for reactivation.
 * provision_community writes the public white-box when the PMK hash mismatches. */
GoodixSession *goodix_session_new(const uint8_t *psk, size_t length,
                                 bool provision_community,
                                 GoodixTransportSubmit submit, void *user_data);
void goodix_session_free(GoodixSession *session);
void goodix_session_tick(GoodixSession *session, uint64_t now_ms);
void goodix_session_feed(GoodixSession *session, const uint8_t *data, size_t length);
void goodix_session_out_complete(GoodixSession *session, bool success);
void goodix_session_fail(GoodixSession *session, bool cancelled);
void goodix_session_deactivate(GoodixSession *session);
void goodix_session_stopped(GoodixSession *session);
GoodixSessionState goodix_session_state(const GoodixSession *session);
GoodixActivationOutcome goodix_session_outcome(const GoodixSession *session);
GoodixActivationActionKind goodix_session_action(const GoodixSession *session);

bool goodix_session_capture_configure(GoodixSession *session,
    GoodixSessionCaptureReply reply, GoodixSessionCaptureFrame frame,
    void *user_data);
bool goodix_session_capture_command(GoodixSession *session, uint8_t command,
    const uint8_t *payload, size_t payload_length, bool expects_reply,
    uint64_t now_ms);
bool goodix_session_capture_busy(const GoodixSession *session);

/* Explicit single-frame development proof; unavailable before activation or
 * after a previous request. Returns only metadata, never image bytes. The TLS
 * object is destroyed immediately after frame processing. Deactivate next. */
bool goodix_session_capture_metadata(GoodixSession *session, uint64_t now_ms);
bool goodix_session_frame_metadata(const GoodixSession *session, GoodixFrameMetadata *metadata);
GoodixFrameResult goodix_session_frame_result(const GoodixSession *session);

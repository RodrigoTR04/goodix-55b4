/* SPDX-License-Identifier: LGPL-2.1-or-later */
#define _GNU_SOURCE
#include "goodix_session.h"
#include "goodix_key.h"
#include "goodix_psk.h"
#include "goodix_security.h"
#include <libusb-1.0/libusb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

static volatile sig_atomic_t interrupted;
static void interrupt_handler(int signal_number) { (void)signal_number; interrupted = 1; }
static uint64_t milliseconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
typedef struct {
    GoodixSession *session;
    struct libusb_transfer *in, *out;
    bool in_pending, out_pending, submit_failed;
    uint8_t in_buffer[65536], out_buffer[64];
} Adapter;
static void in_complete(struct libusb_transfer *transfer)
{
    Adapter *a = transfer->user_data;
    a->in_pending = false;
    if (transfer->status == LIBUSB_TRANSFER_COMPLETED)
        goodix_session_feed(a->session, transfer->buffer, (size_t)transfer->actual_length);
    else if (transfer->status != LIBUSB_TRANSFER_CANCELLED)
        goodix_session_fail(a->session, false);
    explicit_bzero(a->in_buffer, sizeof(a->in_buffer));
}
static void out_complete(struct libusb_transfer *transfer)
{
    Adapter *a = transfer->user_data;
    a->out_pending = false;
    explicit_bzero(a->out_buffer, sizeof(a->out_buffer));
    goodix_session_out_complete(a->session,
        transfer->status == LIBUSB_TRANSFER_COMPLETED && transfer->actual_length == transfer->length);
}
static void submit(void *data, const uint8_t *bytes, size_t size)
{
    Adapter *a = data;
    if (a->out_pending || size > sizeof(a->out_buffer)) abort();
    memcpy(a->out_buffer, bytes, size);
    a->out->length = (int)size;
    a->out_pending = libusb_submit_transfer(a->out) == 0;
    a->submit_failed = !a->out_pending;
    /* Submission failure is reported by the loop, never reentrantly. */
}
static int cycle(libusb_context *context, libusb_device_handle *handle,
                  const char *path, int cancel_action, unsigned number, bool frame_check)
{
    uint8_t key[GOODIX_TLS_PSK_SIZE];
    Adapter a = {0};
    bool stopping = false, active = false, cancelled = false, frame_requested = false;
    bool community = path == NULL;
    GoodixFrameMetadata metadata = {0};
    uint64_t start = milliseconds();
    GoodixActivationActionKind previous = GOODIX_ACTIVATION_CLEAR_SECRETS;
    if (community)
        goodix_psk_community_tls_key(key);
    else if (!goodix_key_read(path, key)) {
        fprintf(stderr, "private key file rejected\n"); return 1;
    }
    a.session = goodix_session_new(key, sizeof(key), community, submit, &a);
    explicit_bzero(key, sizeof(key));
    a.in = libusb_alloc_transfer(0); a.out = libusb_alloc_transfer(0);
    if (!a.session || !a.in || !a.out) {
        goodix_session_free(a.session);
        libusb_free_transfer(a.in); libusb_free_transfer(a.out); return 1;
    }
    libusb_fill_bulk_transfer(a.in, handle, 0x82, a.in_buffer, sizeof(a.in_buffer), in_complete, &a, 0);
    libusb_fill_bulk_transfer(a.out, handle, 0x01, a.out_buffer, sizeof(a.out_buffer), out_complete, &a, 5000);
    for (;;) {
        GoodixSessionState state = goodix_session_state(a.session);
        if (state == GOODIX_SESSION_FINISHED) break;
        if (!stopping && (state == GOODIX_SESSION_RUNNING || state == GOODIX_SESSION_ACTIVE ||
                          state == GOODIX_SESSION_CAPTURING) && !a.in_pending) {
            a.in_pending = libusb_submit_transfer(a.in) == 0;
            if (!a.in_pending) goodix_session_fail(a.session, false);
        }
        if (interrupted && !stopping) goodix_session_fail(a.session, true);
        if (a.submit_failed) goodix_session_fail(a.session, false);
        goodix_session_tick(a.session, milliseconds());
        GoodixActivationActionKind action = goodix_session_action(a.session);
        if (action != previous) {
            printf("cycle %u: stage %d (%llu ms)\n", number, action,
                (unsigned long long)(milliseconds() - start));
            previous = action;
        }
        if (!cancelled && cancel_action >= 0 && (int)action == cancel_action) {
            goodix_session_fail(a.session, true); cancelled = true;
        }
        state = goodix_session_state(a.session);
        if (state == GOODIX_SESSION_ACTIVE) {
            active = true;
            if (frame_check && !frame_requested) {
                frame_requested = true;
                if (!goodix_session_capture_metadata(a.session, milliseconds()))
                    goodix_session_fail(a.session, false);
            } else {
                if (frame_check && !goodix_session_frame_metadata(a.session, &metadata))
                    goodix_session_fail(a.session, false);
                else
                    goodix_session_deactivate(a.session);
            }
        }
        if (state == GOODIX_SESSION_STOPPING && !stopping) {
            stopping = true;
            if (a.in_pending) libusb_cancel_transfer(a.in);
            if (a.out_pending) libusb_cancel_transfer(a.out);
        }
        if (stopping && !a.in_pending && !a.out_pending) {
            goodix_session_stopped(a.session);
            goodix_session_tick(a.session, milliseconds());
            continue;
        }
        struct timeval wait = {.tv_usec = 1000};
        int result = libusb_handle_events_timeout(context, &wait);
        if (result != 0 && result != LIBUSB_ERROR_INTERRUPTED)
            goodix_session_fail(a.session, false);
    }
    GoodixActivationOutcome outcome = goodix_session_outcome(a.session);
    printf("cycle %u: outcome %d, activated %s, drained (%llu ms)\n",
        number, outcome, active ? "yes" : "no", (unsigned long long)(milliseconds() - start));
    if (frame_check) {
        if (outcome == GOODIX_ACTIVATION_DEACTIVATED && metadata.plaintext_bytes) {
            printf("frame_check: authenticated, wrapper_bytes=%zu prefix_bytes=%zu "
                   "tls_bytes=%zu tls_records=%zu plaintext_bytes=%zu; buffers discarded\n",
                   metadata.wrapper_bytes, metadata.prefix_bytes, metadata.tls_bytes,
                   metadata.tls_records, metadata.plaintext_bytes);
            printf("format_check: length_matches=%s candidate_width=%d candidate_height=%d "
                   "packed_row_bytes=%d\n",
                   metadata.format.length_matches ? "yes" : "no", GOODIX_FORMAT_WIDTH,
                   GOODIX_FORMAT_HEIGHT, GOODIX_FORMAT_ROW_BYTES);
        } else
            printf("frame_check: failed (validation_result=%d); buffers discarded\n",
                   goodix_session_frame_result(a.session));
    }
    goodix_session_free(a.session);
    libusb_free_transfer(a.in); libusb_free_transfer(a.out);
    explicit_bzero(&a, sizeof(a));
    return cancel_action >= 0 ? outcome != GOODIX_ACTIVATION_CANCELLED :
        outcome != GOODIX_ACTIVATION_DEACTIVATED;
}
int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s {ABSOLUTE_PSK_FILE | --community} CYCLES [CANCEL_ACTION_NUMBER | --frame-check]\n"
            "Default: activation only. --community writes the public white-box on mismatch.\n"
            "--frame-check requests one frame, reports metadata, and discards image bytes.\n", argv[0]);
        return 2;
    }
    char *end;
    const char *psk_path = strcmp(argv[1], "--community") == 0 ? NULL : argv[1];
    long cycles = strtol(argv[2], &end, 10);
    if (*end || cycles < 1 || cycles > 100) return 2;
    int cancel_action = -1;
    bool frame_check = argc == 4 && strcmp(argv[3], "--frame-check") == 0;
    if (frame_check && cycles != 1) return 2;
    if (argc == 4 && !frame_check) {
        long value = strtol(argv[3], &end, 10);
        if (*end || value < 0 || value >= GOODIX_ACTIVATION_STOP_IO) return 2;
        cancel_action = (int)value;
    }
    if (!goodix_security_disable_dumps()) return 1;
    signal(SIGINT, interrupt_handler); signal(SIGTERM, interrupt_handler);
    libusb_context *context = NULL;
    if (libusb_init(&context) != 0) return 1;
    libusb_device_handle *handle = libusb_open_device_with_vid_pid(context, 0x27c6, 0x55b4);
    if (!handle) { fprintf(stderr, "reader access unavailable\n"); libusb_exit(context); return 1; }
    uint8_t status[2]; int configuration = 0, result = 1;
    if (libusb_control_transfer(handle, 0x80, LIBUSB_REQUEST_GET_STATUS, 0, 0,
        status, sizeof(status), 1000) != 2 ||
        libusb_get_configuration(handle, &configuration) != 0) goto out;
    if (configuration != 1 && libusb_set_configuration(handle, 1) != 0) goto out;
    if (libusb_claim_interface(handle, 0) != 0) goto out;
    result = 0;
    for (long i = 0; i < cycles && !interrupted; i++) {
        if (cycle(context, handle, psk_path, cancel_action, (unsigned)i + 1, frame_check)) { result = 1; break; }
    }
    if (interrupted) result = 1;
    if (libusb_release_interface(handle, 0) != 0) result = 1;
out:
    libusb_close(handle); libusb_exit(context); return result;
}

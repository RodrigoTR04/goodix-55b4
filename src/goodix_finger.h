/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "goodix_image.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The GF3208 FDT reply has a two-word status header followed by twelve
 * little-endian sensor-zone bases. The command payload uses one byte of each
 * two-byte slot for the fixed 0x80 marker and one byte for the threshold. */
#define GOODIX_FINGER_ZONE_COUNT 12U
#define GOODIX_FINGER_FDT_EVENT_HEADER_BYTES 4U
#define GOODIX_FINGER_FDT_EVENT_BYTES \
    (GOODIX_FINGER_FDT_EVENT_HEADER_BYTES + GOODIX_FINGER_ZONE_COUNT * 2U)
#define GOODIX_FINGER_FDT_PAYLOAD_BYTES (2U + GOODIX_FINGER_ZONE_COUNT * 2U)

#define GOODIX_FINGER_COMMAND_FDT_DOWN 0x32U
#define GOODIX_FINGER_COMMAND_FDT_UP 0x34U
#define GOODIX_FINGER_COMMAND_FDT_MODE 0x36U
#define GOODIX_FINGER_COMMAND_GET_IMAGE 0x20U
#define GOODIX_FINGER_COMMAND_SLEEP 0x60U

typedef struct {
    uint16_t irq_status;
    uint16_t touch_flags;
    uint16_t zone[GOODIX_FINGER_ZONE_COUNT];
} GoodixFingerEvent;

typedef struct {
    uint8_t zone[GOODIX_FINGER_ZONE_COUNT];
    bool valid;
} GoodixFingerThresholds;

typedef enum {
    GOODIX_FINGER_FDT_MODE = 0x0d,
    GOODIX_FINGER_FDT_DOWN = 0x0c,
    GOODIX_FINGER_FDT_UP = 0x0e,
} GoodixFingerFdtOperation;

typedef enum {
    GOODIX_FINGER_OK,
    GOODIX_FINGER_INVALID_ARGUMENT,
    GOODIX_FINGER_INVALID_LENGTH,
    GOODIX_FINGER_INVALID_EVENT,
    GOODIX_FINGER_THRESHOLD_OUT_OF_RANGE,
    GOODIX_FINGER_THRESHOLDS_UNAVAILABLE,
    GOODIX_FINGER_BUFFER_TOO_SMALL,
    GOODIX_FINGER_NO_MEMORY,
    GOODIX_FINGER_BUSY,
    GOODIX_FINGER_STALE_ACTION,
    GOODIX_FINGER_TIMEOUT,
    GOODIX_FINGER_CANCELLED,
    GOODIX_FINGER_IO_ERROR,
    GOODIX_FINGER_DISCONNECTED,
    GOODIX_FINGER_IMAGE_ERROR,
    GOODIX_FINGER_EMIT_FAILED,
} GoodixFingerResult;

/* These are the operations exposed to the transport adapter. Payloads are
 * borrowed until the emit callback returns and must be copied by an adapter
 * that queues asynchronous USB work. The callback must not complete an action
 * inline. */
typedef enum {
    GOODIX_FINGER_ACTION_NONE,
    GOODIX_FINGER_ACTION_PROBE,
    GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND,
    GOODIX_FINGER_ACTION_FDT_DOWN,
    GOODIX_FINGER_ACTION_CAPTURE,
    GOODIX_FINGER_ACTION_FDT_UP,
    GOODIX_FINGER_ACTION_REFRESH_BACKGROUND,
    GOODIX_FINGER_ACTION_SLEEP,
} GoodixFingerAction;

typedef enum {
    GOODIX_FINGER_STATE_IDLE,
    GOODIX_FINGER_STATE_WAIT_PROBE,
    GOODIX_FINGER_STATE_WAIT_BACKGROUND,
    GOODIX_FINGER_STATE_WAIT_FINGER_DOWN,
    GOODIX_FINGER_STATE_WAIT_CAPTURE,
    GOODIX_FINGER_STATE_WAIT_FINGER_UP,
    GOODIX_FINGER_STATE_WAIT_REFRESH_BACKGROUND,
    GOODIX_FINGER_STATE_WAIT_SLEEP,
    GOODIX_FINGER_STATE_CLEANUP,
    GOODIX_FINGER_STATE_COMPLETE,
    GOODIX_FINGER_STATE_FAILED,
    GOODIX_FINGER_STATE_CANCELLED,
    GOODIX_FINGER_STATE_DISCONNECTED,
} GoodixFingerState;

typedef struct {
    uint32_t probe_timeout_ms;
    uint32_t background_timeout_ms;
    uint32_t finger_down_timeout_ms;
    uint32_t capture_timeout_ms;
    uint32_t finger_up_timeout_ms;
    uint32_t refresh_timeout_ms;
    uint32_t sleep_timeout_ms;
    /* Decode and combine this many consecutive frames while the finger stays
     * down. Bounded to GOODIX_FINGER_MAX_CAPTURE_FRAMES. */
    uint8_t capture_frames;
    /* Added to each runtime base >> 1. Keep this zero until a target-specific
     * qualification chooses a margin; no private threshold table is stored. */
    uint8_t threshold_margin;
} GoodixFingerCycleConfig;

#define GOODIX_FINGER_MAX_CAPTURE_FRAMES 4U

typedef struct {
    uint8_t frames;
    uint8_t compared_pairs;
    uint32_t mean_absolute_delta_milli;
    uint8_t maximum_absolute_delta;
    uint8_t selected_frame;
    uint32_t selected_gradient_milli;
} GoodixFingerStability;

typedef bool (*GoodixFingerCycleEmit)(void *user_data,
    GoodixFingerAction action, uint8_t command, const uint8_t *payload,
    size_t payload_length);
typedef bool (*GoodixFingerImageSink)(void *user_data, const uint8_t *pixels,
    size_t pixel_count);

typedef struct GoodixFingerCycle GoodixFingerCycle;

GoodixFingerResult goodix_finger_parse_event(const uint8_t *data, size_t length,
    GoodixFingerEvent *event);
GoodixFingerResult goodix_finger_thresholds_from_event(
    const GoodixFingerEvent *event, uint8_t margin,
    GoodixFingerThresholds *thresholds);
GoodixFingerResult goodix_finger_build_fdt_payload(GoodixFingerFdtOperation op,
    const GoodixFingerThresholds *thresholds, uint8_t *payload, size_t capacity);
bool goodix_finger_action_command(GoodixFingerAction action, uint8_t *command);
const char *goodix_finger_result_string(GoodixFingerResult result);

GoodixFingerCycleConfig goodix_finger_cycle_config_default(void);
GoodixFingerResult goodix_finger_cycle_new(
    GoodixImageDecoder *decoder, const GoodixFingerCycleConfig *config,
    GoodixFingerCycleEmit emit, GoodixFingerImageSink image_sink,
    void *user_data, GoodixFingerCycle **cycle);
void goodix_finger_cycle_free(GoodixFingerCycle *cycle);
GoodixFingerResult goodix_finger_cycle_reset(GoodixFingerCycle *cycle);
GoodixFingerResult goodix_finger_cycle_start(GoodixFingerCycle *cycle,
    uint64_t now_ms);
GoodixFingerResult goodix_finger_cycle_command_complete(
    GoodixFingerCycle *cycle, uint64_t now_ms, GoodixFingerAction action,
    bool success, const uint8_t *reply, size_t reply_length);
GoodixFingerResult goodix_finger_cycle_frame_complete(
    GoodixFingerCycle *cycle, uint64_t now_ms, const GoodixImageFrame *frame,
    bool confirmed_finger_absent);
GoodixFingerResult goodix_finger_cycle_frame_failed(GoodixFingerCycle *cycle,
    uint64_t now_ms);
GoodixFingerResult goodix_finger_cycle_disconnect(GoodixFingerCycle *cycle);

GoodixFingerState goodix_finger_cycle_state(const GoodixFingerCycle *cycle);
GoodixFingerAction goodix_finger_cycle_action(const GoodixFingerCycle *cycle);
bool goodix_finger_cycle_get_stability(const GoodixFingerCycle *cycle,
    GoodixFingerStability *stability);

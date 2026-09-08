/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_finger.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct GoodixFingerCycle {
    GoodixImageDecoder *decoder;
    GoodixFingerCycleConfig config;
    GoodixFingerCycleEmit emit;
    GoodixFingerImageSink image_sink;
    void *user_data;
    GoodixFingerThresholds thresholds;
    GoodixFingerState state;
    GoodixFingerAction pending_action;
    GoodixFingerResult result;
    GoodixFingerResult cleanup_result;
    uint64_t deadline;
    bool cleanup_pending;
    bool frame_acked;
    uint8_t captured_frames;
    uint8_t compared_pairs;
    uint8_t maximum_delta;
    uint8_t selected_frame;
    uint64_t delta_sum;
    uint64_t best_gradient;
    uint8_t best_pixels[GOODIX_IMAGE_PIXELS];
    uint8_t previous_pixels[GOODIX_IMAGE_PIXELS];
    uint8_t pixels[GOODIX_IMAGE_PIXELS];
};

static void
wipe(void *data, size_t length)
{
    volatile uint8_t *bytes = data;

    if (bytes == NULL)
        return;
    while (length-- != 0)
        *bytes++ = 0;
}

GoodixFingerResult
goodix_finger_parse_event(const uint8_t *data, size_t length,
                          GoodixFingerEvent *event)
{
    GoodixFingerEvent parsed = {0};

    if (data == NULL || event == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (length != GOODIX_FINGER_FDT_EVENT_BYTES)
        return GOODIX_FINGER_INVALID_LENGTH;

    parsed.irq_status = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    parsed.touch_flags = (uint16_t)data[2] | ((uint16_t)data[3] << 8);
    for (size_t i = 0; i < GOODIX_FINGER_ZONE_COUNT; i++) {
        size_t offset = GOODIX_FINGER_FDT_EVENT_HEADER_BYTES + i * 2U;
        parsed.zone[i] = (uint16_t)data[offset] | ((uint16_t)data[offset + 1] << 8);
    }
    *event = parsed;
    wipe(&parsed, sizeof(parsed));
    return GOODIX_FINGER_OK;
}

GoodixFingerResult
goodix_finger_thresholds_from_event(const GoodixFingerEvent *event,
                                    uint8_t margin,
                                    GoodixFingerThresholds *thresholds)
{
    GoodixFingerThresholds learned = {0};

    if (event == NULL || thresholds == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    for (size_t i = 0; i < GOODIX_FINGER_ZONE_COUNT; i++) {
        uint16_t value = (uint16_t)(event->zone[i] >> 1) + margin;
        if (value > UINT8_MAX)
            return GOODIX_FINGER_THRESHOLD_OUT_OF_RANGE;
        learned.zone[i] = (uint8_t)value;
    }
    learned.valid = true;
    *thresholds = learned;
    wipe(&learned, sizeof(learned));
    return GOODIX_FINGER_OK;
}

GoodixFingerResult
goodix_finger_build_fdt_payload(GoodixFingerFdtOperation operation,
                                const GoodixFingerThresholds *thresholds,
                                uint8_t *payload, size_t capacity)
{
    uint8_t built[GOODIX_FINGER_FDT_PAYLOAD_BYTES] = {0};

    if (payload == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (capacity < sizeof(built))
        return GOODIX_FINGER_BUFFER_TOO_SMALL;
    if (operation != GOODIX_FINGER_FDT_MODE &&
        operation != GOODIX_FINGER_FDT_DOWN &&
        operation != GOODIX_FINGER_FDT_UP)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (operation == GOODIX_FINGER_FDT_MODE && thresholds != NULL &&
        !thresholds->valid)
        return GOODIX_FINGER_THRESHOLDS_UNAVAILABLE;
    if (operation != GOODIX_FINGER_FDT_MODE &&
        (thresholds == NULL || !thresholds->valid))
        return GOODIX_FINGER_THRESHOLDS_UNAVAILABLE;

    built[0] = (uint8_t)operation;
    built[1] = 0x01;
    for (size_t i = 0; i < GOODIX_FINGER_ZONE_COUNT; i++) {
        built[2U + i * 2U] = 0x80;
        if (thresholds != NULL)
            built[3U + i * 2U] = thresholds->zone[i];
    }
    memcpy(payload, built, sizeof(built));
    wipe(built, sizeof(built));
    return GOODIX_FINGER_OK;
}

bool
goodix_finger_action_command(GoodixFingerAction action, uint8_t *command)
{
    uint8_t value;

    switch (action) {
    case GOODIX_FINGER_ACTION_PROBE:
        value = GOODIX_FINGER_COMMAND_FDT_MODE;
        break;
    case GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND:
    case GOODIX_FINGER_ACTION_CAPTURE:
    case GOODIX_FINGER_ACTION_REFRESH_BACKGROUND:
        value = GOODIX_FINGER_COMMAND_GET_IMAGE;
        break;
    case GOODIX_FINGER_ACTION_FDT_DOWN:
        value = GOODIX_FINGER_COMMAND_FDT_DOWN;
        break;
    case GOODIX_FINGER_ACTION_FDT_UP:
        value = GOODIX_FINGER_COMMAND_FDT_UP;
        break;
    case GOODIX_FINGER_ACTION_SLEEP:
        value = GOODIX_FINGER_COMMAND_SLEEP;
        break;
    case GOODIX_FINGER_ACTION_NONE:
        return false;
    default:
        return false;
    }
    if (command != NULL)
        *command = value;
    return true;
}

const char *
goodix_finger_result_string(GoodixFingerResult result)
{
    switch (result) {
    case GOODIX_FINGER_OK: return "ok";
    case GOODIX_FINGER_INVALID_ARGUMENT: return "invalid-argument";
    case GOODIX_FINGER_INVALID_LENGTH: return "invalid-length";
    case GOODIX_FINGER_INVALID_EVENT: return "invalid-event";
    case GOODIX_FINGER_THRESHOLD_OUT_OF_RANGE: return "threshold-out-of-range";
    case GOODIX_FINGER_THRESHOLDS_UNAVAILABLE: return "thresholds-unavailable";
    case GOODIX_FINGER_BUFFER_TOO_SMALL: return "buffer-too-small";
    case GOODIX_FINGER_NO_MEMORY: return "no-memory";
    case GOODIX_FINGER_BUSY: return "busy";
    case GOODIX_FINGER_STALE_ACTION: return "stale-action";
    case GOODIX_FINGER_TIMEOUT: return "timeout";
    case GOODIX_FINGER_CANCELLED: return "cancelled";
    case GOODIX_FINGER_IO_ERROR: return "io-error";
    case GOODIX_FINGER_DISCONNECTED: return "disconnected";
    case GOODIX_FINGER_IMAGE_ERROR: return "image-error";
    case GOODIX_FINGER_EMIT_FAILED: return "emit-failed";
    }
    return "unknown";
}

GoodixFingerCycleConfig
goodix_finger_cycle_config_default(void)
{
    return (GoodixFingerCycleConfig){
        .probe_timeout_ms = 1000,
        .background_timeout_ms = 5000,
        .finger_down_timeout_ms = 10000,
        .capture_timeout_ms = 5000,
        .finger_up_timeout_ms = 10000,
        .refresh_timeout_ms = 5000,
        .sleep_timeout_ms = 1000,
        .capture_frames = 1,
        .threshold_margin = 0,
    };
}

static bool
config_valid(const GoodixFingerCycleConfig *config)
{
    return config->probe_timeout_ms != 0 &&
        config->background_timeout_ms != 0 &&
        config->finger_down_timeout_ms != 0 &&
        config->capture_timeout_ms != 0 &&
        config->finger_up_timeout_ms != 0 &&
        config->refresh_timeout_ms != 0 &&
        config->sleep_timeout_ms != 0 && config->capture_frames != 0 &&
        config->capture_frames <= GOODIX_FINGER_MAX_CAPTURE_FRAMES;
}

static uint64_t
deadline_after(uint64_t now_ms, uint32_t timeout_ms)
{
    if (UINT64_MAX - now_ms < timeout_ms)
        return UINT64_MAX;
    return now_ms + timeout_ms;
}

static uint32_t
timeout_for(const GoodixFingerCycle *cycle, GoodixFingerAction action)
{
    switch (action) {
    case GOODIX_FINGER_ACTION_PROBE: return cycle->config.probe_timeout_ms;
    case GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND:
        return cycle->config.background_timeout_ms;
    case GOODIX_FINGER_ACTION_FDT_DOWN:
        return cycle->config.finger_down_timeout_ms;
    case GOODIX_FINGER_ACTION_CAPTURE: return cycle->config.capture_timeout_ms;
    case GOODIX_FINGER_ACTION_FDT_UP:
        return cycle->config.finger_up_timeout_ms;
    case GOODIX_FINGER_ACTION_REFRESH_BACKGROUND:
        return cycle->config.refresh_timeout_ms;
    case GOODIX_FINGER_ACTION_SLEEP: return cycle->config.sleep_timeout_ms;
    case GOODIX_FINGER_ACTION_NONE: return 0;
    default: return 0;
    }
}

static bool
is_image_action(GoodixFingerAction action)
{
    return action == GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND ||
        action == GOODIX_FINGER_ACTION_CAPTURE ||
        action == GOODIX_FINGER_ACTION_REFRESH_BACKGROUND;
}

static GoodixFingerResult
emit_action(GoodixFingerCycle *cycle, GoodixFingerAction action,
            uint64_t now_ms)
{
    uint8_t payload[GOODIX_FINGER_FDT_PAYLOAD_BYTES] = {0};
    uint8_t command;
    size_t payload_length = 0;
    GoodixFingerResult result;

    if (!goodix_finger_action_command(action, &command))
        return GOODIX_FINGER_INVALID_ARGUMENT;
    switch (action) {
    case GOODIX_FINGER_ACTION_PROBE:
        result = goodix_finger_build_fdt_payload(GOODIX_FINGER_FDT_MODE, NULL,
                                                 payload, sizeof(payload));
        payload_length = GOODIX_FINGER_FDT_PAYLOAD_BYTES;
        break;
    case GOODIX_FINGER_ACTION_FDT_DOWN:
        result = goodix_finger_build_fdt_payload(GOODIX_FINGER_FDT_DOWN,
                                                 &cycle->thresholds, payload,
                                                 sizeof(payload));
        payload_length = GOODIX_FINGER_FDT_PAYLOAD_BYTES;
        break;
    case GOODIX_FINGER_ACTION_FDT_UP:
        result = goodix_finger_build_fdt_payload(GOODIX_FINGER_FDT_UP,
                                                 &cycle->thresholds, payload,
                                                 sizeof(payload));
        payload_length = GOODIX_FINGER_FDT_PAYLOAD_BYTES;
        break;
    case GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND:
    case GOODIX_FINGER_ACTION_CAPTURE:
    case GOODIX_FINGER_ACTION_REFRESH_BACKGROUND:
    case GOODIX_FINGER_ACTION_SLEEP:
        payload[0] = 0x01;
        payload[1] = 0x00;
        payload_length = 2;
        result = GOODIX_FINGER_OK;
        break;
    case GOODIX_FINGER_ACTION_NONE:
        result = GOODIX_FINGER_INVALID_ARGUMENT;
        break;
    default:
        result = GOODIX_FINGER_INVALID_ARGUMENT;
        break;
    }
    if (result != GOODIX_FINGER_OK) {
        wipe(payload, sizeof(payload));
        return result;
    }
    if (!cycle->emit(cycle->user_data, action, command, payload, payload_length)) {
        wipe(payload, sizeof(payload));
        return GOODIX_FINGER_EMIT_FAILED;
    }
    wipe(payload, sizeof(payload));
    cycle->pending_action = action;
    cycle->deadline = deadline_after(now_ms, timeout_for(cycle, action));
    cycle->frame_acked = !is_image_action(action);
    return GOODIX_FINGER_OK;
}

static void
invalidate_transient(GoodixFingerCycle *cycle)
{
    goodix_image_clear_background(cycle->decoder);
    wipe(cycle->pixels, sizeof(cycle->pixels));
    wipe(cycle->best_pixels, sizeof(cycle->best_pixels));
    wipe(cycle->previous_pixels, sizeof(cycle->previous_pixels));
    cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
    cycle->deadline = 0;
    cycle->frame_acked = false;
}

static GoodixFingerResult
begin_cleanup(GoodixFingerCycle *cycle, GoodixFingerResult failure,
              uint64_t now_ms)
{
    GoodixFingerResult result;

    if (cycle->state == GOODIX_FINGER_STATE_CLEANUP)
        return failure;
    cycle->result = failure;
    cycle->cleanup_result = failure;
    cycle->cleanup_pending = true;
    invalidate_transient(cycle);
    cycle->state = GOODIX_FINGER_STATE_CLEANUP;
    result = emit_action(cycle, GOODIX_FINGER_ACTION_SLEEP, now_ms);
    if (result != GOODIX_FINGER_OK) {
        cycle->cleanup_pending = false;
        cycle->state = GOODIX_FINGER_STATE_FAILED;
        cycle->result = result;
        cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
        cycle->deadline = 0;
        return result;
    }
    return failure;
}

static GoodixFingerResult
schedule_next(GoodixFingerCycle *cycle, GoodixFingerAction completed,
              uint64_t now_ms)
{
    GoodixFingerAction next;

    switch (completed) {
    case GOODIX_FINGER_ACTION_PROBE:
        cycle->state = GOODIX_FINGER_STATE_WAIT_BACKGROUND;
        next = GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND;
        break;
    case GOODIX_FINGER_ACTION_CAPTURE_BACKGROUND:
        cycle->state = GOODIX_FINGER_STATE_WAIT_FINGER_DOWN;
        next = GOODIX_FINGER_ACTION_FDT_DOWN;
        break;
    case GOODIX_FINGER_ACTION_FDT_DOWN:
        cycle->state = GOODIX_FINGER_STATE_WAIT_CAPTURE;
        next = GOODIX_FINGER_ACTION_CAPTURE;
        break;
    case GOODIX_FINGER_ACTION_CAPTURE:
        cycle->state = GOODIX_FINGER_STATE_WAIT_FINGER_UP;
        next = GOODIX_FINGER_ACTION_FDT_UP;
        break;
    case GOODIX_FINGER_ACTION_FDT_UP:
        cycle->state = GOODIX_FINGER_STATE_WAIT_REFRESH_BACKGROUND;
        next = GOODIX_FINGER_ACTION_REFRESH_BACKGROUND;
        break;
    case GOODIX_FINGER_ACTION_REFRESH_BACKGROUND:
        cycle->state = GOODIX_FINGER_STATE_WAIT_SLEEP;
        next = GOODIX_FINGER_ACTION_SLEEP;
        break;
    case GOODIX_FINGER_ACTION_SLEEP:
    case GOODIX_FINGER_ACTION_NONE:
        return GOODIX_FINGER_INVALID_ARGUMENT;
    default:
        return GOODIX_FINGER_INVALID_ARGUMENT;
    }
    GoodixFingerResult result = emit_action(cycle, next, now_ms);
    if (result != GOODIX_FINGER_OK)
        return begin_cleanup(cycle, result, now_ms);
    return GOODIX_FINGER_OK;
}

GoodixFingerResult
goodix_finger_cycle_new(GoodixImageDecoder *decoder,
                        const GoodixFingerCycleConfig *config,
                        GoodixFingerCycleEmit emit,
                        GoodixFingerImageSink image_sink, void *user_data,
                        GoodixFingerCycle **cycle)
{
    GoodixFingerCycleConfig selected;
    GoodixFingerCycle *created;

    if (cycle == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    *cycle = NULL;
    if (decoder == NULL || emit == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    selected = config != NULL ? *config : goodix_finger_cycle_config_default();
    if (!config_valid(&selected))
        return GOODIX_FINGER_INVALID_ARGUMENT;
    created = calloc(1, sizeof(*created));
    if (created == NULL)
        return GOODIX_FINGER_NO_MEMORY;
    created->decoder = decoder;
    created->config = selected;
    created->emit = emit;
    created->image_sink = image_sink;
    created->user_data = user_data;
    created->state = GOODIX_FINGER_STATE_IDLE;
    created->result = GOODIX_FINGER_OK;
    *cycle = created;
    return GOODIX_FINGER_OK;
}

void
goodix_finger_cycle_free(GoodixFingerCycle *cycle)
{
    if (cycle == NULL)
        return;
    goodix_image_clear_background(cycle->decoder);
    wipe(cycle, sizeof(*cycle));
    free(cycle);
}

GoodixFingerResult
goodix_finger_cycle_reset(GoodixFingerCycle *cycle)
{
    if (cycle == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (cycle->state != GOODIX_FINGER_STATE_IDLE &&
        cycle->state != GOODIX_FINGER_STATE_COMPLETE &&
        cycle->state != GOODIX_FINGER_STATE_FAILED &&
        cycle->state != GOODIX_FINGER_STATE_CANCELLED &&
        cycle->state != GOODIX_FINGER_STATE_DISCONNECTED)
        return GOODIX_FINGER_BUSY;
    goodix_image_clear_background(cycle->decoder);
    wipe(cycle->pixels, sizeof(cycle->pixels));
    wipe(&cycle->thresholds, sizeof(cycle->thresholds));
    cycle->state = GOODIX_FINGER_STATE_IDLE;
    cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
    cycle->result = GOODIX_FINGER_OK;
    cycle->cleanup_result = GOODIX_FINGER_OK;
    cycle->deadline = 0;
    cycle->cleanup_pending = false;
    cycle->frame_acked = false;
    cycle->captured_frames = 0;
    cycle->compared_pairs = 0;
    cycle->maximum_delta = 0;
    cycle->delta_sum = 0;
    cycle->selected_frame = 0;
    cycle->best_gradient = 0;
    wipe(cycle->best_pixels, sizeof(cycle->best_pixels));
    wipe(cycle->previous_pixels, sizeof(cycle->previous_pixels));
    return GOODIX_FINGER_OK;
}

GoodixFingerResult
goodix_finger_cycle_start(GoodixFingerCycle *cycle, uint64_t now_ms)
{
    GoodixFingerResult result;

    if (cycle == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (cycle->state != GOODIX_FINGER_STATE_IDLE)
        return GOODIX_FINGER_BUSY;
    goodix_image_clear_background(cycle->decoder);
    wipe(cycle->pixels, sizeof(cycle->pixels));
    wipe(&cycle->thresholds, sizeof(cycle->thresholds));
    cycle->result = GOODIX_FINGER_OK;
    cycle->cleanup_result = GOODIX_FINGER_OK;
    cycle->cleanup_pending = false;
    cycle->captured_frames = 0;
    cycle->compared_pairs = 0;
    cycle->maximum_delta = 0;
    cycle->delta_sum = 0;
    cycle->selected_frame = 0;
    cycle->best_gradient = 0;
    wipe(cycle->best_pixels, sizeof(cycle->best_pixels));
    wipe(cycle->previous_pixels, sizeof(cycle->previous_pixels));
    cycle->state = GOODIX_FINGER_STATE_WAIT_PROBE;
    cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
    cycle->deadline = 0;
    result = emit_action(cycle, GOODIX_FINGER_ACTION_PROBE, now_ms);
    if (result != GOODIX_FINGER_OK)
        return begin_cleanup(cycle, result, now_ms);
    return GOODIX_FINGER_OK;
}

GoodixFingerResult
goodix_finger_cycle_command_complete(GoodixFingerCycle *cycle,
                                      uint64_t now_ms,
                                      GoodixFingerAction action, bool success,
                                      const uint8_t *reply, size_t reply_length)
{
    GoodixFingerResult result;

    if (cycle == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (cycle->pending_action != action)
        return GOODIX_FINGER_STALE_ACTION;
    if (!success) {
        if (action == GOODIX_FINGER_ACTION_SLEEP) {
            invalidate_transient(cycle);
            cycle->cleanup_pending = false;
            cycle->state = GOODIX_FINGER_STATE_FAILED;
            cycle->result = GOODIX_FINGER_IO_ERROR;
            return GOODIX_FINGER_IO_ERROR;
        }
        return begin_cleanup(cycle, GOODIX_FINGER_IO_ERROR, now_ms);
    }

    if (action == GOODIX_FINGER_ACTION_PROBE) {
        GoodixFingerEvent event;
        GoodixFingerThresholds learned;

        result = goodix_finger_parse_event(reply, reply_length, &event);
        if (result == GOODIX_FINGER_OK)
            result = goodix_finger_thresholds_from_event(
                &event, cycle->config.threshold_margin, &learned);
        wipe(&event, sizeof(event));
        if (result == GOODIX_FINGER_OK) {
            cycle->thresholds = learned;
            wipe(&learned, sizeof(learned));
        } else {
            wipe(&learned, sizeof(learned));
            cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
            cycle->deadline = 0;
            return begin_cleanup(cycle, result, now_ms);
        }
    } else if (action == GOODIX_FINGER_ACTION_FDT_DOWN ||
               action == GOODIX_FINGER_ACTION_FDT_UP) {
        /* A transport adapter may expose only the command acknowledgement.
         * When it exposes the FDT event, validate and immediately discard it. */
        if (reply_length != 0 && reply_length != GOODIX_FINGER_FDT_EVENT_BYTES) {
            cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
            cycle->deadline = 0;
            return begin_cleanup(cycle, GOODIX_FINGER_INVALID_LENGTH, now_ms);
        }
        if (reply_length != 0) {
            GoodixFingerEvent event;
            result = goodix_finger_parse_event(reply, reply_length, &event);
            wipe(&event, sizeof(event));
            if (result != GOODIX_FINGER_OK) {
                cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
                cycle->deadline = 0;
                return begin_cleanup(cycle, result, now_ms);
            }
        }
    } else if (is_image_action(action)) {
        cycle->frame_acked = true;
        return GOODIX_FINGER_OK;
    }

    cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
    cycle->deadline = 0;
    if (action == GOODIX_FINGER_ACTION_SLEEP) {
        if (cycle->cleanup_pending) {
            GoodixFingerResult cleanup_result = cycle->cleanup_result;
            cycle->cleanup_pending = false;
            cycle->state = cleanup_result == GOODIX_FINGER_CANCELLED ?
                GOODIX_FINGER_STATE_CANCELLED : GOODIX_FINGER_STATE_FAILED;
            cycle->result = cleanup_result;
            return cleanup_result;
        }
        cycle->state = GOODIX_FINGER_STATE_COMPLETE;
        cycle->result = GOODIX_FINGER_OK;
        return GOODIX_FINGER_OK;
    }
    return schedule_next(cycle, action, now_ms);
}

GoodixFingerResult
goodix_finger_cycle_frame_complete(GoodixFingerCycle *cycle,
                                    uint64_t now_ms,
                                    const GoodixImageFrame *frame,
                                    bool confirmed_finger_absent)
{
    GoodixFingerAction action;
    GoodixImageResult image_result;
    GoodixFingerResult result;

    if (cycle == NULL || frame == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    action = cycle->pending_action;
    if (!is_image_action(action) || !cycle->frame_acked)
        return GOODIX_FINGER_STALE_ACTION;

    if (action == GOODIX_FINGER_ACTION_CAPTURE) {
        image_result = goodix_image_decode(cycle->decoder, frame,
                                           cycle->pixels,
                                           sizeof(cycle->pixels));
        if (image_result != GOODIX_IMAGE_OK) {
            wipe(cycle->pixels, sizeof(cycle->pixels));
            cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
            cycle->deadline = 0;
            return begin_cleanup(cycle, GOODIX_FINGER_IMAGE_ERROR, now_ms);
        }
        uint64_t gradient = 0;

        for (size_t y = 0; y < GOODIX_FORMAT_HEIGHT; y++) {
            for (size_t x = 0; x < GOODIX_FORMAT_WIDTH; x++) {
                size_t i = y * GOODIX_FORMAT_WIDTH + x;
                if (x != 0) {
                    uint8_t left = cycle->pixels[i - 1];
                    gradient += cycle->pixels[i] > left ?
                        cycle->pixels[i] - left : left - cycle->pixels[i];
                }
                if (y != 0) {
                    uint8_t above = cycle->pixels[i - GOODIX_FORMAT_WIDTH];
                    gradient += cycle->pixels[i] > above ?
                        cycle->pixels[i] - above : above - cycle->pixels[i];
                }
            }
        }
        for (size_t i = 0; i < GOODIX_IMAGE_PIXELS; i++) {
            if (cycle->captured_frames != 0) {
                uint8_t previous = cycle->previous_pixels[i];
                uint8_t current = cycle->pixels[i];
                uint8_t delta = previous > current ?
                    (uint8_t)(previous - current) : (uint8_t)(current - previous);
                cycle->delta_sum += delta;
                if (delta > cycle->maximum_delta)
                    cycle->maximum_delta = delta;
            }
            cycle->previous_pixels[i] = cycle->pixels[i];
        }
        cycle->captured_frames++;
        if (cycle->selected_frame == 0 || gradient > cycle->best_gradient) {
            memcpy(cycle->best_pixels, cycle->pixels, sizeof(cycle->best_pixels));
            cycle->best_gradient = gradient;
            cycle->selected_frame = cycle->captured_frames;
        }
        if (cycle->captured_frames > 1)
            cycle->compared_pairs++;
        if (cycle->captured_frames < cycle->config.capture_frames) {
            wipe(cycle->pixels, sizeof(cycle->pixels));
            cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
            cycle->deadline = 0;
            cycle->frame_acked = false;
            cycle->state = GOODIX_FINGER_STATE_WAIT_CAPTURE;
            result = emit_action(cycle, GOODIX_FINGER_ACTION_CAPTURE, now_ms);
            if (result != GOODIX_FINGER_OK)
                return begin_cleanup(cycle, result, now_ms);
            return GOODIX_FINGER_OK;
        }
        memcpy(cycle->pixels, cycle->best_pixels, sizeof(cycle->pixels));
        if (cycle->image_sink != NULL &&
            !cycle->image_sink(cycle->user_data, cycle->pixels,
                               GOODIX_IMAGE_PIXELS)) {
            wipe(cycle->pixels, sizeof(cycle->pixels));
            cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
            cycle->deadline = 0;
            return begin_cleanup(cycle, GOODIX_FINGER_EMIT_FAILED, now_ms);
        }
        wipe(cycle->pixels, sizeof(cycle->pixels));
        wipe(cycle->best_pixels, sizeof(cycle->best_pixels));
        wipe(cycle->previous_pixels, sizeof(cycle->previous_pixels));
    } else {
        image_result = goodix_image_set_background(cycle->decoder, frame,
                                                   confirmed_finger_absent);
        if (image_result != GOODIX_IMAGE_OK) {
            cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
            cycle->deadline = 0;
            return begin_cleanup(cycle, GOODIX_FINGER_IMAGE_ERROR, now_ms);
        }
    }
    cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
    cycle->deadline = 0;
    cycle->frame_acked = false;
    return schedule_next(cycle, action, now_ms);
}

GoodixFingerResult
goodix_finger_cycle_frame_failed(GoodixFingerCycle *cycle, uint64_t now_ms)
{
    if (cycle == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (!is_image_action(cycle->pending_action) || !cycle->frame_acked)
        return GOODIX_FINGER_STALE_ACTION;
    cycle->pending_action = GOODIX_FINGER_ACTION_NONE;
    cycle->deadline = 0;
    cycle->frame_acked = false;
    return begin_cleanup(cycle, GOODIX_FINGER_IMAGE_ERROR, now_ms);
}

GoodixFingerResult
goodix_finger_cycle_disconnect(GoodixFingerCycle *cycle)
{
    if (cycle == NULL)
        return GOODIX_FINGER_INVALID_ARGUMENT;
    if (cycle->state == GOODIX_FINGER_STATE_COMPLETE ||
        cycle->state == GOODIX_FINGER_STATE_FAILED ||
        cycle->state == GOODIX_FINGER_STATE_CANCELLED ||
        cycle->state == GOODIX_FINGER_STATE_DISCONNECTED)
        return cycle->result;
    invalidate_transient(cycle);
    cycle->cleanup_pending = false;
    cycle->state = GOODIX_FINGER_STATE_DISCONNECTED;
    cycle->result = GOODIX_FINGER_DISCONNECTED;
    return GOODIX_FINGER_DISCONNECTED;
}

GoodixFingerState
goodix_finger_cycle_state(const GoodixFingerCycle *cycle)
{
    return cycle != NULL ? cycle->state : GOODIX_FINGER_STATE_DISCONNECTED;
}

GoodixFingerAction
goodix_finger_cycle_action(const GoodixFingerCycle *cycle)
{
    return cycle != NULL ? cycle->pending_action : GOODIX_FINGER_ACTION_NONE;
}

bool
goodix_finger_cycle_get_stability(const GoodixFingerCycle *cycle,
                                  GoodixFingerStability *stability)
{
    uint64_t divisor;

    if (cycle == NULL || stability == NULL || cycle->captured_frames == 0)
        return false;
    divisor = (uint64_t)cycle->compared_pairs * GOODIX_IMAGE_PIXELS;
    *stability = (GoodixFingerStability){
        .frames = cycle->captured_frames,
        .compared_pairs = cycle->compared_pairs,
        .mean_absolute_delta_milli = divisor != 0 ?
            (uint32_t)(cycle->delta_sum * 1000U / divisor) : 0,
        .maximum_absolute_delta = cycle->maximum_delta,
        .selected_frame = cycle->selected_frame,
        .selected_gradient_milli = (uint32_t)(cycle->best_gradient * 1000U /
            ((GOODIX_FORMAT_WIDTH - 1U) * GOODIX_FORMAT_HEIGHT +
             (GOODIX_FORMAT_HEIGHT - 1U) * GOODIX_FORMAT_WIDTH)),
    };
    return true;
}

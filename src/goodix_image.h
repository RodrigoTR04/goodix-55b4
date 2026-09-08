/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include "goodix_format.h"
#include <stddef.h>
#include <stdint.h>

#define GOODIX_IMAGE_PIXELS (GOODIX_FORMAT_WIDTH * GOODIX_FORMAT_HEIGHT)
#define GOODIX_IMAGE_MAX_SAMPLE 4095

typedef enum {
    GOODIX_IMAGE_FORMAT_55B4_108X88_12 = 1,
} GoodixImageFormat;

typedef enum {
    GOODIX_IMAGE_OK,
    GOODIX_IMAGE_INVALID_ARGUMENT,
    GOODIX_IMAGE_UNSUPPORTED_FORMAT,
    GOODIX_IMAGE_INVALID_LENGTH,
    GOODIX_IMAGE_BUFFER_TOO_SMALL,
    GOODIX_IMAGE_STALE_FRAME,
    GOODIX_IMAGE_NO_BACKGROUND,
    GOODIX_IMAGE_FINGER_STATE_UNKNOWN,
    GOODIX_IMAGE_FLAT,
    GOODIX_IMAGE_NO_MEMORY,
} GoodixImageResult;

/* Borrowed, complete authenticated plaintext, including its opaque trailer.
 * The caller supplies a nonzero generation unique to the current activation
 * and calibration/configuration. Authentication is a caller precondition:
 * the decoder cannot establish authenticity or finger absence from bytes. */
typedef struct {
    GoodixImageFormat format;
    uint64_t generation;
    const uint8_t *data;
    size_t length;
} GoodixImageFrame;

typedef struct GoodixImageDecoder GoodixImageDecoder;

/* Produces 9504 native-endian uint16_t samples in serialized row-major order.
 * capacity is in samples. Output is unchanged on failure. Input and output
 * must not overlap for unpacking. Caller owns and must wipe output samples. */
GoodixImageResult goodix_image_unpack(const GoodixImageFrame *frame,
    uint16_t *samples, size_t capacity);

GoodixImageResult goodix_image_decoder_new(GoodixImageFormat format,
    uint64_t generation, GoodixImageDecoder **decoder);
void goodix_image_decoder_free(GoodixImageDecoder *decoder);

/* Wipe/invalidate the reference. Dispose of the entire context on activation,
 * configuration, reset, power or disconnect changes, and use a new generation.
 * A failed background replacement also invalidates any previous reference. */
void goodix_image_clear_background(GoodixImageDecoder *decoder);
GoodixImageResult goodix_image_set_background(GoodixImageDecoder *decoder,
    const GoodixImageFrame *frame, bool confirmed_finger_absent);

/* Produces exactly 9504 grayscale bytes (108x88, stride 108), suitable for
 * copying into an FpImage. Uses absolute background difference and full-range
 * linear normalization. Flat differences return GOODIX_IMAGE_FLAT. No physical
 * quality threshold is inferred. Output, including its tail, is unchanged on
 * failure; on success only its first 9504 bytes are written. */
GoodixImageResult goodix_image_decode(GoodixImageDecoder *decoder,
    const GoodixImageFrame *frame, uint8_t *pixels, size_t capacity);

/* Wipe caller-owned image/packed buffers before releasing or reusing them. */
void goodix_image_clear(void *data, size_t length);

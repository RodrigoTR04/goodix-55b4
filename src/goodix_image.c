/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_image.h"
#include <stdlib.h>
#include <string.h>

struct GoodixImageDecoder {
    GoodixImageFormat format;
    uint64_t generation;
    bool background_valid;
    uint16_t background[GOODIX_IMAGE_PIXELS];
};

void
goodix_image_clear(void *data, size_t length)
{
    volatile uint8_t *bytes = data;
    if (bytes == NULL)
        return;
    while (length-- != 0)
        *bytes++ = 0;
}

static GoodixImageResult
validate_frame(const GoodixImageFrame *frame)
{
    if (frame == NULL || frame->data == NULL || frame->generation == 0)
        return GOODIX_IMAGE_INVALID_ARGUMENT;
    if (frame->format != GOODIX_IMAGE_FORMAT_55B4_108X88_12)
        return GOODIX_IMAGE_UNSUPPORTED_FORMAT;
    if (frame->length != GOODIX_FORMAT_PLAINTEXT_BYTES)
        return GOODIX_IMAGE_INVALID_LENGTH;
    return GOODIX_IMAGE_OK;
}

static GoodixImageResult
validate_generation(const GoodixImageDecoder *decoder, const GoodixImageFrame *frame)
{
    GoodixImageResult result = validate_frame(frame);
    if (result != GOODIX_IMAGE_OK)
        return result;
    if (frame->format != decoder->format)
        return GOODIX_IMAGE_UNSUPPORTED_FORMAT;
    if (frame->generation != decoder->generation)
        return GOODIX_IMAGE_STALE_FRAME;
    return GOODIX_IMAGE_OK;
}

/* Public 55x4 bit placement. The output is consecutive serialized samples,
 * with no transpose or mirror. */
static void
unpack_group(const uint8_t *b, uint16_t *p)
{
    p[0] = (uint16_t)(((uint16_t)(b[0] & 15) << 8) | b[1]);
    p[1] = (uint16_t)(((uint16_t)b[3] << 4) | (b[0] >> 4));
    p[2] = (uint16_t)(((uint16_t)(b[5] & 15) << 8) | b[2]);
    p[3] = (uint16_t)(((uint16_t)b[4] << 4) | (b[5] >> 4));
}

GoodixImageResult
goodix_image_unpack(const GoodixImageFrame *frame, uint16_t *samples, size_t capacity)
{
    GoodixImageResult result = validate_frame(frame);
    if (result != GOODIX_IMAGE_OK)
        return result;
    if (samples == NULL)
        return GOODIX_IMAGE_INVALID_ARGUMENT;
    if (capacity < GOODIX_IMAGE_PIXELS)
        return GOODIX_IMAGE_BUFFER_TOO_SMALL;
    for (size_t i = 0; i < GOODIX_IMAGE_PIXELS; i += 4)
        unpack_group(frame->data + i / 4 * 6, samples + i);
    return GOODIX_IMAGE_OK;
}

GoodixImageResult
goodix_image_decoder_new(GoodixImageFormat format, uint64_t generation,
                          GoodixImageDecoder **decoder)
{
    if (decoder == NULL)
        return GOODIX_IMAGE_INVALID_ARGUMENT;
    *decoder = NULL;
    if (generation == 0)
        return GOODIX_IMAGE_INVALID_ARGUMENT;
    if (format != GOODIX_IMAGE_FORMAT_55B4_108X88_12)
        return GOODIX_IMAGE_UNSUPPORTED_FORMAT;
    GoodixImageDecoder *created = calloc(1, sizeof(*created));
    if (created == NULL)
        return GOODIX_IMAGE_NO_MEMORY;
    created->format = format;
    created->generation = generation;
    *decoder = created;
    return GOODIX_IMAGE_OK;
}

void
goodix_image_clear_background(GoodixImageDecoder *decoder)
{
    if (decoder == NULL)
        return;
    goodix_image_clear(decoder->background, sizeof(decoder->background));
    decoder->background_valid = false;
}

void
goodix_image_decoder_free(GoodixImageDecoder *decoder)
{
    if (decoder == NULL)
        return;
    goodix_image_clear(decoder, sizeof(*decoder));
    free(decoder);
}

GoodixImageResult
goodix_image_set_background(GoodixImageDecoder *decoder,
                             const GoodixImageFrame *frame, bool confirmed_finger_absent)
{
    if (decoder == NULL)
        return GOODIX_IMAGE_INVALID_ARGUMENT;
    goodix_image_clear_background(decoder);
    GoodixImageResult result = validate_generation(decoder, frame);
    if (result != GOODIX_IMAGE_OK)
        return result;
    if (!confirmed_finger_absent)
        return GOODIX_IMAGE_FINGER_STATE_UNKNOWN;
    result = goodix_image_unpack(frame, decoder->background, GOODIX_IMAGE_PIXELS);
    decoder->background_valid = result == GOODIX_IMAGE_OK;
    return result;
}

GoodixImageResult
goodix_image_decode(GoodixImageDecoder *decoder, const GoodixImageFrame *frame,
                     uint8_t *pixels, size_t capacity)
{
    if (decoder == NULL || pixels == NULL)
        return GOODIX_IMAGE_INVALID_ARGUMENT;
    GoodixImageResult result = validate_generation(decoder, frame);
    if (result != GOODIX_IMAGE_OK)
        return result;
    if (capacity < GOODIX_IMAGE_PIXELS)
        return GOODIX_IMAGE_BUFFER_TOO_SMALL;
    if (!decoder->background_valid)
        return GOODIX_IMAGE_NO_BACKGROUND;

    /* Stage the entire difference plane so validation/flat rejection cannot
     * partially overwrite caller output. No full foreground copy is needed. */
    size_t scratch_size = GOODIX_IMAGE_PIXELS * sizeof(uint16_t);
    uint16_t *difference = malloc(scratch_size);
    if (difference == NULL)
        return GOODIX_IMAGE_NO_MEMORY;
    uint16_t group[4] = {0};
    uint16_t minimum = GOODIX_IMAGE_MAX_SAMPLE, maximum = 0;
    for (size_t i = 0; i < GOODIX_IMAGE_PIXELS; i += 4) {
        unpack_group(frame->data + i / 4 * 6, group);
        for (size_t j = 0; j < 4; j++) {
            uint16_t bg = decoder->background[i + j];
            uint16_t value = group[j] > bg ? group[j] - bg : bg - group[j];
            difference[i + j] = value;
            if (value < minimum) minimum = value;
            if (value > maximum) maximum = value;
        }
    }
    goodix_image_clear(group, sizeof(group));
    if (minimum == maximum) {
        result = GOODIX_IMAGE_FLAT;
    } else {
        uint32_t range = (uint32_t)maximum - minimum;
        for (size_t i = 0; i < GOODIX_IMAGE_PIXELS; i++)
            pixels[i] = (uint8_t)(((uint32_t)difference[i] - minimum) * 255U / range);
        result = GOODIX_IMAGE_OK;
    }
    goodix_image_clear(difference, scratch_size);
    free(difference);
    return result;
}

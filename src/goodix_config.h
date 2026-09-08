/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define GOODIX_CONFIG_SIZE 256

typedef enum {
    GOODIX_CONFIG_OK = 0,
    GOODIX_CONFIG_INVALID_ARGUMENT,
    GOODIX_CONFIG_BUFFER_TOO_SMALL,
    GOODIX_CONFIG_INVALID_LENGTH,
    GOODIX_CONFIG_INVALID_CHECKSUM,
    GOODIX_CONFIG_INVALID_STRUCTURE,
    GOODIX_CONFIG_MISSING_TAG,
    GOODIX_CONFIG_DUPLICATE_TAG,
    GOODIX_CONFIG_INVALID_CALIBRATION,
} GoodixConfigResult;

typedef struct {
    /* TCODE must be a nonzero multiple of 16. */
    uint16_t tcode;
    /* DELTA_DOWN is stored in the high byte of tag 0x0082. */
    uint16_t delta_down;
    /* The decoded two-bit sensor value plus 8, therefore 8 through 11. */
    uint16_t fdt_offset;
} GoodixConfigCalibration;

/*
 * Builds one configuration from a checked base. Output remains unchanged on
 * failure. The base and output buffers may refer to the same storage.
 */
GoodixConfigResult goodix_config_build(
    const uint8_t *base,
    size_t base_length,
    const GoodixConfigCalibration *calibration,
    uint8_t *output,
    size_t output_capacity);

/* Uses the attributed public 55x4 base selected for the target profile. */
GoodixConfigResult goodix_config_build_55b4(
    const GoodixConfigCalibration *calibration,
    uint8_t *output,
    size_t output_capacity);

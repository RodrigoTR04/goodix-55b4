/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "goodix_config.h"

#include <stddef.h>
#include <stdint.h>

#define GOODIX_GF3208_OTP_SIZE 32

typedef enum {
    GOODIX_CALIBRATION_OK = 0,
    GOODIX_CALIBRATION_INVALID_ARGUMENT,
    GOODIX_CALIBRATION_INVALID_LENGTH,
    GOODIX_CALIBRATION_INVALID_TCODE,
    GOODIX_CALIBRATION_INVALID_FDT_OFFSET,
    GOODIX_CALIBRATION_OUT_OF_RANGE,
} GoodixCalibrationResult;

/*
 * Decode only the three runtime values consumed by the checked 55b4
 * configuration builder. The caller retains ownership of the raw OTP and
 * should erase it as soon as the configuration has been built.
 */
GoodixCalibrationResult goodix_calibration_decode_gf3208(
    const uint8_t *otp,
    size_t otp_length,
    GoodixConfigCalibration *calibration);

const char *goodix_calibration_result_string(GoodixCalibrationResult result);

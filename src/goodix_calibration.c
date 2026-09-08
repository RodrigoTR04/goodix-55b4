/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_calibration.h"

#include <limits.h>

#define GF3208_FDT_OFFSET_INDEX 17
#define GF3208_TCODE_INDEX 22
#define GF3208_TCODE_COMPLEMENT_INDEX 23

GoodixCalibrationResult
goodix_calibration_decode_gf3208(const uint8_t *otp,
                                size_t otp_length,
                                GoodixConfigCalibration *calibration)
{
    GoodixConfigCalibration candidate;
    uint8_t encoded;
    uint8_t fdt_encoded;
    uint8_t low;
    uint8_t middle_complement;
    uint8_t high;

    if (otp == NULL || calibration == NULL)
        return GOODIX_CALIBRATION_INVALID_ARGUMENT;
    if (otp_length != GOODIX_GF3208_OTP_SIZE)
        return GOODIX_CALIBRATION_INVALID_LENGTH;

    encoded = otp[GF3208_TCODE_INDEX];
    if (encoded == 0 ||
        (uint8_t)~encoded != otp[GF3208_TCODE_COMPLEMENT_INDEX])
        return GOODIX_CALIBRATION_INVALID_TCODE;

    candidate.tcode = (uint16_t)(((encoded >> 4) + 1U) * 16U);
    candidate.delta_down = (uint16_t)((
        ((((uint32_t)(encoded & 0x0fU) + 2U) * 100U * 256U) /
          candidate.tcode) /
         3U) >>
        4U);

    fdt_encoded = otp[GF3208_FDT_OFFSET_INDEX];
    low = fdt_encoded & 0x03U;
    middle_complement = ((uint8_t)~fdt_encoded >> 2) & 0x03U;
    high = (fdt_encoded >> 4) & 0x03U;
    if (low == high || low == middle_complement)
        candidate.fdt_offset = (uint16_t)(low + 8U);
    else if (high == middle_complement)
        candidate.fdt_offset = (uint16_t)(high + 8U);
    else
        return GOODIX_CALIBRATION_INVALID_FDT_OFFSET;

    if (candidate.tcode == 0 || candidate.tcode % 16U != 0 ||
        candidate.delta_down > UINT8_MAX || candidate.fdt_offset < 8U ||
        candidate.fdt_offset > 11U)
        return GOODIX_CALIBRATION_OUT_OF_RANGE;

    *calibration = candidate;
    return GOODIX_CALIBRATION_OK;
}

const char *
goodix_calibration_result_string(GoodixCalibrationResult result)
{
    switch (result) {
    case GOODIX_CALIBRATION_OK:
        return "calibration decoded";
    case GOODIX_CALIBRATION_INVALID_ARGUMENT:
        return "invalid argument";
    case GOODIX_CALIBRATION_INVALID_LENGTH:
        return "invalid GF3208 OTP length";
    case GOODIX_CALIBRATION_INVALID_TCODE:
        return "invalid GF3208 TCODE redundancy";
    case GOODIX_CALIBRATION_INVALID_FDT_OFFSET:
        return "invalid GF3208 FDT-offset redundancy";
    case GOODIX_CALIBRATION_OUT_OF_RANGE:
        return "decoded calibration is out of range";
    }
    return "unknown calibration error";
}

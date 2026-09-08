/* SPDX-License-Identifier: LGPL-2.1-or-later AND MIT */

#include "goodix_config.h"

#include <stdbool.h>
#include <string.h>

#define GOODIX_CONFIG_SECTION_COUNT 8
#define GOODIX_CONFIG_SECTION_TABLE_OFFSET 1
#define GOODIX_CONFIG_SECTION_TABLE_END 17
#define GOODIX_CONFIG_CHECKSUM_OFFSET 254
#define GOODIX_CONFIG_CHECKSUM_SEED 0xa5a5U
#define GOODIX_CONFIG_TAG_TCODE 0x005cU
#define GOODIX_CONFIG_TAG_FDT_OFFSET 0x0056U
#define GOODIX_CONFIG_TAG_DELTA_DOWN 0x0082U

/*
 * This configuration comes from goodix-fp-dump driver_55x4.py at commit
 * cc43bb3b3154a0bccc0412ae024013c7e1923139.
 * Copyright (c) 2022 Goodix Fingerprint Linux Development.
 * Distributed under the MIT license in LICENSES/MIT-goodix-fp-dump.txt.
 */
static const uint8_t goodix_55b4_base[GOODIX_CONFIG_SIZE] = {
    0x60, 0x11, 0x60, 0x71, 0x24, 0x95, 0x2c, 0xc1, 0x14, 0xd5, 0x10, 0xe5,
    0x00, 0xe5, 0x14, 0xf9, 0x03, 0x04, 0x02, 0x00, 0x00, 0x08, 0x00, 0x11,
    0x11, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x07, 0x00, 0x84, 0x00, 0xc0,
    0xb3, 0x86, 0x00, 0xbb, 0xc4, 0x88, 0x00, 0xba, 0xba, 0x8a, 0x00, 0xb2,
    0xb2, 0x8c, 0x00, 0xaa, 0xaa, 0x8e, 0x00, 0xc1, 0xc1, 0x90, 0x00, 0xbb,
    0xbb, 0x92, 0x00, 0xb1, 0xb1, 0x94, 0x00, 0x00, 0xa8, 0x96, 0x00, 0x00,
    0xb6, 0x98, 0x00, 0x00, 0xbf, 0x9a, 0x00, 0x00, 0xba, 0x50, 0x00, 0x01,
    0x05, 0xd0, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78,
    0x56, 0x74, 0x00, 0x34, 0x12, 0x26, 0x00, 0x00, 0x12, 0x20, 0x00, 0x10,
    0x40, 0x12, 0x00, 0x03, 0x04, 0x2a, 0x01, 0x02, 0x00, 0x22, 0x00, 0x01,
    0x20, 0x24, 0x00, 0x32, 0x00, 0x80, 0x00, 0x01, 0x00, 0x5c, 0x00, 0x80,
    0x00, 0x56, 0x00, 0x08, 0x20, 0x58, 0x00, 0x01, 0x00, 0x32, 0x00, 0x2c,
    0x02, 0x82, 0x00, 0x80, 0x0c, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x07,
    0x00, 0x2a, 0x01, 0x82, 0x03, 0x20, 0x00, 0x10, 0x40, 0x22, 0x00, 0x01,
    0x20, 0x24, 0x00, 0x14, 0x00, 0x80, 0x00, 0x05, 0x00, 0x5c, 0x00, 0x00,
    0x01, 0x56, 0x00, 0x08, 0x20, 0x58, 0x00, 0x03, 0x00, 0x82, 0x00, 0x80,
    0x14, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x80, 0x00, 0x62, 0x00, 0x09,
    0x03, 0x64, 0x00, 0x18, 0x00, 0x22, 0x00, 0x00, 0x20, 0x2a, 0x01, 0x08,
    0x00, 0x5c, 0x00, 0x00, 0x01, 0x52, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x9a, 0x69,
};

static uint16_t
read_le16(const uint8_t *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static void
write_le16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value & 0xffU);
    data[1] = (uint8_t)(value >> 8);
}

static uint16_t
config_checksum(const uint8_t config[GOODIX_CONFIG_SIZE])
{
    uint16_t sum = GOODIX_CONFIG_CHECKSUM_SEED;

    for (size_t offset = 0; offset < GOODIX_CONFIG_CHECKSUM_OFFSET;
         offset += 2)
        sum = (uint16_t)(sum + read_le16(config + offset));

    return (uint16_t)(0U - sum);
}

static GoodixConfigResult
validate_sections(const uint8_t config[GOODIX_CONFIG_SIZE])
{
    size_t previous_end = GOODIX_CONFIG_SECTION_TABLE_END;

    for (size_t section = 0; section < GOODIX_CONFIG_SECTION_COUNT; section++) {
        size_t table_offset = GOODIX_CONFIG_SECTION_TABLE_OFFSET + section * 2;
        size_t base = config[table_offset];
        size_t size = config[table_offset + 1];

        if (base < GOODIX_CONFIG_SECTION_TABLE_END ||
            base > GOODIX_CONFIG_CHECKSUM_OFFSET ||
            size > GOODIX_CONFIG_CHECKSUM_OFFSET - base)
            return GOODIX_CONFIG_INVALID_STRUCTURE;
        if (size != 0 && base < previous_end)
            return GOODIX_CONFIG_INVALID_STRUCTURE;
        if (size != 0)
            previous_end = base + size;
    }

    return GOODIX_CONFIG_OK;
}

static GoodixConfigResult
find_value(uint8_t config[GOODIX_CONFIG_SIZE],
           size_t section,
           uint16_t tag,
           uint8_t **value)
{
    size_t table_offset = GOODIX_CONFIG_SECTION_TABLE_OFFSET + section * 2;
    size_t base = config[table_offset];
    size_t size = config[table_offset + 1];
    size_t matches = 0;

    if (section >= GOODIX_CONFIG_SECTION_COUNT || size % 4 != 0)
        return GOODIX_CONFIG_INVALID_STRUCTURE;

    for (size_t offset = base; offset < base + size; offset += 4) {
        if (read_le16(config + offset) == tag) {
            *value = config + offset + 2;
            matches++;
        }
    }

    if (matches == 0)
        return GOODIX_CONFIG_MISSING_TAG;
    if (matches != 1)
        return GOODIX_CONFIG_DUPLICATE_TAG;
    return GOODIX_CONFIG_OK;
}

GoodixConfigResult
goodix_config_build(const uint8_t *base,
                    size_t base_length,
                    const GoodixConfigCalibration *calibration,
                    uint8_t *output,
                    size_t output_capacity)
{
    uint8_t candidate[GOODIX_CONFIG_SIZE];
    uint8_t *delta_value = NULL;
    uint8_t *tcode_value = NULL;
    uint8_t *offset_value = NULL;
    GoodixConfigResult result;

    if (base == NULL || calibration == NULL || output == NULL)
        return GOODIX_CONFIG_INVALID_ARGUMENT;
    if (base_length != GOODIX_CONFIG_SIZE)
        return GOODIX_CONFIG_INVALID_LENGTH;
    if (output_capacity < GOODIX_CONFIG_SIZE)
        return GOODIX_CONFIG_BUFFER_TOO_SMALL;
    if (read_le16(base + GOODIX_CONFIG_CHECKSUM_OFFSET) !=
        config_checksum(base))
        return GOODIX_CONFIG_INVALID_CHECKSUM;
    if (calibration->tcode == 0 || calibration->tcode % 16 != 0 ||
        calibration->delta_down > UINT8_MAX ||
        calibration->fdt_offset < 8 || calibration->fdt_offset > 11)
        return GOODIX_CONFIG_INVALID_CALIBRATION;

    memcpy(candidate, base, sizeof(candidate));
    result = validate_sections(candidate);
    if (result != GOODIX_CONFIG_OK)
        return result;

    result = find_value(candidate, 2, GOODIX_CONFIG_TAG_DELTA_DOWN,
                        &delta_value);
    if (result != GOODIX_CONFIG_OK)
        return result;
    result = find_value(candidate, 4, GOODIX_CONFIG_TAG_TCODE, &tcode_value);
    if (result != GOODIX_CONFIG_OK)
        return result;
    result = find_value(candidate, 2, GOODIX_CONFIG_TAG_FDT_OFFSET,
                        &offset_value);
    if (result != GOODIX_CONFIG_OK)
        return result;

    write_le16(delta_value,
               (uint16_t)(calibration->delta_down << 8) | 0x0080U);
    write_le16(tcode_value, calibration->tcode);
    offset_value[0] = (uint8_t)calibration->fdt_offset;
    write_le16(candidate + GOODIX_CONFIG_CHECKSUM_OFFSET,
               config_checksum(candidate));
    memcpy(output, candidate, sizeof(candidate));
    return GOODIX_CONFIG_OK;
}

GoodixConfigResult
goodix_config_build_55b4(const GoodixConfigCalibration *calibration,
                         uint8_t *output,
                         size_t output_capacity)
{
    return goodix_config_build(goodix_55b4_base,
                               sizeof(goodix_55b4_base),
                               calibration,
                               output,
                               output_capacity);
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once
#include <stdbool.h>

/* Serialized raster from both public 55x4 implementations. These constants
 * describe the packed payload, not a decoded FpImage or screen orientation. */
#define GOODIX_FORMAT_WIDTH 108
#define GOODIX_FORMAT_HEIGHT 88
#define GOODIX_FORMAT_ROW_BYTES 162
#define GOODIX_FORMAT_PACKED_BYTES 14256
#define GOODIX_FORMAT_TRAILER_BYTES 4
#define GOODIX_FORMAT_PLAINTEXT_BYTES 14260

typedef struct {
    bool length_matches;
} GoodixFormatMetadata;

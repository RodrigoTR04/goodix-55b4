/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "goodix_image.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SIGFM (SIFT Is Good For Matching) is used here on the sensor's native
 * raster.  Keeping the matcher at 108 x 88 avoids inventing detail by
 * upscaling the image before feature extraction. */
#define GOODIX_SIGFM_WIDTH GOODIX_FORMAT_WIDTH
#define GOODIX_SIGFM_HEIGHT GOODIX_FORMAT_HEIGHT
#define GOODIX_SIGFM_PIXELS GOODIX_IMAGE_PIXELS
#define GOODIX_SIGFM_MAX_KEYPOINTS 256U
#define GOODIX_SIGFM_MAX_TEMPLATES 10U
#define GOODIX_SIGFM_MIN_MATCHES 12U
#define GOODIX_SIGFM_SCORE_THRESHOLD 72
#define GOODIX_SIGFM_DESCRIPTOR_LENGTH 128U
#define GOODIX_SIGFM_SERIALIZED_HEADER_BYTES 19U
#define GOODIX_SIGFM_MAX_BLOB_BYTES                                      \
    (GOODIX_SIGFM_SERIALIZED_HEADER_BYTES +                              \
     GOODIX_SIGFM_MAX_KEYPOINTS * 2U * sizeof(uint32_t) +                \
     GOODIX_SIGFM_MAX_KEYPOINTS * GOODIX_SIGFM_DESCRIPTOR_LENGTH *       \
         sizeof(float))

typedef enum {
    GOODIX_SIGFM_OK,
    GOODIX_SIGFM_INVALID_ARGUMENT,
    GOODIX_SIGFM_INVALID_LENGTH,
    GOODIX_SIGFM_NO_FEATURES,
    GOODIX_SIGFM_INVALID_TEMPLATE,
    GOODIX_SIGFM_NO_MEMORY,
    GOODIX_SIGFM_INTERNAL,
} GoodixSigfmResult;

typedef struct GoodixSigfmFeatures GoodixSigfmFeatures;

/* Extract SIFT keypoints and descriptors from one native 8-bit frame. Frames
 * with fewer than GOODIX_SIGFM_MIN_MATCHES reliable keypoints are reported as
 * GOODIX_SIGFM_NO_FEATURES so they cannot become enrollment templates. */
GoodixSigfmResult goodix_sigfm_extract(const uint8_t *pixels,
                                       size_t pixel_count,
                                       GoodixSigfmFeatures **features);

/* Feature objects contain biometric template data and must be destroyed with
 * this function.  It wipes owned descriptor/keypoint memory before release. */
void goodix_sigfm_features_free(GoodixSigfmFeatures *features);

size_t goodix_sigfm_keypoint_count(const GoodixSigfmFeatures *features);

/* Serialize only matcher features, never the source raster.  The format is a
 * versioned, little-endian representation with bounded dimensions and counts.
 * The returned buffer belongs to the caller and must be wiped with
 * goodix_sigfm_free_buffer().  Output pointers must be initialized to NULL;
 * the functions reject a non-NULL output to avoid overwriting owned data. */
GoodixSigfmResult goodix_sigfm_serialize(const GoodixSigfmFeatures *features,
                                         uint8_t **blob, size_t *blob_length);
GoodixSigfmResult goodix_sigfm_deserialize(const uint8_t *blob,
                                           size_t blob_length,
                                           GoodixSigfmFeatures **features);
void goodix_sigfm_free_buffer(uint8_t *blob, size_t blob_length);

/* Return the SIGFM relation score.  A score of zero is a valid rejection and
 * is returned for too few reliable descriptor matches. */
GoodixSigfmResult goodix_sigfm_score(const GoodixSigfmFeatures *probe,
                                     const GoodixSigfmFeatures *enrolled,
                                     int32_t *score);
bool goodix_sigfm_accepts(int32_t score);
const char *goodix_sigfm_result_string(GoodixSigfmResult result);

#ifdef __cplusplus
}
#endif

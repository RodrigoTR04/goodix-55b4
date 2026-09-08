/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Native-frame SIGFM matcher for Goodix 27c6:55b4.
 *
 * The relation test follows the public SIGFM design: SIFT descriptors find
 * candidate correspondences, pairwise distances reject inconsistent matches,
 * and a circular rotation test counts mutually consistent relations.  The
 * implementation is deliberately independent of the reference project's
 * serialization and fixes the y-only correspondence ordering and angle edge
 * cases documented by the Goodix 55x4 investigations.
 */

#include "goodix_sigfm.h"

#include <opencv2/core.hpp>
#include <opencv2/features2d.hpp>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <set>
#include <utility>
#include <vector>

struct GoodixSigfmFeatures {
    std::vector<cv::KeyPoint> keypoints;
    cv::Mat descriptors;
};

namespace {

// Version includes the matcher policy, not just the byte layout. Bump on
// extraction/scoring parameter changes; old enrollments must be replaced.
constexpr uint8_t kVersion = 2;
constexpr uint8_t kDescriptorTypeFloat32 = 1;
constexpr size_t kHeaderBytes = GOODIX_SIGFM_SERIALIZED_HEADER_BYTES;
constexpr float kMaximumDescriptorValue = 512.0F;
constexpr float kLoweRatio = 0.75F;
constexpr double kLengthTolerance = 0.05;
constexpr double kAngleTolerance = 0.10;
constexpr double kMinimumLength = 1.0e-6;

struct Correspondence {
    int probe;
    int enrolled;
};

struct Relation {
    double angle;
};

using GoodixSigfmFeaturesImpl = GoodixSigfmFeatures;

static_assert (sizeof (float) == sizeof (uint32_t), "float must be IEEE-sized");
static_assert (GOODIX_SIGFM_MAX_BLOB_BYTES == 133139U,
               "serialized SIGFM bound must match the format");

static void
wipe_memory (void *data, size_t length)
{
    volatile uint8_t *bytes = static_cast<volatile uint8_t *> (data);
    while (bytes != nullptr && length-- != 0)
        *bytes++ = 0;
}

struct MatWipe {
    cv::Mat *mat;

    ~MatWipe ()
    {
        if (mat != nullptr && !mat->empty () && mat->data != nullptr)
            wipe_memory (mat->data, mat->total () * mat->elemSize ());
    }
};

struct VectorWipe {
    std::vector<uint8_t> *bytes;

    ~VectorWipe ()
    {
        if (bytes != nullptr && bytes->data () != nullptr &&
            bytes->capacity () != 0)
            wipe_memory (bytes->data (), bytes->capacity ());
    }
};

struct KeypointWipe {
    std::vector<cv::KeyPoint> *points;

    ~KeypointWipe ()
    {
        if (points != nullptr && points->data () != nullptr &&
            points->capacity () != 0)
            wipe_memory (points->data (),
                         points->capacity () * sizeof (cv::KeyPoint));
    }
};

static bool
finite_float (float value)
{
    return std::isfinite (value);
}

static uint32_t
float_bits (float value)
{
    uint32_t bits = 0;
    std::memcpy (&bits, &value, sizeof bits);
    return bits;
}

static float
bits_float (uint32_t bits)
{
    float value = 0.0F;
    std::memcpy (&value, &bits, sizeof value);
    return value;
}

static void
put_u16 (std::vector<uint8_t> &out, uint16_t value)
{
    out.push_back (static_cast<uint8_t> (value & 0xffU));
    out.push_back (static_cast<uint8_t> ((value >> 8) & 0xffU));
}

static void
put_u32 (std::vector<uint8_t> &out, uint32_t value)
{
    for (unsigned int shift = 0; shift < 32; shift += 8)
        out.push_back (static_cast<uint8_t> ((value >> shift) & 0xffU));
}

static bool
get_u16 (const uint8_t *data, size_t length, size_t *offset, uint16_t *value)
{
    if (data == nullptr || offset == nullptr || value == nullptr ||
        *offset > length || length - *offset < 2)
        return false;
    *value = static_cast<uint16_t> (data[*offset]) |
             static_cast<uint16_t> (data[*offset + 1]) << 8;
    *offset += 2;
    return true;
}

static bool
get_u32 (const uint8_t *data, size_t length, size_t *offset, uint32_t *value)
{
    uint32_t result = 0;

    if (data == nullptr || offset == nullptr || value == nullptr ||
        *offset > length || length - *offset < 4)
        return false;
    for (unsigned int shift = 0; shift < 32; shift += 8)
        result |= static_cast<uint32_t> (data[*offset + shift / 8]) << shift;
    *offset += 4;
    *value = result;
    return true;
}

static GoodixSigfmFeaturesImpl *
impl (GoodixSigfmFeatures *features)
{
    return features;
}

static const GoodixSigfmFeaturesImpl *
impl (const GoodixSigfmFeatures *features)
{
    return features;
}

static GoodixSigfmResult
validate_features (const GoodixSigfmFeaturesImpl *features)
{
    if (features == nullptr ||
        features->keypoints.size () < GOODIX_SIGFM_MIN_MATCHES ||
        features->keypoints.size () > GOODIX_SIGFM_MAX_KEYPOINTS ||
        features->descriptors.empty () ||
        features->descriptors.type () != CV_32F ||
        features->descriptors.rows !=
            static_cast<int> (features->keypoints.size ()) ||
        features->descriptors.cols != GOODIX_SIGFM_DESCRIPTOR_LENGTH ||
        !features->descriptors.isContinuous ())
        return GOODIX_SIGFM_INVALID_TEMPLATE;

    for (const cv::KeyPoint &point : features->keypoints) {
        if (!finite_float (point.pt.x) || !finite_float (point.pt.y) ||
            point.pt.x < 0.0F || point.pt.x >= GOODIX_SIGFM_WIDTH ||
            point.pt.y < 0.0F || point.pt.y >= GOODIX_SIGFM_HEIGHT)
            return GOODIX_SIGFM_INVALID_TEMPLATE;
    }
    for (int row = 0; row < features->descriptors.rows; row++) {
        const float *descriptor = features->descriptors.ptr<float> (row);
        for (int col = 0; col < features->descriptors.cols; col++) {
            if (!finite_float (descriptor[col]) || descriptor[col] < 0.0F ||
                descriptor[col] > kMaximumDescriptorValue)
                return GOODIX_SIGFM_INVALID_TEMPLATE;
        }
    }
    return GOODIX_SIGFM_OK;
}

static void
destroy_impl (GoodixSigfmFeaturesImpl *features)
{
    if (features == nullptr)
        return;
    if (!features->descriptors.empty () && features->descriptors.data != nullptr)
        wipe_memory (features->descriptors.data, features->descriptors.total () *
                     features->descriptors.elemSize ());
    features->descriptors.release ();
    if (features->keypoints.data () != nullptr &&
        features->keypoints.capacity () != 0)
        wipe_memory (features->keypoints.data (),
                     features->keypoints.capacity () * sizeof (cv::KeyPoint));
    features->keypoints.clear ();
    delete features;
}

static double
circular_difference (double first, double second)
{
    double difference = std::fabs (first - second);
    constexpr double two_pi = 2.0 * CV_PI;
    while (difference > two_pi)
        difference -= two_pi;
    if (difference > CV_PI)
        difference = two_pi - difference;
    return difference;
}

static bool
build_correspondences (const GoodixSigfmFeaturesImpl *probe,
                       const GoodixSigfmFeaturesImpl *enrolled,
                       std::vector<Correspondence> *correspondences)
{
    std::vector<std::vector<cv::DMatch>> candidates;
    std::set<std::pair<int, int>> unique;
    cv::BFMatcher matcher (cv::NORM_L2, false);

    if (probe == nullptr || enrolled == nullptr || correspondences == nullptr)
        return false;
    try {
        matcher.knnMatch (probe->descriptors, enrolled->descriptors,
                          candidates, 2);
    } catch (const cv::Exception &) {
        return false;
    }
    for (const std::vector<cv::DMatch> &candidate : candidates) {
        if (candidate.size () < 2)
            continue;
        const cv::DMatch &best = candidate[0];
        const cv::DMatch &next = candidate[1];
        if (!std::isfinite (best.distance) || !std::isfinite (next.distance) ||
            !(best.distance < kLoweRatio * next.distance))
            continue;
        if (best.queryIdx < 0 || best.trainIdx < 0 ||
            best.queryIdx >= probe->descriptors.rows ||
            best.trainIdx >= enrolled->descriptors.rows)
            continue;
        if (unique.emplace (best.queryIdx, best.trainIdx).second)
            correspondences->push_back ({best.queryIdx, best.trainIdx});
    }
    return correspondences->size () >= GOODIX_SIGFM_MIN_MATCHES;
}

static int32_t
relation_score (const GoodixSigfmFeaturesImpl *probe,
                const GoodixSigfmFeaturesImpl *enrolled,
                const std::vector<Correspondence> &correspondences)
{
    std::vector<Relation> relations;

    for (size_t first = 0; first < correspondences.size (); first++) {
        const Correspondence &a = correspondences[first];
        const cv::Point2f a_probe = probe->keypoints[a.probe].pt;
        const cv::Point2f a_enrolled = enrolled->keypoints[a.enrolled].pt;
        for (size_t second = first + 1; second < correspondences.size (); second++) {
            const Correspondence &b = correspondences[second];
            const cv::Point2f b_probe = probe->keypoints[b.probe].pt;
            const cv::Point2f b_enrolled = enrolled->keypoints[b.enrolled].pt;
            const double probe_x = static_cast<double> (a_probe.x - b_probe.x);
            const double probe_y = static_cast<double> (a_probe.y - b_probe.y);
            const double enrolled_x =
                static_cast<double> (a_enrolled.x - b_enrolled.x);
            const double enrolled_y =
                static_cast<double> (a_enrolled.y - b_enrolled.y);
            const double probe_length =
                std::hypot (probe_x, probe_y);
            const double enrolled_length =
                std::hypot (enrolled_x, enrolled_y);

            if (probe_length < kMinimumLength || enrolled_length < kMinimumLength)
                continue;
            if (1.0 - std::min (probe_length, enrolled_length) /
                            std::max (probe_length, enrolled_length) >
                kLengthTolerance)
                continue;
            relations.push_back ({
                std::atan2 (probe_x * enrolled_y - probe_y * enrolled_x,
                            probe_x * enrolled_x + probe_y * enrolled_y)});
        }
    }
    if (relations.size () < GOODIX_SIGFM_MIN_MATCHES)
        return 0;

    uint64_t count = 0;
    for (size_t first = 0; first < relations.size (); first++) {
        for (size_t second = first + 1; second < relations.size (); second++) {
            if (circular_difference (relations[first].angle,
                                     relations[second].angle) <=
                kAngleTolerance)
                count++;
        }
    }
    return count > static_cast<uint64_t> (std::numeric_limits<int32_t>::max ()) ?
        std::numeric_limits<int32_t>::max () : static_cast<int32_t> (count);
}

} // namespace

extern "C" GoodixSigfmResult
goodix_sigfm_extract (const uint8_t *pixels, size_t pixel_count,
                      GoodixSigfmFeatures **features)
{
    cv::Mat image;
    std::vector<cv::KeyPoint> keypoints;
    cv::Mat descriptors;
    MatWipe image_wipe {&image};
    MatWipe descriptor_wipe {&descriptors};
    KeypointWipe keypoint_wipe {&keypoints};

    if (features == nullptr || pixels == nullptr)
        return GOODIX_SIGFM_INVALID_ARGUMENT;
    if (*features != nullptr)
        return GOODIX_SIGFM_INVALID_ARGUMENT;
    if (pixel_count != GOODIX_SIGFM_PIXELS)
        return GOODIX_SIGFM_INVALID_LENGTH;
    *features = nullptr;
    try {
        image = cv::Mat (GOODIX_SIGFM_HEIGHT, GOODIX_SIGFM_WIDTH, CV_8UC1,
                         const_cast<uint8_t *> (pixels)).clone ();
        const cv::Mat mask = cv::Mat::ones (image.size (), CV_8UC1);
        cv::Ptr<cv::SIFT> sift = cv::SIFT::create (
            GOODIX_SIGFM_MAX_KEYPOINTS, 3, 0.04, 10, 1.6);
        sift->detectAndCompute (image, mask, keypoints, descriptors, false);
        if (keypoints.size () < GOODIX_SIGFM_MIN_MATCHES ||
            descriptors.empty ())
            return GOODIX_SIGFM_NO_FEATURES;
        if (keypoints.size () > GOODIX_SIGFM_MAX_KEYPOINTS) {
            const size_t keep = GOODIX_SIGFM_MAX_KEYPOINTS;
            wipe_memory (keypoints.data () + keep,
                         (keypoints.size () - keep) * sizeof (cv::KeyPoint));
            keypoints.resize (keep);
        }
        if (descriptors.rows > static_cast<int> (keypoints.size ())) {
            cv::Mat limited = descriptors.rowRange (
                0, static_cast<int> (keypoints.size ())).clone ();
            if (descriptors.data != nullptr)
                wipe_memory (descriptors.data,
                             descriptors.total () * descriptors.elemSize ());
            descriptors = std::move (limited);
        }
        if (descriptors.rows != static_cast<int> (keypoints.size ()) ||
            descriptors.cols != GOODIX_SIGFM_DESCRIPTOR_LENGTH ||
            descriptors.type () != CV_32F)
            return GOODIX_SIGFM_INTERNAL;

        std::unique_ptr<GoodixSigfmFeatures> result (
            new GoodixSigfmFeatures ());
        result->keypoints = std::move (keypoints);
        result->descriptors = std::move (descriptors);
        *features = result.release ();
        return GOODIX_SIGFM_OK;
    } catch (const std::bad_alloc &) {
        return GOODIX_SIGFM_NO_MEMORY;
    } catch (const cv::Exception &) {
        return GOODIX_SIGFM_INTERNAL;
    } catch (...) {
        return GOODIX_SIGFM_INTERNAL;
    }
}

extern "C" void
goodix_sigfm_features_free (GoodixSigfmFeatures *features)
{
    destroy_impl (impl (features));
}

extern "C" size_t
goodix_sigfm_keypoint_count (const GoodixSigfmFeatures *features)
{
    const GoodixSigfmFeaturesImpl *value = impl (features);
    return value == nullptr ? 0 : value->keypoints.size ();
}

extern "C" GoodixSigfmResult
goodix_sigfm_serialize (const GoodixSigfmFeatures *features,
                        uint8_t **blob, size_t *blob_length)
{
    const GoodixSigfmFeaturesImpl *value = impl (features);
    std::vector<uint8_t> encoded;
    VectorWipe encoded_wipe {&encoded};
    size_t total;

    if (blob == nullptr || blob_length == nullptr)
        return GOODIX_SIGFM_INVALID_ARGUMENT;
    if (*blob != nullptr)
        return GOODIX_SIGFM_INVALID_ARGUMENT;
    if (validate_features (value) != GOODIX_SIGFM_OK)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    *blob_length = 0;
    if (value->keypoints.size () > std::numeric_limits<uint16_t>::max ())
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    total = kHeaderBytes + value->keypoints.size () * 8U +
            value->keypoints.size () * GOODIX_SIGFM_DESCRIPTOR_LENGTH * 4U;
    if (total > GOODIX_SIGFM_MAX_BLOB_BYTES || total < kHeaderBytes)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    try {
        encoded.reserve (total);
        encoded.insert (encoded.end (), {'G', 'S', 'F', 'M'});
        encoded.push_back (kVersion);
        put_u16 (encoded, GOODIX_SIGFM_WIDTH);
        put_u16 (encoded, GOODIX_SIGFM_HEIGHT);
        put_u16 (encoded, static_cast<uint16_t> (value->keypoints.size ()));
        put_u16 (encoded, GOODIX_SIGFM_DESCRIPTOR_LENGTH);
        encoded.push_back (kDescriptorTypeFloat32);
        encoded.push_back (0);
        put_u16 (encoded, GOODIX_SIGFM_MIN_MATCHES);
        put_u16 (encoded, GOODIX_SIGFM_SCORE_THRESHOLD);
        for (const cv::KeyPoint &point : value->keypoints) {
            put_u32 (encoded, float_bits (point.pt.x));
            put_u32 (encoded, float_bits (point.pt.y));
        }
        for (int row = 0; row < value->descriptors.rows; row++) {
            const float *descriptor = value->descriptors.ptr<float> (row);
            for (int col = 0; col < value->descriptors.cols; col++)
                put_u32 (encoded, float_bits (descriptor[col]));
        }
        if (encoded.size () != total)
            return GOODIX_SIGFM_INTERNAL;
        auto *result = static_cast<uint8_t *> (std::malloc (encoded.size ()));
        if (result == nullptr)
            return GOODIX_SIGFM_NO_MEMORY;
        std::memcpy (result, encoded.data (), encoded.size ());
        *blob = result;
        *blob_length = encoded.size ();
        wipe_memory (encoded.data (), encoded.size ());
        return GOODIX_SIGFM_OK;
    } catch (const std::bad_alloc &) {
        return GOODIX_SIGFM_NO_MEMORY;
    } catch (...) {
        return GOODIX_SIGFM_INTERNAL;
    }
}

extern "C" GoodixSigfmResult
goodix_sigfm_deserialize (const uint8_t *blob, size_t blob_length,
                          GoodixSigfmFeatures **features)
{
    size_t offset = 5;
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t count = 0;
    uint16_t descriptor_length = 0;
    uint8_t descriptor_type;
    std::vector<cv::KeyPoint> keypoints;
    cv::Mat descriptors;
    MatWipe descriptor_wipe {&descriptors};
    KeypointWipe keypoint_wipe {&keypoints};

    if (features == nullptr || blob == nullptr)
        return GOODIX_SIGFM_INVALID_ARGUMENT;
    if (*features != nullptr)
        return GOODIX_SIGFM_INVALID_ARGUMENT;
    *features = nullptr;
    if (blob_length < kHeaderBytes || blob_length > GOODIX_SIGFM_MAX_BLOB_BYTES)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    if (std::memcmp (blob, "GSFM", 4) != 0 || blob[4] != kVersion)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    if (!get_u16 (blob, blob_length, &offset, &width) ||
        !get_u16 (blob, blob_length, &offset, &height) ||
        !get_u16 (blob, blob_length, &offset, &count) ||
        !get_u16 (blob, blob_length, &offset, &descriptor_length))
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    descriptor_type = blob[offset++];
    if (blob[offset++] != 0 || width != GOODIX_SIGFM_WIDTH ||
        height != GOODIX_SIGFM_HEIGHT ||
        count < GOODIX_SIGFM_MIN_MATCHES ||
        count > GOODIX_SIGFM_MAX_KEYPOINTS ||
        descriptor_length != GOODIX_SIGFM_DESCRIPTOR_LENGTH ||
        descriptor_type != kDescriptorTypeFloat32)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    uint16_t minimum_matches = 0, threshold = 0;
    if (!get_u16 (blob, blob_length, &offset, &minimum_matches) ||
        !get_u16 (blob, blob_length, &offset, &threshold) ||
        minimum_matches != GOODIX_SIGFM_MIN_MATCHES ||
        threshold != GOODIX_SIGFM_SCORE_THRESHOLD)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    const size_t expected = kHeaderBytes + static_cast<size_t> (count) * 8U +
        static_cast<size_t> (count) * descriptor_length * 4U;
    if (expected != blob_length || expected > GOODIX_SIGFM_MAX_BLOB_BYTES)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    try {
        keypoints.reserve (count);
        for (uint16_t index = 0; index < count; index++) {
            uint32_t x_bits = 0;
            uint32_t y_bits = 0;
            if (!get_u32 (blob, blob_length, &offset, &x_bits) ||
                !get_u32 (blob, blob_length, &offset, &y_bits))
                return GOODIX_SIGFM_INVALID_TEMPLATE;
            const float x = bits_float (x_bits);
            const float y = bits_float (y_bits);
            if (!finite_float (x) || !finite_float (y) ||
                x < 0.0F || x >= GOODIX_SIGFM_WIDTH ||
                y < 0.0F || y >= GOODIX_SIGFM_HEIGHT)
                return GOODIX_SIGFM_INVALID_TEMPLATE;
            keypoints.emplace_back (cv::Point2f (x, y), 1.0F);
        }
        descriptors = cv::Mat (count, descriptor_length, CV_32F);
        for (int row = 0; row < descriptors.rows; row++) {
            float *descriptor = descriptors.ptr<float> (row);
            for (int col = 0; col < descriptors.cols; col++) {
                uint32_t bits = 0;
                if (!get_u32 (blob, blob_length, &offset, &bits))
                    return GOODIX_SIGFM_INVALID_TEMPLATE;
                descriptor[col] = bits_float (bits);
                if (!finite_float (descriptor[col]) ||
                    descriptor[col] < 0.0F ||
                    descriptor[col] > kMaximumDescriptorValue)
                    return GOODIX_SIGFM_INVALID_TEMPLATE;
            }
        }
        if (offset != blob_length)
            return GOODIX_SIGFM_INVALID_TEMPLATE;
        std::unique_ptr<GoodixSigfmFeatures> result (
            new GoodixSigfmFeatures ());
        result->keypoints = std::move (keypoints);
        result->descriptors = std::move (descriptors);
        *features = result.release ();
        return GOODIX_SIGFM_OK;
    } catch (const std::bad_alloc &) {
        return GOODIX_SIGFM_NO_MEMORY;
    } catch (const cv::Exception &) {
        return GOODIX_SIGFM_NO_MEMORY;
    } catch (...) {
        return GOODIX_SIGFM_INTERNAL;
    }
}

extern "C" void
goodix_sigfm_free_buffer (uint8_t *blob, size_t blob_length)
{
    if (blob == nullptr)
        return;
    wipe_memory (blob, blob_length);
    std::free (blob);
}

extern "C" GoodixSigfmResult
goodix_sigfm_score (const GoodixSigfmFeatures *probe,
                    const GoodixSigfmFeatures *enrolled, int32_t *score)
{
    const GoodixSigfmFeaturesImpl *probe_impl = impl (probe);
    const GoodixSigfmFeaturesImpl *enrolled_impl = impl (enrolled);
    std::vector<Correspondence> correspondences;

    if (score == nullptr || probe == nullptr || enrolled == nullptr)
        return GOODIX_SIGFM_INVALID_ARGUMENT;
    if (validate_features (probe_impl) != GOODIX_SIGFM_OK ||
        validate_features (enrolled_impl) != GOODIX_SIGFM_OK)
        return GOODIX_SIGFM_INVALID_TEMPLATE;
    *score = 0;
    try {
        if (!build_correspondences (probe_impl, enrolled_impl, &correspondences))
            return GOODIX_SIGFM_OK;
        *score = relation_score (probe_impl, enrolled_impl, correspondences);
        return GOODIX_SIGFM_OK;
    } catch (const cv::Exception &) {
        return GOODIX_SIGFM_INTERNAL;
    } catch (...) {
        return GOODIX_SIGFM_INTERNAL;
    }
}

extern "C" bool
goodix_sigfm_accepts (int32_t score)
{
    return score >= GOODIX_SIGFM_SCORE_THRESHOLD;
}

extern "C" const char *
goodix_sigfm_result_string (GoodixSigfmResult result)
{
    switch (result) {
    case GOODIX_SIGFM_OK:
        return "ok";
    case GOODIX_SIGFM_INVALID_ARGUMENT:
        return "invalid argument";
    case GOODIX_SIGFM_INVALID_LENGTH:
        return "invalid length";
    case GOODIX_SIGFM_NO_FEATURES:
        return "no features";
    case GOODIX_SIGFM_INVALID_TEMPLATE:
        return "invalid template";
    case GOODIX_SIGFM_NO_MEMORY:
        return "out of memory";
    case GOODIX_SIGFM_INTERNAL:
        return "matcher failure";
    }
    return "unknown matcher error";
}

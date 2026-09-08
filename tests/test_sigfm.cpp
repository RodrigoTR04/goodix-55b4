/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_sigfm.h"
#include <cassert>
#include <cstring>
#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>

int main()
{
    cv::Mat image(GOODIX_SIGFM_HEIGHT, GOODIX_SIGFM_WIDTH, CV_8UC1);
    cv::RNG random(42);
    random.fill(image, cv::RNG::UNIFORM, 0, 256);
    cv::GaussianBlur(image, image, cv::Size(3, 3), 0.7);
    GoodixSigfmFeatures *features = nullptr, *decoded = nullptr;
    assert(goodix_sigfm_extract(image.data, image.total(), &features) == GOODIX_SIGFM_OK);
    uint8_t *blob = nullptr;
    size_t size = 0;
    assert(goodix_sigfm_serialize(features, &blob, &size) == GOODIX_SIGFM_OK);
    assert(goodix_sigfm_deserialize(blob, size, &decoded) == GOODIX_SIGFM_OK);
    int32_t score = 0;
    assert(goodix_sigfm_score(features, decoded, &score) == GOODIX_SIGFM_OK);
    assert(goodix_sigfm_accepts(score));
    goodix_sigfm_features_free(decoded);
    decoded = nullptr;
    for (size_t offset : {size_t(4), size_t(15), size_t(17)}) {
        blob[offset] ^= 1;
        assert(goodix_sigfm_deserialize(blob, size, &decoded) == GOODIX_SIGFM_INVALID_TEMPLATE);
        assert(decoded == nullptr);
        blob[offset] ^= 1;
    }
    assert(goodix_sigfm_deserialize(blob, size - 1, &decoded) == GOODIX_SIGFM_INVALID_TEMPLATE);
    goodix_sigfm_free_buffer(blob, size);
    goodix_sigfm_features_free(features);
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "goodix_key.h"
#include "goodix_sigfm.h"

#include <stddef.h>
#include <stdint.h>

#define GOODIX_SEAL_NONCE_SIZE 12U
#define GOODIX_SEAL_TAG_SIZE 16U
#define GOODIX_SEAL_HEADER_SIZE (8U + 1U + GOODIX_SEAL_NONCE_SIZE)
#define GOODIX_SEAL_OVERHEAD (GOODIX_SEAL_HEADER_SIZE + GOODIX_SEAL_TAG_SIZE)
#define GOODIX_SEAL_MAX_PLAIN_BYTES GOODIX_SIGFM_MAX_BLOB_BYTES
#define GOODIX_SEAL_MAX_BYTES (GOODIX_SEAL_MAX_PLAIN_BYTES + GOODIX_SEAL_OVERHEAD)

typedef enum {
    GOODIX_SEAL_OK = 0,
    GOODIX_SEAL_INVALID_ARGUMENT,
    GOODIX_SEAL_BUFFER_TOO_SMALL,
    GOODIX_SEAL_CRYPTO_ERROR,
    GOODIX_SEAL_FORGED,
} GoodixSealResult;

/* AES-256-GCM wrap of SIGFM feature blobs. Rasters are never sealed. */
GoodixSealResult goodix_seal_wrap(const uint8_t key[GOODIX_WRAP_KEY_SIZE],
                                  const uint8_t *plain, size_t plain_length,
                                  uint8_t *sealed, size_t sealed_capacity,
                                  size_t *sealed_length);
GoodixSealResult goodix_seal_unwrap(const uint8_t key[GOODIX_WRAP_KEY_SIZE],
                                    const uint8_t *sealed, size_t sealed_length,
                                    uint8_t *plain, size_t plain_capacity,
                                    size_t *plain_length);

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define GOODIX_TLS_PSK_SIZE 32

typedef struct GoodixTlsSession GoodixTlsSession;

typedef enum {
    GOODIX_TLS_OK = 0,
    GOODIX_TLS_WANT_INPUT,
    GOODIX_TLS_ESTABLISHED,
    GOODIX_TLS_INVALID_ARGUMENT,
    GOODIX_TLS_BUFFER_TOO_SMALL,
    GOODIX_TLS_OPENSSL_ERROR,
} GoodixTlsResult;

GoodixTlsResult goodix_tls_session_new(const uint8_t *psk,
                                       size_t psk_length,
                                       GoodixTlsSession **session);

void goodix_tls_session_free(GoodixTlsSession *session);

GoodixTlsResult goodix_tls_session_feed(GoodixTlsSession *session,
                                        const uint8_t *ciphertext,
                                        size_t ciphertext_length);

size_t goodix_tls_session_pending_output(const GoodixTlsSession *session);

GoodixTlsResult goodix_tls_session_take_output(GoodixTlsSession *session,
                                               uint8_t *output,
                                               size_t output_capacity,
                                               size_t *output_length);

GoodixTlsResult goodix_tls_session_read(GoodixTlsSession *session,
                                        uint8_t *plaintext,
                                        size_t plaintext_capacity,
                                        size_t *plaintext_length);

bool goodix_tls_session_is_established(const GoodixTlsSession *session);

const char *goodix_tls_result_string(GoodixTlsResult result);

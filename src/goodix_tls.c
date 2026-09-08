/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "goodix_tls.h"

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>

#ifndef SSL_OP_CLEANSE_PLAINTEXT
#error "Goodix private frame handling requires OpenSSL SSL_OP_CLEANSE_PLAINTEXT"
#endif

struct GoodixTlsSession {
    SSL_CTX *context;
    SSL *ssl;
    uint8_t psk[GOODIX_TLS_PSK_SIZE];
    bool established;
};

static unsigned int
provide_psk(SSL *ssl,
            const char *identity,
            unsigned char *psk,
            unsigned int max_psk_length)
{
    (void)identity;
    GoodixTlsSession *session = SSL_get_app_data(ssl);

    if (session == NULL || max_psk_length < sizeof(session->psk))
        return 0;
    memcpy(psk, session->psk, sizeof(session->psk));
    return sizeof(session->psk);
}

static GoodixTlsResult
advance_handshake(GoodixTlsSession *session)
{
    if (session->established)
        return GOODIX_TLS_ESTABLISHED;

    int rc = SSL_do_handshake(session->ssl);
    if (rc == 1) {
        /* Defense in depth against accidental policy widening. */
        if (SSL_version(session->ssl) != TLS1_2_VERSION ||
            strcmp(SSL_get_cipher_name(session->ssl),
                   "PSK-AES128-CBC-SHA256") != 0)
            return GOODIX_TLS_OPENSSL_ERROR;
        session->established = true;
        return GOODIX_TLS_ESTABLISHED;
    }

    int error = SSL_get_error(session->ssl, rc);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
        return GOODIX_TLS_WANT_INPUT;
    return GOODIX_TLS_OPENSSL_ERROR;
}

GoodixTlsResult
goodix_tls_session_new(const uint8_t *psk,
                       size_t psk_length,
                       GoodixTlsSession **session_out)
{
    if (psk == NULL || psk_length != GOODIX_TLS_PSK_SIZE ||
        session_out == NULL)
        return GOODIX_TLS_INVALID_ARGUMENT;

    *session_out = NULL;
    GoodixTlsSession *session = calloc(1, sizeof(*session));
    if (session == NULL)
        return GOODIX_TLS_OPENSSL_ERROR;

    session->context = SSL_CTX_new(TLS_server_method());
    if (session->context == NULL)
        goto error;
    /* Compatibility exception, isolated to this sensor context: the device
     * speaks only TLS 1.2 PSK-AES128-CBC-SHA256. Distribution default security
     * levels reject CBC/SHA256 PSK suites, so level 0 disables OpenSSL's
     * minimum-strength policy filter here. It does not weaken the record MAC,
     * and the negotiated version/cipher is re-checked after the handshake. */
    if (SSL_CTX_set_min_proto_version(session->context, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(session->context, TLS1_2_VERSION) != 1 ||
        SSL_CTX_set_cipher_list(session->context,
                                "PSK-AES128-CBC-SHA256:@SECLEVEL=0") != 1)
        goto error;
    /* SSL_free alone does not promise to wipe decrypted record buffers. */
    SSL_CTX_set_options(session->context, SSL_OP_CLEANSE_PLAINTEXT |
                        SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(session->context, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_psk_server_callback(session->context, provide_psk);

    session->ssl = SSL_new(session->context);
    if (session->ssl == NULL)
        goto error;

    BIO *read_bio = BIO_new(BIO_s_mem());
    BIO *write_bio = BIO_new(BIO_s_mem());
    if (read_bio == NULL || write_bio == NULL) {
        BIO_free(read_bio);
        BIO_free(write_bio);
        goto error;
    }

    memcpy(session->psk, psk, sizeof(session->psk));
    SSL_set_app_data(session->ssl, session);
    SSL_set_bio(session->ssl, read_bio, write_bio);
    SSL_set_accept_state(session->ssl);
    *session_out = session;
    return GOODIX_TLS_OK;

error:
    goodix_tls_session_free(session);
    return GOODIX_TLS_OPENSSL_ERROR;
}

static void
cleanse_memory_bio(BIO *bio)
{
    BUF_MEM *buffer = NULL;
    if (bio != NULL && BIO_get_mem_ptr(bio, &buffer) > 0 && buffer != NULL && buffer->data != NULL)
        OPENSSL_cleanse(buffer->data, buffer->max);
}

void
goodix_tls_session_free(GoodixTlsSession *session)
{
    if (session == NULL)
        return;
    if (session->ssl != NULL) {
        cleanse_memory_bio(SSL_get_rbio(session->ssl));
        cleanse_memory_bio(SSL_get_wbio(session->ssl));
    }
    SSL_free(session->ssl);
    SSL_CTX_free(session->context);
    OPENSSL_cleanse(session->psk, sizeof(session->psk));
    free(session);
}

GoodixTlsResult
goodix_tls_session_feed(GoodixTlsSession *session,
                        const uint8_t *ciphertext,
                        size_t ciphertext_length)
{
    if (session == NULL || ciphertext == NULL || ciphertext_length == 0 ||
        ciphertext_length > INT_MAX)
        return GOODIX_TLS_INVALID_ARGUMENT;

    BIO *read_bio = SSL_get_rbio(session->ssl);
    int written = BIO_write(read_bio, ciphertext, (int)ciphertext_length);
    if (written != (int)ciphertext_length)
        return GOODIX_TLS_OPENSSL_ERROR;

    if (!session->established)
        return advance_handshake(session);
    return GOODIX_TLS_OK;
}

size_t
goodix_tls_session_pending_output(const GoodixTlsSession *session)
{
    if (session == NULL || session->ssl == NULL)
        return 0;
    return BIO_ctrl_pending(SSL_get_wbio(session->ssl));
}

GoodixTlsResult
goodix_tls_session_take_output(GoodixTlsSession *session,
                               uint8_t *output,
                               size_t output_capacity,
                               size_t *output_length)
{
    if (session == NULL || output_length == NULL ||
        (output == NULL && output_capacity != 0))
        return GOODIX_TLS_INVALID_ARGUMENT;

    size_t pending = goodix_tls_session_pending_output(session);
    *output_length = pending;
    if (pending == 0)
        return GOODIX_TLS_OK;
    if (output_capacity < pending || pending > INT_MAX)
        return GOODIX_TLS_BUFFER_TOO_SMALL;

    int read = BIO_read(SSL_get_wbio(session->ssl), output, (int)pending);
    if (read != (int)pending)
        return GOODIX_TLS_OPENSSL_ERROR;
    return GOODIX_TLS_OK;
}

GoodixTlsResult
goodix_tls_session_read(GoodixTlsSession *session,
                        uint8_t *plaintext,
                        size_t plaintext_capacity,
                        size_t *plaintext_length)
{
    if (session == NULL || plaintext == NULL || plaintext_length == NULL ||
        plaintext_capacity == 0 || plaintext_capacity > INT_MAX)
        return GOODIX_TLS_INVALID_ARGUMENT;
    if (!session->established)
        return GOODIX_TLS_WANT_INPUT;

    int read = SSL_read(session->ssl, plaintext, (int)plaintext_capacity);
    if (read > 0) {
        *plaintext_length = (size_t)read;
        return GOODIX_TLS_OK;
    }

    *plaintext_length = 0;
    int error = SSL_get_error(session->ssl, read);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
        return GOODIX_TLS_WANT_INPUT;
    return GOODIX_TLS_OPENSSL_ERROR;
}

bool
goodix_tls_session_is_established(const GoodixTlsSession *session)
{
    return session != NULL && session->established;
}

const char *
goodix_tls_result_string(GoodixTlsResult result)
{
    switch (result) {
    case GOODIX_TLS_OK:
        return "success";
    case GOODIX_TLS_WANT_INPUT:
        return "more TLS input required";
    case GOODIX_TLS_ESTABLISHED:
        return "TLS session established";
    case GOODIX_TLS_INVALID_ARGUMENT:
        return "invalid argument";
    case GOODIX_TLS_BUFFER_TOO_SMALL:
        return "buffer too small";
    case GOODIX_TLS_OPENSSL_ERROR:
        return "TLS operation failed";
    }
    return "unknown TLS error";
}

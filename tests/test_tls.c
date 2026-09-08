/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_tls.h"
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <string.h>

static unsigned char key[GOODIX_TLS_PSK_SIZE];
static unsigned int client_psk(SSL *ssl, const char *hint, char *identity,
                              unsigned int identity_capacity, unsigned char *psk,
                              unsigned int capacity)
{
    (void)ssl; (void)hint;
    assert(identity_capacity > 4 && capacity >= sizeof(key));
    memcpy(identity, "test", 5);
    memcpy(psk, key, sizeof(key));
    return sizeof(key);
}

static void exercise(const char *cipher, int version, int wrong_key, int expected)
{
    GoodixTlsSession *server = NULL;
    assert(goodix_tls_session_new(key, sizeof(key), &server) == GOODIX_TLS_OK);
    if (wrong_key) key[0] ^= 1;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx);
    assert(SSL_CTX_set_min_proto_version(ctx, version));
    assert(SSL_CTX_set_max_proto_version(ctx, version));
    assert(SSL_CTX_set_cipher_list(ctx, cipher));
    SSL_CTX_set_psk_client_callback(ctx, client_psk);
    SSL *client = SSL_new(ctx);
    assert(client);
    SSL_set_bio(client, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
    SSL_set_connect_state(client);
    unsigned char wire[8192];
    GoodixTlsResult result = GOODIX_TLS_OK;
    for (int i = 0; i < 20; i++) {
        int rc = SSL_do_handshake(client);
        if (rc != 1) {
            int error = SSL_get_error(client, rc);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) break;
        }
        int count = BIO_read(SSL_get_wbio(client), wire, sizeof(wire));
        if (count > 0) result = goodix_tls_session_feed(server, wire, (size_t)count);
        if (result == GOODIX_TLS_OPENSSL_ERROR) break;
        size_t size = 0;
        assert(goodix_tls_session_take_output(server, wire, sizeof(wire), &size) == GOODIX_TLS_OK);
        if (size) assert(BIO_write(SSL_get_rbio(client), wire, (int)size) == (int)size);
        if (SSL_is_init_finished(client) && goodix_tls_session_is_established(server)) break;
    }
    assert(goodix_tls_session_is_established(server) == (expected != 0));
    if (expected) {
        assert(SSL_version(client) == TLS1_2_VERSION);
        assert(strcmp(SSL_get_cipher_name(client), "PSK-AES128-CBC-SHA256") == 0);
        const char message[] = "synthetic frame";
        assert(SSL_write(client, message, sizeof(message)) == sizeof(message));
        int count = BIO_read(SSL_get_wbio(client), wire, sizeof(wire));
        assert(count > 0);
        assert(goodix_tls_session_feed(server, wire, (size_t)count) == GOODIX_TLS_OK);
        unsigned char plain[128];
        size_t size = 0;
        assert(goodix_tls_session_read(server, plain, sizeof(plain), &size) == GOODIX_TLS_OK);
        assert(size == sizeof(message) && memcmp(plain, message, size) == 0);
        assert(SSL_write(client, message, sizeof(message)) == sizeof(message));
        count = BIO_read(SSL_get_wbio(client), wire, sizeof(wire));
        assert(count > 0);
        wire[count - 1] ^= 1;
        assert(goodix_tls_session_feed(server, wire, (size_t)count) == GOODIX_TLS_OK);
        assert(goodix_tls_session_read(server, plain, sizeof(plain), &size) == GOODIX_TLS_OPENSSL_ERROR);
        assert(size == 0);
    }
    if (wrong_key) key[0] ^= 1;
    SSL_free(client);
    SSL_CTX_free(ctx);
    goodix_tls_session_free(server);
}

int main(void)
{
    assert(RAND_bytes(key, sizeof(key)) == 1);
    exercise("PSK-AES128-CBC-SHA256:@SECLEVEL=0", TLS1_2_VERSION, 0, 1);
    exercise("PSK-AES128-CBC-SHA256:@SECLEVEL=0", TLS1_2_VERSION, 1, 0);
    exercise("PSK-AES256-CBC-SHA384:@SECLEVEL=0", TLS1_2_VERSION, 0, 0);
    exercise("PSK-AES128-CBC-SHA256:@SECLEVEL=0", TLS1_3_VERSION, 0, 0);
    return 0;
}

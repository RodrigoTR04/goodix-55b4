/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_seal.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

static const uint8_t seal_magic[8] = {
    'G', '5', '5', 'B', '4', 'S', 'L', '1',
};
static const uint8_t seal_aad[] = "goodix55b4-sigfm-v2";

GoodixSealResult
goodix_seal_wrap(const uint8_t key[GOODIX_WRAP_KEY_SIZE],
                 const uint8_t *plain, size_t plain_length,
                 uint8_t *sealed, size_t sealed_capacity,
                 size_t *sealed_length)
{
    EVP_CIPHER_CTX *ctx;
    size_t needed;
    int out_length = 0;
    int extra = 0;

    if (sealed_length != NULL)
        *sealed_length = 0;
    if (key == NULL || plain == NULL || sealed == NULL || sealed_length == NULL ||
        plain_length == 0 || plain_length > GOODIX_SEAL_MAX_PLAIN_BYTES)
        return GOODIX_SEAL_INVALID_ARGUMENT;
    needed = plain_length + GOODIX_SEAL_OVERHEAD;
    if (sealed_capacity < needed)
        return GOODIX_SEAL_BUFFER_TOO_SMALL;

    memcpy(sealed, seal_magic, sizeof(seal_magic));
    sealed[8] = 1;
    if (RAND_bytes(sealed + 9, GOODIX_SEAL_NONCE_SIZE) != 1)
        return GOODIX_SEAL_CRYPTO_ERROR;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return GOODIX_SEAL_CRYPTO_ERROR;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GOODIX_SEAL_NONCE_SIZE,
                            NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, sealed + 9) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &out_length, seal_aad, (int)sizeof(seal_aad) - 1) != 1 ||
        EVP_EncryptUpdate(ctx, sealed + GOODIX_SEAL_HEADER_SIZE, &out_length,
                          plain, (int)plain_length) != 1 ||
        EVP_EncryptFinal_ex(ctx, sealed + GOODIX_SEAL_HEADER_SIZE + out_length,
                            &extra) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GOODIX_SEAL_TAG_SIZE,
                            sealed + GOODIX_SEAL_HEADER_SIZE + out_length + extra) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(sealed, sealed_capacity);
        return GOODIX_SEAL_CRYPTO_ERROR;
    }
    EVP_CIPHER_CTX_free(ctx);
    *sealed_length = needed;
    return GOODIX_SEAL_OK;
}

GoodixSealResult
goodix_seal_unwrap(const uint8_t key[GOODIX_WRAP_KEY_SIZE],
                   const uint8_t *sealed, size_t sealed_length,
                   uint8_t *plain, size_t plain_capacity,
                   size_t *plain_length)
{
    uint8_t tag[GOODIX_SEAL_TAG_SIZE];
    EVP_CIPHER_CTX *ctx;
    size_t cipher_length;
    int out_length = 0;
    int extra = 0;

    if (plain_length != NULL)
        *plain_length = 0;
    if (key == NULL || sealed == NULL || plain == NULL || plain_length == NULL)
        return GOODIX_SEAL_INVALID_ARGUMENT;
    if (sealed_length < GOODIX_SEAL_OVERHEAD + 1 ||
        sealed_length > GOODIX_SEAL_MAX_BYTES)
        return GOODIX_SEAL_FORGED;
    if (memcmp(sealed, seal_magic, sizeof(seal_magic)) != 0 || sealed[8] != 1)
        return GOODIX_SEAL_FORGED;
    cipher_length = sealed_length - GOODIX_SEAL_OVERHEAD;
    if (cipher_length > GOODIX_SEAL_MAX_PLAIN_BYTES ||
        plain_capacity < cipher_length)
        return GOODIX_SEAL_BUFFER_TOO_SMALL;
    memcpy(tag, sealed + GOODIX_SEAL_HEADER_SIZE + cipher_length,
           sizeof(tag));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OPENSSL_cleanse(tag, sizeof(tag));
        return GOODIX_SEAL_CRYPTO_ERROR;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GOODIX_SEAL_NONCE_SIZE,
                            NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, sealed + 9) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &out_length, seal_aad, (int)sizeof(seal_aad) - 1) != 1 ||
        EVP_DecryptUpdate(ctx, plain, &out_length,
                          sealed + GOODIX_SEAL_HEADER_SIZE,
                          (int)cipher_length) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GOODIX_SEAL_TAG_SIZE,
                            tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plain + out_length, &extra) != 1) {
        OPENSSL_cleanse(tag, sizeof(tag));
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(plain, plain_capacity);
        return GOODIX_SEAL_FORGED;
    }
    OPENSSL_cleanse(tag, sizeof(tag));
    EVP_CIPHER_CTX_free(ctx);
    *plain_length = (size_t)(out_length + extra);
    return GOODIX_SEAL_OK;
}

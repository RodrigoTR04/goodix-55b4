/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "goodix_seal.h"
#include <assert.h>
#include <string.h>
#include <sys/random.h>

int main(void)
{
    uint8_t key[GOODIX_WRAP_KEY_SIZE];
    uint8_t other[GOODIX_WRAP_KEY_SIZE];
    uint8_t plain[64];
    uint8_t sealed[GOODIX_SEAL_MAX_BYTES];
    uint8_t recovered[sizeof(plain)];
    size_t sealed_length = 0;
    size_t recovered_length = 0;

    assert(getentropy(key, sizeof(key)) == 0);
    assert(getentropy(other, sizeof(other)) == 0);
    assert(getentropy(plain, sizeof(plain)) == 0);
    other[0] ^= 1;

    assert(goodix_seal_wrap(key, plain, sizeof(plain), sealed, sizeof(sealed),
                            &sealed_length) == GOODIX_SEAL_OK);
    assert(sealed_length == sizeof(plain) + GOODIX_SEAL_OVERHEAD);
    assert(goodix_seal_unwrap(key, sealed, sealed_length, recovered,
                              sizeof(recovered), &recovered_length) ==
           GOODIX_SEAL_OK);
    assert(recovered_length == sizeof(plain));
    assert(memcmp(recovered, plain, sizeof(plain)) == 0);

    assert(goodix_seal_unwrap(other, sealed, sealed_length, recovered,
                              sizeof(recovered), &recovered_length) ==
           GOODIX_SEAL_FORGED);
    sealed[GOODIX_SEAL_HEADER_SIZE] ^= 1;
    assert(goodix_seal_unwrap(key, sealed, sealed_length, recovered,
                              sizeof(recovered), &recovered_length) ==
           GOODIX_SEAL_FORGED);
    assert(goodix_seal_unwrap(key, plain, sizeof(plain), recovered,
                              sizeof(recovered), &recovered_length) ==
           GOODIX_SEAL_FORGED);
}

/* Reproduce every s1 XOF byte using only a 256-bit chaining state and
 * the last 11 bytes of a known test seed. This is a stream reconstruction
 * check, not an unknown-key recovery or a collision search.
 *
 * Compile against a Reference_Implementation or Optimized_Implementation
 * profile, with both the profile root and its utils directory on the
 * include path. auxfunc.c is included here; do not link it separately.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define RRLWR_HASH_DOMAIN_XOF
#define RRLWR_HASH_DOMAIN_XOF_SECRET_SINGLE
#include "hash_domain.h"
#include "auxfunc.c"

static void from_descriptor(uint8_t out[32], const unsigned int state[8],
                            const uint8_t tail[11], uint8_t poly_index,
                            uint32_t counter)
{
    uint8_t block[64] = {0};
    unsigned int working[8];
    const uint64_t total_bits = 145u * 8u;
    memcpy(working, state, sizeof(working));
    memcpy(block, tail, 11);
    block[11] = poly_index;
    block[12] = 0; /* secret coefficient expansion uses lane zero */
    for (unsigned int j = 0; j < 4; ++j)
        block[13 + j] = (uint8_t)(counter >> (24 - 8*j));
    block[17] = 0x80;
    for (unsigned int j = 0; j < 8; ++j)
        block[56 + j] = (uint8_t)(total_bits >> (56 - 8*j));
    sm3_bit_compress(working, block, 1);
    for (unsigned int j = 0; j < 32; ++j)
        out[j] = (uint8_t)(working[j/4] >> (24 - 8*(j%4)));
}

int main(void)
{
    enum { OUTLEN = (RRLWR_SIGN_LOG_ETA + 1) * (RRLWR_N / 8) };
    uint8_t seed[RRLWR_SIGN_RHOPRIME_LEN];
    uint8_t input[256], common_prefix[128], actual[OUTLEN], rebuilt[OUTLEN];
    uint8_t tail[11];
    unsigned int state[8];
    assert(sizeof(unsigned int) == 4 && sizeof(seed) == 128);
    assert(OUTLEN % 32 == 0);
    for (size_t j = 0; j < sizeof(seed); ++j)
        seed[j] = (uint8_t)(13*j + 7);
    memcpy(tail, seed + 117, sizeof(tail));
    for (unsigned int index = 0; index < RRLWR_K; ++index) {
        size_t length = RRLWR_DOMAIN_ENCODE_XOF_SECRET(
            input, OUTLEN, seed, sizeof(seed), (uint8_t)index, 0);
        assert(length == 141);
        assert(memcmp(input + 128, tail, 11) == 0);
        assert(input[139] == index && input[140] == 0);
        if (index == 0) {
            memcpy(common_prefix, input, sizeof(common_prefix));
            sm3_bit_init(state);
            sm3_bit_compress(state, common_prefix, 2);
        } else {
            assert(memcmp(common_prefix, input, sizeof(common_prefix)) == 0);
        }
        RRLWR_XOF_SECRET_DOMAIN(actual, OUTLEN, seed, sizeof(seed),
                                (uint8_t)index, 0);
        for (unsigned int block = 0; block < OUTLEN/32; ++block)
            from_descriptor(rebuilt + 32*block, state, tail,
                            (uint8_t)index, block + 1);
        assert(memcmp(actual, rebuilt, sizeof(actual)) == 0);
    }
    printf("level=%d polynomials=%d bytes_per_polynomial=%d "
           "descriptor_bits=344 all_stream_bytes_match=true\n",
           RRLWR_SECURITY_LEVEL, RRLWR_K, OUTLEN);
    return 0;
}

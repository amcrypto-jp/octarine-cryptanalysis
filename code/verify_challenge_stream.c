/* Compare Algorithm 2's sign-stream request with the shipped request.
 * Build separately against each Reference_Implementation/Octarine-* tree.
 * This uses an all-zero public challenge seed and the supplied SM3 code.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define RRLWR_HASH_DOMAIN_SAMPLE_C
#include "hash_domain.h"

static void print_hex(const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; ++i)
        printf("%02x", data[i]);
}

int main(void)
{
    const size_t specified = (RRLWR_SIGN_TAU + 7) / 8;
    uint8_t seed[RRLWR_SIGN_CTILDE_LEN] = {0};
    uint8_t pdf[RRLWR_SIGN_MAX_TAU_BYTES] = {0};
    uint8_t code[RRLWR_SIGN_MAX_TAU_BYTES] = {0};
    unsigned int different_bits = 0;

    RRLWR_SIGN_HASH_SAMPLE_C_DOMAIN(pdf, specified, seed, 0, 0);
    RRLWR_SIGN_HASH_SAMPLE_C_DOMAIN(code, sizeof(code), seed, 0, 0);
    for (unsigned int i = 0; i < RRLWR_SIGN_TAU; ++i)
        different_bits += ((pdf[i / 8] ^ code[i / 8]) >> (i % 8)) & 1u;

    printf("level=%d tau=%d seed=all-zero\n", RRLWR_SECURITY_LEVEL,
           RRLWR_SIGN_TAU);
    printf("specified_bytes=%zu shipped_bytes=%zu\n", specified, sizeof(code));
    printf("specified_stream=");
    print_hex(pdf, specified);
    printf("\nshipped_prefix=");
    print_hex(code, specified);
    printf("\ndifferent_used_sign_bits=%u\n", different_bits);
    if (specified == sizeof(code))
        assert(different_bits == 0);
    else
        assert(different_bits > 0);
    return 0;
}

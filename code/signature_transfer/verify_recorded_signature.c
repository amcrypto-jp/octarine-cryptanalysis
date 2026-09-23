/* Verify a recorded reduced-state campaign using only public artifacts.
 * Build with Octarine-256 reference sources and the generated 48-bit hash.
 * Usage: verifier pk.bin signature.bin M0.bin M1.bin M2.bin
 * No key generation or signing call is made by this driver.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parameters.h"
#include "sign.h"
#include "auxfunc_reduced.c"

#if OCTARINE_STATE_BITS != 48
#error "The recorded signature must be checked under the 48-bit variant."
#endif

DRNG_ctx drng_algorithm; /* Required by the linked sign.c; unused here. */

static void load_exact(const char *path, unsigned char *buffer, size_t size)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fread(buffer, 1, size, file) != size || fgetc(file) != EOF) {
        fprintf(stderr, "Unexpected artifact size or read failure: %s\n", path);
        exit(2);
    }
    fclose(file);
}

int main(int argc, char **argv)
{
    if (argc != 6) return 2;
    size_t pk_len = sig_get_pk_len_bytes();
    size_t sig_len = sig_get_sn_len_bytes();
    unsigned char *pk = malloc(pk_len), *sig = malloc(sig_len);
    unsigned char m0[120], m1[120], m2[120];
    if (!pk || !sig) return 2;
    load_exact(argv[1], pk, pk_len);
    load_exact(argv[2], sig, sig_len);
    load_exact(argv[3], m0, sizeof m0);
    load_exact(argv[4], m1, sizeof m1);
    load_exact(argv[5], m2, sizeof m2);

    int v0 = sig_verify(pk, pk_len, sig, sig_len, m0, sizeof m0);
    int v1 = sig_verify(pk, pk_len, sig, sig_len, m1, sizeof m1);
    int v2 = sig_verify(pk, pk_len, sig, sig_len, m2, sizeof m2);
    sig[0] ^= 1;
    int corrupted = sig_verify(pk, pk_len, sig, sig_len, m0, sizeof m0);
    sig[0] ^= 1;
    int truncated = sig_verify(pk, pk_len, sig, 9, m0, sizeof m0);
    int ok = memcmp(m0, m1, sizeof m0) != 0 && v0 == 0 && v1 == 0 &&
             v2 != 0 && corrupted != 0 && truncated != 0;
    printf("{\n  \"state_bits\": 48,\n  \"signature_bytes\": %zu,\n"
           "  \"uses_signing_key\": false,\n  \"additional_signing_queries\": 0,\n"
           "  \"verify_M0_rc\": %d,\n  \"verify_M1_rc\": %d,\n"
           "  \"verify_M2_rc\": %d,\n  \"verify_corrupted_full_length_rc\": %d,\n"
           "  \"verify_truncated_rc\": %d,\n  \"all_controls_passed\": %s\n}\n",
           sig_len, v0, v1, v2, corrupted, truncated, ok ? "true" : "false");
    free(pk);
    free(sig);
    return ok ? 0 : 1;
}

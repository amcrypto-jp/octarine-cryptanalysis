/* Build: gcc -O2 -std=c99 -I<utils> verify_sm3_reduced_collision.c -o verify_sm3_reduced_collision
   This translation unit includes auxfunc.c; do not link a second copy.

   Replays Mendel, Nad, Schlaeffer, "Finding Collisions for Round-Reduced
   SM3", CT-RSA 2013, Section 5.1, Table 3: the two blocks m1 and m1* from h1.
   DOI: https://doi.org/10.1007/978-3-642-36095-4_12

   compress_steps is an ADAPTATION of the submitted sm3_bit_compress:
   the same expansion, round operations and XOR feed-forward, with an
   adjustable step count and a rotation helper defined also at count zero.
   Its 64-step results are checked against the unmodified submitted function.
   The submitted function itself always executes 64 steps.

   The starting chaining state h1 is supplied, not reached from the standard
   SM3 IV or Octarine's H_mu domain/public-key prefix. The pair does not
   collide under the submitted 64-step function. No signature operation is run.
*/
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auxfunc.c"

#if UINT_MAX != 0xffffffffU
#error "This check, like the submitted utility, requires 32-bit unsigned int."
#endif

static void load_words(const char *hex, unsigned int out[8])
{
  if (strlen(hex) != 64) exit(2);
  for (int i = 0; i < 8; i++)
    if (sscanf(hex + 8 * i, "%8x", &out[i]) != 1) exit(2);
}

static void load_block(const char *hex, unsigned char out[64])
{
  if (strlen(hex) != 128) exit(2);
  for (int i = 0; i < 64; i++)
    if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1) exit(2);
}

static unsigned int rotate_left(unsigned int x, unsigned int n)
{
  n &= 31;
  return (x << n) | (x >> ((32 - n) & 31));
}

static void compress_steps(unsigned int state[8], const unsigned char block[64], int steps)
{
  unsigned int A, B, C, D, E, F, G, H;
  unsigned int W[68], W_prime[64], SS1, SS2, TT1, TT2;
  int i;
  if (steps < 1 || steps > 64) exit(2);

  for (i = 0; i < 16; i++) {
    W[i] = ((unsigned int)block[4*i] << 24) | ((unsigned int)block[4*i+1] << 16) |
           ((unsigned int)block[4*i+2] << 8) | block[4*i+3];
  }
  for (; i < 68; i++) {
    W[i] = P1(W[i-16] ^ W[i-9] ^ rotate_left(W[i-3], 15)) ^
           rotate_left(W[i-13], 7) ^ W[i-6];
  }
  for (i = 0; i < 64; i++) W_prime[i] = W[i] ^ W[i+4];

  A = state[0]; B = state[1]; C = state[2]; D = state[3];
  E = state[4]; F = state[5]; G = state[6]; H = state[7];
  for (i = 0; i < steps; i++) {
    unsigned int constant = i < 16 ? 0x79cc4519U : 0x7a879d8aU;
    SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(constant, i), 7);
    SS2 = SS1 ^ rotate_left(A, 12);
    if (i < 16) {
      TT1 = FF1(A, B, C) + D + SS2 + W_prime[i];
      TT2 = GG1(E, F, G) + H + SS1 + W[i];
    } else {
      TT1 = FF2(A, B, C) + D + SS2 + W_prime[i];
      TT2 = GG2(E, F, G) + H + SS1 + W[i];
    }
    D = C; C = rotate_left(B, 9); B = A; A = TT1;
    H = G; G = rotate_left(F, 19); F = E; E = P0(TT2);
  }
  state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
  state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

static int matches_submitted_64(const unsigned int state[8], const unsigned char block[64])
{
  unsigned int adapted[8], submitted[8];
  memcpy(adapted, state, sizeof adapted);
  memcpy(submitted, state, sizeof submitted);
  compress_steps(adapted, block, 64);
  sm3_bit_compress(submitted, block, 1);
  return memcmp(adapted, submitted, sizeof adapted) == 0;
}

static const char *yes_no(int condition) { return condition ? "yes" : "no"; }

static void print_state(const char *label, const unsigned int state[8])
{
  printf("%s", label);
  for (int i = 0; i < 8; i++) printf("%08x%s", state[i], i == 7 ? "\n" : "");
}

int main(void)
{
  const char *h1_hex = "5e801aac4b8c7a46c8f346463b2420c197e775aee3a6c39983a05d406a257995";
  const char *m_hex =
    "559654cd8d4f9e948ca64e4ab85d989c8c185880b51caad103eca739be66a265"
    "ca21ab719c3410282c043967d4617038bf6744cad8772f12a58e12c035f4f9f2";
  const char *m_star_hex =
    "559654cd8d1f9e848ca64e5ab85d989c8c185880950cbad103eca739be66a265"
    "ca71ab619c3410282c043967d4617038bf6744cad8772f12a58e12c035f4f9f2";
  const char *h2_hex = "b2033829677c16d2a6de9db9fd898668a9119d20476364d6a0838adc08d3833d";
  unsigned int h0[8], h1[8], h2[8], left[8], right[8];
  unsigned int full_left[8], full_right[8];
  unsigned char m[64], m_star[64], suffix[64] = {0};
  unsigned char digest[32], digest_star[32];
  int differences = 0;

  sm3_bit_init(h0);
  load_words(h1_hex, h1);
  load_words(h2_hex, h2);
  load_block(m_hex, m);
  load_block(m_star_hex, m_star);
  for (int i = 0; i < 64; i++) differences += m[i] != m_star[i];

  puts("source=adapted_sm3_bit_compress_with_submitted_64step_cross_checks");
  puts("reference=Mendel-Nad-Schlaeffer_CT-RSA_2013_Table_3");
  printf("blocks_distinct=%s differing_bytes=%d\n", yes_no(differences > 0), differences);

  memcpy(left, h1, sizeof left);
  memcpy(right, h1, sizeof right);
  compress_steps(left, m, 20);
  compress_steps(right, m_star, 20);
  int equal20 = memcmp(left, right, sizeof left) == 0;
  int published_match = memcmp(left, h2, sizeof left) == 0;
  print_state("state_20=", left);
  printf("states_equal_after_20=%s\n", yes_no(equal20));
  printf("matches_published_h2=%s\n", yes_no(published_match));

  /* This negative control calls the UNMODIFIED, 64-step submitted function. */
  memcpy(full_left, h1, sizeof full_left);
  memcpy(full_right, h1, sizeof full_right);
  sm3_bit_compress(full_left, m, 1);
  sm3_bit_compress(full_right, m_star, 1);
  int equal64 = memcmp(full_left, full_right, sizeof full_left) == 0;
  printf("states_equal_after_64=%s\n", yes_no(equal64));

  /* Padding for one 64-byte block in a custom-IV, 20-step variant.
     The IV is h1, not the standard SM3 IV; this is not Octarine H_mu. */
  suffix[0] = 0x80;
  suffix[62] = 0x02; /* 512 bits, big-endian 64-bit length. */
  int adapter_match = matches_submitted_64(h0, m) &&
                      matches_submitted_64(h1, m) &&
                      matches_submitted_64(h1, m_star) &&
                      matches_submitted_64(h2, suffix);
  printf("adapter_64step_matches_submitted=%s checked_inputs=4\n", yes_no(adapter_match));
  unsigned int padded_left[8], padded_right[8];
  memcpy(padded_left, left, sizeof padded_left);
  memcpy(padded_right, right, sizeof padded_right);
  compress_steps(padded_left, suffix, 20);
  compress_steps(padded_right, suffix, 20);
  int padded_equal = memcmp(padded_left, padded_right, sizeof padded_left) == 0;
  print_state("custom_iv_padded_20step_digest=", padded_left);
  printf("equal_20step_state_plus_identical_suffix_remains_equal=%s\n", yes_no(padded_equal));

  /* Apply BE32(counter) and correct padding to the ACTUAL computed states.
     This is custom-IV, reduced-round expansion of m, without an H_mu prefix.
     Each 68-byte input has length 544 = 0x0220 bits. */
  int equal_counters = 0;
  for (unsigned int counter = 1; counter <= 64; counter++) {
    memset(suffix, 0, sizeof suffix);
    PUT32(suffix, counter);
    suffix[4] = 0x80;
    suffix[62] = 0x02;
    suffix[63] = 0x20;
    memcpy(padded_left, left, sizeof padded_left);
    memcpy(padded_right, right, sizeof padded_right);
    compress_steps(padded_left, suffix, 20);
    compress_steps(padded_right, suffix, 20);
    equal_counters += memcmp(padded_left, padded_right, sizeof padded_left) == 0;
  }
  printf("equal_20step_counter_blocks=%d checked_counters=64\n", equal_counters);

  /* The complete 64-byte messages also differ under submitted full SM3. */
  sm3_bit(m, sizeof(m) * 8ULL, digest);
  sm3_bit(m_star, sizeof(m_star) * 8ULL, digest_star);
  int full_collision = memcmp(digest, digest_star, sizeof digest) == 0;
  int collision = differences == 8 && equal20 && published_match && padded_equal;
  printf("concrete_20step_collision=%s\n", yes_no(collision));
  printf("full_sm3_collision=%s\n", yes_no(full_collision));
  puts("octarine_prefix_reached=no");
  puts("octarine_signature_campaign_executed=no");
  puts("octarine_signature_transferred=no");
  return collision && adapter_match && !equal64 && !full_collision && equal_counters == 64 ? 0 : 1;
}

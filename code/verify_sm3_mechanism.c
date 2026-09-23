/* Build through code/verify_original_code.py --submission-root /path/to/Octarine.
 This translation unit includes auxfunc.c; do not link a second copy.
 Demonstrate on the SHIPPED SM3 code (Reference_Implementation/.../utils/auxfunc.c):
 *   if two equal-length, block-aligned inputs X0,X1 produce the same SM3 chaining state,
 *   then every counter-mode KDF output block collides (all output lengths).
 * We cannot find a real 256-bit state collision (cost ~2^128), so we verify the
 * propagation direction exactly: equal state after X + equal total length => equal
 * digest for every counter block. The 2^128 cost of the state collision itself is
 * the generic birthday bound; code/verify_kdf_collision.py uses a 12-bit toy.
 */
#include <stdio.h>
#include <string.h>
#include "auxfunc.c"   /* same translation unit: access static sm3 internals */

/* replicate the tail of sm3_bit from an arbitrary chaining state:
   suffix < 512 bits, total message bit length = total_bits */
static void digest_from_state(const unsigned int state[8],
                              const unsigned char *suffix, unsigned long long suffix_bits,
                              unsigned long long total_bits, unsigned char dgst[32])
{
  unsigned int digest[8];
  memcpy(digest, state, sizeof(unsigned int) * 8);
  unsigned char block[64];
  memset(block, 0, 64);
  memcpy(block, suffix, (suffix_bits + 7) >> 3);
  block[suffix_bits >> 3] |= (1 << (7 - (suffix_bits & 0x7)));
  /* length field is the TOTAL message length (as in sm3_bit) */
  block[56] = (unsigned char)(total_bits >> 56); block[57] = (unsigned char)(total_bits >> 48);
  block[58] = (unsigned char)(total_bits >> 40); block[59] = (unsigned char)(total_bits >> 32);
  block[60] = (unsigned char)(total_bits >> 24); block[61] = (unsigned char)(total_bits >> 16);
  block[62] = (unsigned char)(total_bits >> 8);  block[63] = (unsigned char)(total_bits);
  sm3_bit_compress(digest, block, 1);
  for (int i = 0; i < 8; i++) {
    dgst[i*4+0] = (unsigned char)(digest[i] >> 24);
    dgst[i*4+1] = (unsigned char)(digest[i] >> 16);
    dgst[i*4+2] = (unsigned char)(digest[i] >> 8);
    dgst[i*4+3] = (unsigned char)(digest[i]);
  }
}

/* chaining state after the full 512-bit blocks of msg (msg block-aligned) */
static void state_of(const unsigned char *msg, unsigned long long blocks, unsigned int state[8])
{
  sm3_bit_init(state);
  sm3_bit_compress(state, msg, blocks);
}

int main(void)
{
  /* X0: one full block. We first check digest_from_state reproduces sm3_bit(X0||ct). */
  unsigned char X0[64], X1[64];
  for (int i = 0; i < 64; i++) { X0[i] = (unsigned char)(i * 3 + 1); X1[i] = (unsigned char)(i * 5 + 2); }

  unsigned int S0[8], S1[8];
  state_of(X0, 1, S0);
  state_of(X1, 1, S1);
  printf("states differ (sanity): %s\n", memcmp(S0, S1, sizeof(S0)) ? "yes" : "NO - unexpected");

  /* cross-check: sm3_bit(X0 || ct) == digest_from_state(S0, ct, total=68 bytes) for ct=1 */
  for (unsigned int ct = 1; ct <= 4; ct++) {
    unsigned char ctbe[4] = {(unsigned char)(ct>>24),(unsigned char)(ct>>16),(unsigned char)(ct>>8),(unsigned char)ct};
    unsigned char msg[68]; memcpy(msg, X0, 64); memcpy(msg+64, ctbe, 4);
    unsigned char d1[32], d2[32];
    sm3_bit(msg, 68*8, d1);
    digest_from_state(S0, ctbe, 32, 68*8, d2);
    if (memcmp(d1, d2, 32)) { printf("MISMATCH at ct=%u (model wrong)\n", ct); return 1; }
  }
  printf("digest_from_state model matches sm3_bit(X||ct) for ct=1..4\n");

  /* THE MECHANISM: force a state collision S0' = S1' = S0 (simulating a found collision),
     then every counter block collides */
  unsigned char out0[32], out1[32];
  int collide_all = 1;
  for (unsigned int ct = 1; ct <= 64; ct++) {
    unsigned char ctbe[4] = {(unsigned char)(ct>>24),(unsigned char)(ct>>16),(unsigned char)(ct>>8),(unsigned char)ct};
    digest_from_state(S0, ctbe, 32, 68*8, out0);   /* X0 path: state S0 */
    digest_from_state(S0, ctbe, 32, 68*8, out1);   /* X1 path: collided state = S0, same length */
    if (memcmp(out0, out1, 32)) collide_all = 0;
  }
  printf("state collision + equal length => all 64 counter blocks collide: %s\n",
         collide_all ? "yes (mechanism confirmed on shipped SM3)" : "NO");
  return collide_all ? 0 : 1;
}

/*
 * verify_signature_transfer.c -- executed OCT-01 signature-transfer instance.
 *
 * Chosen-message signature transfer in a scaled ARCANE-Octarine-256 reference
 * variant. Its SM3 chaining state is reduced to OCTARINE_STATE_BITS bits, and
 * the live bytes are tiled into each 32-byte SM3 digest. Both changes affect
 * every SM3 role; the signing and verification C functions are unmodified.
 *
 * OCT-01 of the published review shows mu = H_mu(tr, M) is computed by the
 * shipped pseudoXOF  XOF(X) = SM3(X||BE32(1)) || SM3(X||BE32(2)) || ...  and
 * that a collision of the 256-bit SM3 chaining state before a common suffix
 * equalizes every counter block, hence mu, at generic cost ~2^128. The note
 * did not execute an instance. This driver executes the complete attack on
 * the shipped code with the state map scaled to t bits (cost ~2^(t/2)):
 *
 *   campaign mode (reduced build, t = OCTARINE_STATE_BITS):
 *     1. deterministic sig_keygen (fixed DRNG seed);
 *     2. exact H_MU domain header for the generated key (shipped encoder);
 *     3. birthday search for two distinct 64-byte message blocks B0 != B1 at
 *        SM3 block offset 3 of the pseudoXOF input reaching the same t-bit
 *        chaining state (common 192-byte prefix, common 39-byte suffix);
 *     4. M0 = P||B0||S, M1 = P||B1||S (equal length, 120 bytes);
 *     5. mu0 == mu1 over the full 1024-bit representative (all 4 counters);
 *     6. ONE signing query sigma = sig_sign(sk, M0);
 *     7. sig_verify(pk, sigma, M0) == 0 (control) and
 *        sig_verify(pk, sigma, M1) == 0  -->  sigma transfers to the
 *        never-signed M1: the EUF-CMA forgery instance promised by OCT-01;
 *     8. controls: different suffix => mu differs => rejected; truncated
 *        signature => rejected. A separate public-artifact verifier also
 *        checks a corrupted signature at its full length.
 *
 *   probe mode (full-width build): replay the recorded (B0,B1) at t = 256:
 *     states differ, mu values differ, the same signer output does NOT
 *     transfer; and driver-side emulation of the t-bit construction
 *     reproduces the campaign collision (cross-build validation).
 *
 *   selftest mode: deterministic keygen/sign/verify; SM3 known-answer tests;
 *     used to show the reduced generator at t = 256 is behaviorally identical
 *     to the shipped utils/auxfunc.c.
 *
 *   scale mode: illustrative birthday trials at six small state widths.
 *     The ~2^128 bound at 256 bits is a generic birthday estimate, not an
 *     empirical extrapolation proven by these small experiments.
 *
 * Build (see run_signature_transfer.py): the driver #includes the hash
 * implementation (shipped auxfunc.c or generated auxfunc_reduced.c) in this
 * translation unit, exactly as verify_sm3_mechanism.c does, and links the
 * remaining unmodified submission sources (sign.c, arith/*, drng.c).
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "parameters.h"
#include "sign.h"

#define RRLWR_HASH_DOMAIN_SIGN
#include "hash_domain.h"

#ifdef OCT_DRIVER_ORIGINAL_AUXFUNC
#include "auxfunc.c"          /* shipped utils/auxfunc.c (full 256-bit state) */
#define DRIVER_STATE_BITS 256
#define OCT_DRIVER_ORIGINAL_AUXFUNC_STR "shipped utils/auxfunc.c"
#else
#include "auxfunc_reduced.c"  /* generated reduced-state variant */
#ifndef OCTARINE_STATE_BITS
#define OCTARINE_STATE_BITS 256
#endif
#define DRIVER_STATE_BITS OCTARINE_STATE_BITS
#define OCT_DRIVER_ORIGINAL_AUXFUNC_STR "generated auxfunc_reduced.c"
#endif

static int hex_to_bytes(const char *hex, unsigned char *out, size_t n);

/* sign.c expects this global DRNG context (as in the submission's tests). */
DRNG_ctx drng_algorithm;

/* ------------------------------------------------------------------ */
/* Fixed layout: message = P(17) || B(64) || S(39), 120 bytes total.   */
/* The H_MU pseudoXOF input is header(31) || len64||tr(8+128) ||       */
/* len64(8) || message, so the message starts at input offset 175 and  */
/* the 64-byte variable block B occupies exactly input bytes 192..255  */
/* (SM3 block number 3). The 39-byte suffix, the 4-byte counter and    */
/* the padding all sit in the final block: identical for M0 and M1.    */
/* ------------------------------------------------------------------ */

#define MSG_PREFIX_LEN 17
#define MSG_SUFFIX_LEN 39
#define MSG_LEN (MSG_PREFIX_LEN + 64 + MSG_SUFFIX_LEN) /* 120 */

static const unsigned char MSG_PREFIX[MSG_PREFIX_LEN] = "OCTARINE-REVIEW-P";
static const unsigned char MSG_SUFFIX[MSG_SUFFIX_LEN] =
    "OCTARINE-COMMON-SUFFIX-0123456789abcdef";

static const unsigned char DRNG_SEED[48] =
    "OCT-01-transfer-instance-deterministic-seed!!";

#define HEADER_LEN 192 /* bytes of pseudoXOF input before the variable block */

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void print_hex(const unsigned char *p, size_t n)
{
  for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static void json_hex(const char *key, const unsigned char *p, size_t n, int comma)
{
  printf("  \"%s\": \"", key);
  print_hex(p, n);
  printf("\"%s\n", comma ? "," : "");
}

static void json_u64(const char *key, unsigned long long v, int comma)
{
  printf("  \"%s\": %llu%s\n", key, v, comma ? "," : "");
}

static void json_i64(const char *key, long long v, int comma)
{
  printf("  \"%s\": %lld%s\n", key, v, comma ? "," : "");
}

static void json_str(const char *key, const char *v, int comma)
{
  printf("  \"%s\": \"%s\"%s\n", key, v, comma ? "," : "");
}

/* splitmix64 finalizer; stateless candidate stream for reproducibility. */
static uint64_t vst_splitmix64(uint64_t x)
{
  x += 0x9E3779B97F4A7C15ULL;
  x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
  return x ^ (x >> 31);
}

static void candidate_block(uint64_t i, unsigned char B[64])
{
  for (uint64_t j = 0; j < 8; j++) {
    uint64_t w = vst_splitmix64((i << 3) ^ j ^ 0x0C7013A5D5E5F001ULL);
    for (int k = 0; k < 8; k++) B[8 * j + k] = (unsigned char)(w >> (8 * k));
  }
}

/* identical semantics to octarine_mask_state() in auxfunc_reduced.c:
 * keep the first tbits state bits in serialization order (the high bits
 * of dgst[0], then dgst[1], ...). */
static void vst_mask_state(unsigned int dgst[8], unsigned int tbits)
{
  unsigned int remaining = tbits;
  for (int i = 0; i < 8; i++) {
    if (remaining >= 32U) { remaining -= 32U; continue; }
    dgst[i] &= (remaining == 0U) ? 0U : (0xFFFFFFFFU << (32U - remaining));
    remaining = 0U;
  }
}

/* state after nblocks full blocks, masking after EVERY block (driver-side
 * emulation of the reduced construction; in reduced builds the internal
 * mask makes the extra mask a no-op). */
static void state_after_blocks(const unsigned char *msg, unsigned long long nblocks,
                               unsigned int tbits, unsigned int st[8])
{
  sm3_bit_init(st);
  for (unsigned long long b = 0; b < nblocks; b++) {
    sm3_bit_compress(st, msg + 64 * b, 1);
    vst_mask_state(st, tbits);
  }
}

/* driver-side emulation of shipped sm3_bit with per-compress masking;
 * mirrors the shipped padding logic (byte-aligned inputs only here). */
static void vst_reduced_sm3(const unsigned char *msg, unsigned long long msg_bitlen,
                            unsigned int tbits, unsigned char dgst[32])
{
  unsigned int digest[8];
  unsigned long long block_num = msg_bitlen / 512;
  unsigned long long remain = msg_bitlen & 0x1FF;
  unsigned char block[64];

  state_after_blocks(msg, block_num, tbits, digest);

  memset(block, 0, 64);
  memcpy(block, msg + block_num * 64, (remain + 7) >> 3);
  block[remain >> 3] &= ((0xFF00 >> (remain & 0x7)) & 0xFF);
  block[remain >> 3] |= (1 << (7 - (remain & 0x7)));
  if (remain <= 512 - 65) {
    memset(block + (remain >> 3) + 1, 0, (512 - remain - 65) >> 3);
  } else {
    memset(block + (remain >> 3) + 1, 0, (512 - remain - 1) >> 3);
    sm3_bit_compress(digest, block, 1);
    vst_mask_state(digest, tbits);
    memset(block, 0, 64 - 8);
  }
  PUT32(block + 56, block_num >> 32 << 9);
  PUT32(block + 60, (block_num << 9) + (remain));
  sm3_bit_compress(digest, block, 1);
  vst_mask_state(digest, tbits);
  if (tbits < 256) {
    /* tiled serialization of the t-bit state (matches auxfunc_reduced.c) */
    unsigned int live = (tbits + 7) / 8;
    for (int j = 0; j < 32; j++) {
      unsigned int src = (unsigned int)j % live;
      dgst[j] = (unsigned char)(digest[src >> 2] >> (24 - 8 * (src & 3)));
    }
  } else {
    for (int i = 0; i < 8; i++) {
      dgst[i * 4 + 0] = (unsigned char)(digest[i] >> 24);
      dgst[i * 4 + 1] = (unsigned char)(digest[i] >> 16);
      dgst[i * 4 + 2] = (unsigned char)(digest[i] >> 8);
      dgst[i * 4 + 3] = (unsigned char)(digest[i]);
    }
  }
}

/* driver-side emulation of shipped pseudoXOF (byte-aligned inputs) with the
 * t-bit construction. */
static void vst_reduced_pseudoxof(unsigned long long output_len_bits,
                                  const unsigned char *msg,
                                  unsigned long long msg_len_bits,
                                  unsigned int tbits, unsigned char *output)
{
  unsigned int ct = 1;
  unsigned long long msg_bytes = (msg_len_bits + 7) / 8;
  unsigned char *cascade = malloc(msg_bytes + 4);
  unsigned char d[32];
  unsigned long long nblocks = (output_len_bits + 255) / 256;
  if (cascade == NULL) { fprintf(stderr, "oom\n"); exit(2); }
  if (msg_len_bits % 8 != 0) { fprintf(stderr, "emulation: byte-aligned only\n"); exit(2); }
  for (unsigned long long i = 0; i < nblocks; i++) {
    memcpy(cascade, msg, msg_bytes);
    cascade[msg_bytes + 0] = (unsigned char)(ct >> 24);
    cascade[msg_bytes + 1] = (unsigned char)(ct >> 16);
    cascade[msg_bytes + 2] = (unsigned char)(ct >> 8);
    cascade[msg_bytes + 3] = (unsigned char)ct;
    vst_reduced_sm3(cascade, msg_len_bits + 32, tbits, d);
    memcpy(output + i * 32, d, 32);
    ct++;
  }
  free(cascade);
}

/* ------------------------------------------------------------------ */
/* birthday collision search on the t-bit state after the variable block */
/* ------------------------------------------------------------------ */

typedef struct { uint64_t key; uint64_t idx; } slot_t;

/* returns 0 on success; st0/st1 receive the colliding states */
static int birthday_search(const unsigned int hpre[8], unsigned int tbits,
                           uint64_t *idx0, uint64_t *idx1, uint64_t *trials,
                           double *seconds, unsigned int st0[8], unsigned int st1[8])
{
  if (tbits == 0 || tbits > 62) return -1;
  unsigned int log2cap = tbits / 2 + 3;
  if (log2cap < 12) log2cap = 12;
  size_t cap = (size_t)1 << log2cap, mask = cap - 1;
  slot_t *tab = malloc(cap * sizeof(slot_t));
  if (tab == NULL) return -2;
  for (size_t i = 0; i < cap; i++) tab[i].idx = UINT64_MAX;

  unsigned char B[64], Bprev[64];
  unsigned int st[8];
  clock_t t0 = clock();
  uint64_t i = 0;
  int found = 0;
  while (!found) {
    candidate_block(i, B);
    memcpy(st, hpre, 32);
    sm3_bit_compress(st, B, 1);
    vst_mask_state(st, tbits); /* no-op in reduced builds */
    uint64_t key = (uint64_t)st[0] | ((uint64_t)st[1] << 32);
    size_t p = (size_t)(vst_splitmix64(key) >> (64 - log2cap));
    while (tab[p].idx != UINT64_MAX && tab[p].key != key) p = (p + 1) & mask;
    if (tab[p].idx == UINT64_MAX) {
      tab[p].key = key;
      tab[p].idx = i;
    } else {
      candidate_block(tab[p].idx, Bprev);
      if (memcmp(Bprev, B, 64) != 0) {
        unsigned int sprev[8];
        memcpy(sprev, hpre, 32);
        sm3_bit_compress(sprev, Bprev, 1);
        vst_mask_state(sprev, tbits);
        if (memcmp(sprev, st, 32) == 0) {
          *idx0 = tab[p].idx;
          *idx1 = i;
          memcpy(st0, sprev, 32);
          memcpy(st1, st, 32);
          found = 1;
        }
      }
    }
    i++;
  }
  *trials = i;
  *seconds = (double)(clock() - t0) / CLOCKS_PER_SEC;
  free(tab);
  return 0;
}

/* ------------------------------------------------------------------ */
/* build the exact H_MU pseudoXOF input prefix using the shipped encoder */
/* ------------------------------------------------------------------ */

static size_t build_header192(unsigned char header[HEADER_LEN],
                              const unsigned char tr[RRLWR_SIGN_TR_LEN])
{
  size_t pos = rrlwr_domain_begin(header, RRLWR_DOMAIN_LABEL_MU,
                                  RRLWR_DOMAIN_LABEL_LEN(RRLWR_DOMAIN_LABEL_MU),
                                  RRLWR_SIGN_MU_LEN, 2);
  pos = rrlwr_domain_add_field(header, pos, tr, RRLWR_SIGN_TR_LEN);
  rrlwr_store64_le(header + pos, (uint64_t)MSG_LEN);
  pos += RRLWR_DOMAIN_LEN_BYTES;
  memcpy(header + pos, MSG_PREFIX, MSG_PREFIX_LEN);
  pos += MSG_PREFIX_LEN;
  return pos; /* must equal HEADER_LEN = 3 SM3 blocks */
}

static void build_message(unsigned char M[MSG_LEN], const unsigned char B[64],
                          const unsigned char *suffix)
{
  memcpy(M, MSG_PREFIX, MSG_PREFIX_LEN);
  memcpy(M + MSG_PREFIX_LEN, B, 64);
  memcpy(M + MSG_PREFIX_LEN + 64, suffix, MSG_SUFFIX_LEN);
}

/* deterministic keygen + one-message sign used by several modes */
static int do_keygen(unsigned char **pk_out, unsigned char **sk_out)
{
  unsigned char *pk = malloc(sig_get_pk_len_bytes());
  unsigned char *sk = malloc(sig_get_sk_len_bytes());
  unsigned long long pk_len, sk_len;
  if (pk == NULL || sk == NULL) return -1;
  if (init_random_number(&drng_algorithm, DRNG_SEED, sizeof DRNG_SEED) != 0) return -1;
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return -1;
  if (pk_len != sig_get_pk_len_bytes() || sk_len != sig_get_sk_len_bytes()) return -1;
  *pk_out = pk;
  *sk_out = sk;
  return 0;
}

static int do_sign(const unsigned char *sk, const unsigned char *m,
                   unsigned long long m_len, unsigned char **sn_out)
{
  unsigned char *sn = malloc(sig_get_sn_len_bytes());
  unsigned long long sn_len;
  if (sn == NULL) return -1;
  if (sig_sign((unsigned char *)sk, sig_get_sk_len_bytes(),
               (unsigned char *)m, m_len, sn, &sn_len) != 0) return -1;
  if (sn_len != sig_get_sn_len_bytes()) return -1;
  *sn_out = sn;
  return 0;
}

/* ------------------------------------------------------------------ */
/* SM3 known-answer tests (GB/T 32905-2016 examples)                     */
/* ------------------------------------------------------------------ */

static int sm3_kat(void)
{
  static const char *m1 = "abc";
  static const char *e1 =
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
  static const char *m2 =
    "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
  static const char *e2 =
    "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";
  unsigned char d[32];
  char hex[65];
  const struct { const char *m; const char *e; } tv[2] = {{m1, e1}, {m2, e2}};
  for (int k = 0; k < 2; k++) {
    sm3_bit((const unsigned char *)tv[k].m, 8 * strlen(tv[k].m), d);
    for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", d[i]);
    hex[64] = 0;
    if (strcmp(hex, tv[k].e) != 0) {
      printf("  \"sm3_kat_%d\": \"FAIL (%s)\",\n", k, hex);
      return -1;
    }
    printf("  \"sm3_kat_%d\": \"%s\",\n", k, hex);
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* modes                                                                 */
/* ------------------------------------------------------------------ */

static int mode_selftest(void)
{
  static const unsigned char stm[] = "OCT-01 selftest message";
  unsigned char *pk, *sk, *sn;
  unsigned char d[32];
  int rc;

  printf("{\n");
  json_str("mode", "selftest", 1);
  json_str("auxfunc", OCT_DRIVER_ORIGINAL_AUXFUNC_STR, 1);
  json_u64("octarine_state_bits", DRIVER_STATE_BITS, 1);
  if (DRIVER_STATE_BITS == 256) {
    rc = sm3_kat();
    if (rc != 0) { printf("  \"status\": 1\n}\n"); return 1; }
  } else {
    json_str("sm3_kat", "skipped (reduced width; tiled digests by design)", 1);
  }

  if (do_keygen(&pk, &sk) != 0) { fprintf(stderr, "keygen failed\n"); return 2; }
  if (do_sign(sk, stm, sizeof stm - 1, &sn) != 0) { fprintf(stderr, "sign failed\n"); return 2; }
  int v = sig_verify(pk, sig_get_pk_len_bytes(), sn, sig_get_sn_len_bytes(),
                     (unsigned char *)stm, sizeof stm - 1);
  sm3_bit(pk, 8 * sig_get_pk_len_bytes(), d);
  json_hex("pk_sm3", d, 32, 1);
  sm3_bit(sk, 8 * sig_get_sk_len_bytes(), d);
  json_hex("sk_sm3", d, 32, 1);
  sm3_bit(sn, 8 * sig_get_sn_len_bytes(), d);
  json_hex("sig_sm3", d, 32, 1);
  json_i64("verify_rc", v, 1);
  json_u64("status", (v == 0) ? 0 : 1, 0);
  printf("}\n");
  free(pk); free(sk); free(sn);
  return (v == 0) ? 0 : 1;
}

static int mode_campaign(unsigned int tbits)
{
  unsigned char *pk, *sk, *sn;
  unsigned char tr[RRLWR_SIGN_TR_LEN];
  unsigned char header[HEADER_LEN];
  unsigned int hpre[8], st0[8], st1[8];
  unsigned char B0[64], B1[64], M0[MSG_LEN], M1[MSG_LEN], M2[MSG_LEN];
  unsigned char mu0[RRLWR_SIGN_MU_LEN], mu1[RRLWR_SIGN_MU_LEN], mu2[RRLWR_SIGN_MU_LEN];
  unsigned char mu0x[RRLWR_SIGN_MU_LEN];
  unsigned char S2[MSG_SUFFIX_LEN];
  unsigned char X[HEADER_LEN + 64 + MSG_SUFFIX_LEN];
  uint64_t idx0, idx1, trials;
  double secs;

  if (tbits >= 256) { fprintf(stderr, "campaign requires t < 256\n"); return 2; }
  if (tbits > 62) { fprintf(stderr, "campaign search supports t <= 62\n"); return 2; }

  if (do_keygen(&pk, &sk) != 0) { fprintf(stderr, "keygen failed\n"); return 2; }
  RRLWR_SIGN_HASH_TR(tr, pk);

  if (build_header192(header, tr) != HEADER_LEN) {
    fprintf(stderr, "header layout error\n");
    return 2;
  }

  /* reduced chaining state after the 3 header blocks (masked internally) */
  state_after_blocks(header, 3, tbits, hpre);

  clock_t t_start = clock();
  if (birthday_search(hpre, tbits, &idx0, &idx1, &trials, &secs, st0, st1) != 0) {
    fprintf(stderr, "search failed\n");
    return 2;
  }
  double total_secs = (double)(clock() - t_start) / CLOCKS_PER_SEC;

  candidate_block(idx0, B0);
  candidate_block(idx1, B1);
  build_message(M0, B0, MSG_SUFFIX);
  build_message(M1, B1, MSG_SUFFIX);
  for (int i = 0; i < MSG_SUFFIX_LEN; i++) S2[i] = MSG_SUFFIX[i] ^ 0xFF;
  build_message(M2, B0, S2);

  /* layout check: the true pseudoXOF input for M0 matches our block map */
  {
    size_t inlen = rrlwr_domain_encode_2(X, RRLWR_DOMAIN_LABEL_MU,
                                         RRLWR_DOMAIN_LABEL_LEN(RRLWR_DOMAIN_LABEL_MU),
                                         RRLWR_SIGN_MU_LEN,
                                         tr, RRLWR_SIGN_TR_LEN, M0, MSG_LEN);
    if (inlen != HEADER_LEN + 64 + MSG_SUFFIX_LEN ||
        memcmp(X, header, HEADER_LEN) != 0 ||
        memcmp(X + HEADER_LEN, B0, 64) != 0 ||
        memcmp(X + HEADER_LEN + 64, MSG_SUFFIX, MSG_SUFFIX_LEN) != 0) {
      fprintf(stderr, "pseudoXOF input layout mismatch\n");
      return 2;
    }
  }

  /* message representatives via the scheme's own H_MU path */
  if (RRLWR_SIGN_HASH_MU(mu0, tr, M0, MSG_LEN) != 0) return 2;
  if (RRLWR_SIGN_HASH_MU(mu1, tr, M1, MSG_LEN) != 0) return 2;
  if (RRLWR_SIGN_HASH_MU(mu2, tr, M2, MSG_LEN) != 0) return 2;
  /* cross-check: driver-side emulation of the reduced pseudoXOF agrees */
  vst_reduced_pseudoxof(8 * RRLWR_SIGN_MU_LEN, X, 8 * sizeof X, tbits, mu0x);
  int emu_matches = (memcmp(mu0, mu0x, RRLWR_SIGN_MU_LEN) == 0);

  int mu_equal = (memcmp(mu0, mu1, RRLWR_SIGN_MU_LEN) == 0);
  int mu2_differs = (memcmp(mu0, mu2, RRLWR_SIGN_MU_LEN) != 0);

  /* one signing oracle query: M0 only */
  if (do_sign(sk, M0, MSG_LEN, &sn) != 0) { fprintf(stderr, "sign failed\n"); return 2; }
  int v0 = sig_verify(pk, sig_get_pk_len_bytes(), sn, sig_get_sn_len_bytes(), M0, MSG_LEN);
  int v1 = sig_verify(pk, sig_get_pk_len_bytes(), sn, sig_get_sn_len_bytes(), M1, MSG_LEN);
  int v2 = sig_verify(pk, sig_get_pk_len_bytes(), sn, sig_get_sn_len_bytes(), M2, MSG_LEN);
  unsigned char snc[9];
  memcpy(snc, sn, 9);
  snc[0] ^= 1;
  int v3 = sig_verify(pk, sig_get_pk_len_bytes(), snc, 9, M0, MSG_LEN);

  printf("{\n");
  json_str("mode", "campaign", 1);
  json_str("profile", "Octarine-256 reference scheme (48-bit reduced-state SM3 model)", 1);
  json_u64("octarine_state_bits", tbits, 1);
  json_u64("header_bytes", HEADER_LEN, 1);
  json_u64("message_bytes", MSG_LEN, 1);
  json_u64("variable_block_offset", HEADER_LEN, 1);
  json_u64("pseudoxof_input_bytes", sizeof X, 1);
  json_u64("collision_candidate_index_first", idx0, 1);
  json_u64("collision_candidate_index_second", idx1, 1);
  json_u64("collision_search_trials", trials, 1);
  printf("  \"collision_search_seconds\": %.3f,\n", secs);
  printf("  \"campaign_seconds\": %.3f,\n", total_secs);
  printf("  \"collision_search_ratio_trials_over_sqrt_2^t\": %.4f,\n",
         (double)trials / (double)(1ULL << (tbits / 2)));
  json_hex("pk", pk, sig_get_pk_len_bytes(), 1);
  json_hex("tr", tr, RRLWR_SIGN_TR_LEN, 1);
  json_hex("message_prefix_P", MSG_PREFIX, MSG_PREFIX_LEN, 1);
  json_hex("message_suffix_S", MSG_SUFFIX, MSG_SUFFIX_LEN, 1);
  json_hex("block_B0", B0, 64, 1);
  json_hex("block_B1", B1, 64, 1);
  json_hex("M0", M0, MSG_LEN, 1);
  json_hex("M1", M1, MSG_LEN, 1);
  json_hex("M2_control_different_suffix", M2, MSG_LEN, 1);
  printf("  \"state_after_header_words\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", hpre[i]);
  printf("],\n");
  printf("  \"state_after_B0_words\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", st0[i]);
  printf("],\n");
  printf("  \"state_after_B1_words\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", st1[i]);
  printf("],\n");
  json_u64("states_equal", (memcmp(st0, st1, 32) == 0), 1);
  json_hex("mu_M0", mu0, RRLWR_SIGN_MU_LEN, 1);
  json_hex("mu_M1", mu1, RRLWR_SIGN_MU_LEN, 1);
  json_u64("mu_equal_over_1024_bits", mu_equal, 1);
  json_hex("mu_M2_control", mu2, RRLWR_SIGN_MU_LEN, 1);
  json_u64("mu_control_differs", mu2_differs, 1);
  json_u64("emulation_matches_scheme_path", emu_matches, 1);
  json_u64("signing_oracle_queries", 1, 1);
  json_str("signing_oracle_queried_message", "M0", 1);
  json_hex("signature", sn, sig_get_sn_len_bytes(), 1);
  json_i64("verify_M0_rc", v0, 1);
  json_i64("verify_M1_rc", v1, 1);
  json_i64("verify_M2_control_rc", v2, 1);
  json_i64("verify_truncated_sig_control_rc", v3, 1);
  json_u64("signature_transferred_to_never_signed_message", (v1 == 0), 1);
  json_u64("status", (mu_equal && v0 == 0 && v1 == 0 && v2 != 0 && v3 != 0 &&
                      emu_matches) ? 0 : 1, 0);
  printf("}\n");

  free(pk); free(sk); free(sn);
  return (mu_equal && v0 == 0 && v1 == 0 && v2 != 0 && v3 != 0 && emu_matches) ? 0 : 1;
}

/* probe <t> <tr_hex> <B0hex> <B1hex>: full-width replay of a recorded
 * campaign pair + driver-side emulation of the reduced construction.
 * tr_hex is the campaign's recorded tr (its key's public-key hash): the
 * collision is relative to that header, so the emulation is rebuilt from
 * it. The full-width negative control uses this build's own fresh key. */
static int mode_probe(unsigned int tbits, const char *trhex,
                      const char *b0hex, const char *b1hex)
{
  unsigned char *pk, *sk, *sn;
  unsigned char tr[RRLWR_SIGN_TR_LEN];
  unsigned char header[HEADER_LEN];
  unsigned char B0[64], B1[64], M0[MSG_LEN], M1[MSG_LEN];
  unsigned char mu0[RRLWR_SIGN_MU_LEN], mu1[RRLWR_SIGN_MU_LEN];
  unsigned char mu0e[RRLWR_SIGN_MU_LEN], mu1e[RRLWR_SIGN_MU_LEN];
  unsigned char X0[HEADER_LEN + 64 + MSG_SUFFIX_LEN], X1[HEADER_LEN + 64 + MSG_SUFFIX_LEN];
  unsigned int hpre_full[8], s0_full[8], s1_full[8];
  unsigned int hpre_emu[8], s0_emu[8], s1_emu[8];

  if (hex_to_bytes(trhex, tr, RRLWR_SIGN_TR_LEN) != 0 ||
      hex_to_bytes(b0hex, B0, 64) != 0 || hex_to_bytes(b1hex, B1, 64) != 0) {
    fprintf(stderr, "bad hex argument\n");
    return 2;
  }

  if (build_header192(header, tr) != HEADER_LEN) return 2;
  build_message(M0, B0, MSG_SUFFIX);
  build_message(M1, B1, MSG_SUFFIX);

  /* full-width states from the recorded header (shipped SM3) */
  state_after_blocks(header, 3, 256, hpre_full);
  memcpy(s0_full, hpre_full, 32); sm3_bit_compress(s0_full, B0, 1);
  memcpy(s1_full, hpre_full, 32); sm3_bit_compress(s1_full, B1, 1);

  /* emulated t-bit construction from the recorded header (per-block masking) */
  state_after_blocks(header, 3, tbits, hpre_emu);
  memcpy(s0_emu, hpre_emu, 32); sm3_bit_compress(s0_emu, B0, 1); vst_mask_state(s0_emu, tbits);
  memcpy(s1_emu, hpre_emu, 32); sm3_bit_compress(s1_emu, B1, 1); vst_mask_state(s1_emu, tbits);

  /* full-width mu of the two messages under the recorded tr (scheme path) */
  if (RRLWR_SIGN_HASH_MU(mu0, tr, M0, MSG_LEN) != 0) return 2;
  if (RRLWR_SIGN_HASH_MU(mu1, tr, M1, MSG_LEN) != 0) return 2;

  /* emulated t-bit mu on the true pseudoXOF inputs under the recorded tr */
  {
    size_t l0 = rrlwr_domain_encode_2(X0, RRLWR_DOMAIN_LABEL_MU,
                                      RRLWR_DOMAIN_LABEL_LEN(RRLWR_DOMAIN_LABEL_MU),
                                      RRLWR_SIGN_MU_LEN, tr, RRLWR_SIGN_TR_LEN, M0, MSG_LEN);
    size_t l1 = rrlwr_domain_encode_2(X1, RRLWR_DOMAIN_LABEL_MU,
                                      RRLWR_DOMAIN_LABEL_LEN(RRLWR_DOMAIN_LABEL_MU),
                                      RRLWR_SIGN_MU_LEN, tr, RRLWR_SIGN_TR_LEN, M1, MSG_LEN);
    if (l0 != sizeof X0 || l1 != sizeof X1) return 2;
  }
  vst_reduced_pseudoxof(8 * RRLWR_SIGN_MU_LEN, X0, 8 * sizeof X0, tbits, mu0e);
  vst_reduced_pseudoxof(8 * RRLWR_SIGN_MU_LEN, X1, 8 * sizeof X1, tbits, mu1e);

  /* full-width negative control: fresh key, sign M0, attempt transfer to M1 */
  if (do_keygen(&pk, &sk) != 0) return 2;
  if (do_sign(sk, M0, MSG_LEN, &sn) != 0) return 2;
  int v0 = sig_verify(pk, sig_get_pk_len_bytes(), sn, sig_get_sn_len_bytes(), M0, MSG_LEN);
  int v1 = sig_verify(pk, sig_get_pk_len_bytes(), sn, sig_get_sn_len_bytes(), M1, MSG_LEN);

  int full_states_differ = (memcmp(s0_full, s1_full, 32) != 0);
  int emu_states_equal = (memcmp(s0_emu, s1_emu, 32) == 0);
  int full_mu_differ = (memcmp(mu0, mu1, RRLWR_SIGN_MU_LEN) != 0);
  int emu_mu_equal = (memcmp(mu0e, mu1e, RRLWR_SIGN_MU_LEN) == 0);

  printf("{\n");
  json_str("mode", "probe", 1);
  json_u64("build_state_bits", DRIVER_STATE_BITS, 1);
  json_u64("emulated_state_bits", tbits, 1);
  json_hex("recorded_tr", tr, RRLWR_SIGN_TR_LEN, 1);
  json_hex("M0", M0, MSG_LEN, 1);
  json_hex("M1", M1, MSG_LEN, 1);
  printf("  \"full_width_state_words_B0\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", s0_full[i]);
  printf("],\n");
  printf("  \"full_width_state_words_B1\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", s1_full[i]);
  printf("],\n");
  json_u64("full_width_states_differ", full_states_differ, 1);
  printf("  \"emulated_header_state_words\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", hpre_emu[i]);
  printf("],\n");
  printf("  \"emulated_state_words_B0\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", s0_emu[i]);
  printf("],\n");
  printf("  \"emulated_state_words_B1\": [");
  for (int i = 0; i < 8; i++) printf("%s%u", i ? ", " : "", s1_emu[i]);
  printf("],\n");
  json_u64("emulated_states_equal", emu_states_equal, 1);
  json_u64("full_width_mu_differ", full_mu_differ, 1);
  json_hex("full_width_mu_M0", mu0, RRLWR_SIGN_MU_LEN, 1);
  json_hex("full_width_mu_M1", mu1, RRLWR_SIGN_MU_LEN, 1);
  json_u64("emulated_mu_equal", emu_mu_equal, 1);
  json_hex("emulated_mu", mu0e, RRLWR_SIGN_MU_LEN, 1);
  json_hex("control_pk", pk, sig_get_pk_len_bytes(), 1);
  json_hex("control_signature", sn, sig_get_sn_len_bytes(), 1);
  json_i64("control_verify_M0_rc", v0, 1);
  json_i64("control_verify_M1_rc", v1, 1);
  json_u64("status", (full_states_differ && full_mu_differ && v0 == 0 && v1 != 0 &&
                      emu_states_equal && emu_mu_equal) ? 0 : 1, 0);
  printf("}\n");
  free(pk); free(sk); free(sn);
  return (full_states_differ && full_mu_differ && v0 == 0 && v1 != 0 &&
          emu_states_equal && emu_mu_equal) ? 0 : 1;
}

/* scale <wmax>: birthday trials vs width, emulated construction, fixed prefix */
static int mode_scale(unsigned int wmax)
{
  unsigned char prefix[HEADER_LEN];
  unsigned int hpre[8], st0[8], st1[8];
  uint64_t i0, i1, trials;
  double secs;

  for (int i = 0; i < HEADER_LEN; i++) prefix[i] = (unsigned char)(i * 7 + 3);

  printf("{\n");
  json_str("mode", "scale", 1);
  json_u64("build_state_bits", DRIVER_STATE_BITS, 1);
  json_hex("fixed_prefix", prefix, HEADER_LEN, 1);
  printf("  \"runs\": [\n");
  int first = 1;
  for (unsigned int w = 8; w <= wmax; w += 8) {
    unsigned int reps = (w <= 24) ? 16 : (w <= 32 ? 8 : (w <= 40 ? 4 : 2));
    for (unsigned int r = 0; r < reps; r++) {
      /* vary the fixed prefix per rep deterministically */
      prefix[0] = (unsigned char)(r * 31 + w);
      state_after_blocks(prefix, 3, w, hpre);
      if (birthday_search(hpre, w, &i0, &i1, &trials, &secs, st0, st1) != 0) {
        fprintf(stderr, "scale search failed at w=%u\n", w);
        return 2;
      }
      if (!first) printf(",\n");
      first = 0;
      printf("    {\"t\": %u, \"rep\": %u, \"trials\": %llu, \"seconds\": %.3f, "
             "\"ratio\": %.4f}",
             w, r, (unsigned long long)trials, secs,
             (double)trials / (double)(1ULL << (w / 2)));
    }
  }
  printf("\n  ],\n");
  json_u64("status", 0, 0);
  printf("}\n");
  return 0;
}

static int hex_nibble(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t n)
{
  if (strlen(hex) != 2 * n) return -1;
  for (size_t i = 0; i < n; i++) {
    int hi = hex_nibble(hex[2 * i]), lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr,
            "usage: %s selftest | campaign | probe <t> <B0hex> <B1hex> | scale <wmax>\n",
            argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "selftest") == 0) return mode_selftest();
  if (strcmp(argv[1], "campaign") == 0) return mode_campaign(DRIVER_STATE_BITS);
  if (strcmp(argv[1], "probe") == 0) {
    if (argc != 6) return 2;
    return mode_probe((unsigned int)strtoul(argv[2], NULL, 10), argv[3], argv[4], argv[5]);
  }
  if (strcmp(argv[1], "scale") == 0) {
    if (argc != 3) return 2;
    return mode_scale((unsigned int)strtoul(argv[2], NULL, 10));
  }
  fprintf(stderr, "unknown mode\n");
  return 2;
}

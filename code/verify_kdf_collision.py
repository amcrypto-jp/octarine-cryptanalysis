#!/usr/bin/env python3
"""Shared-state collision mechanism for a counter-mode KDF over a Merkle-Damgard
hash with a small chaining state (12-bit toy). Run: python3 verify_kdf_collision.py

Demonstrates, on a toy:
  (i)  a collision in the n-bit chaining state is found by birthday search at
       cost ~ 2^{n/2};
  (ii) for equal-length inputs, one state collision collides EVERY counter block,
       hence the full KDF output at every output length.
Consequence for the 256-bit-state SM3 counter-mode KDF (GB/T 32918.4-2016
Sec. 5.4.3, as implemented in the submission's reference/optimized families):
collision resistance is capped at ~2^128 for equal-length inputs, independent
of the requested output length.

Note: the toy compression is deliberately NON-injective in the message block
(the block is masked to the state width). A compression bijective in the block
structurally forbids equal-length state collisions and is not representative.
"""
import require_checks
import random

MASK = (1 << 12) - 1

def cf(h, b):
    h = (h ^ (b & MASK)) & MASK
    h = ((h << 5) | (h >> 7)) & MASK
    h = (h * 0x9E3 + 0x7F5) & MASK
    h ^= h >> 5
    return h & MASK

def md_state(blocks):
    blocks = tuple(blocks)
    h = 0x10F
    for b in blocks:
        h = cf(h, b)
    return h

def md(blocks):
    blocks = tuple(blocks)
    return cf(md_state(blocks), ((len(blocks) & MASK) << 4) | 0x8)

def kdf(blocks, n=64):
    blocks = tuple(blocks)
    return [md(blocks + (j,)) for j in range(1, n + 1)]

def main():
    rng = random.Random(11)
    seen, tries = {}, 0
    while tries < 200000:
        tries += 1
        blk = rng.randrange(1 << 16)
        s = md_state((0xABC, blk))          # common prefix block + one variable block
        if s in seen and seen[s] != blk:
            other = seen[s]
            k0 = kdf((0xABC, other))
            k1 = kdf((0xABC, blk))
            assert k0 == k1
            print(f"state collision after {tries} trials "
                  f"(12-bit toy state; birthday exponent 6)")
            print(f"inputs: prefix=0xABC, blocks {other:#06x} vs {blk:#06x}, state {s:#05x}")
            print(f"all {len(k0)} counter blocks identical: {k0 == k1} "
                  f"({12 * len(k0)} effective output bits)")
            return
        seen[s] = blk
    raise AssertionError("no collision found within cap (unexpected)")

if __name__ == "__main__":
    main()

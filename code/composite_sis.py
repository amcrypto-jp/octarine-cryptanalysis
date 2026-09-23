#!/usr/bin/env python3
"""Run with the Python interpreter in the Sage environment.
This attacks Appendix A's *relaxed SIS*, not Verify.

For q divisible by 4 and A=[B|C|...] with square B,C invertible mod 2:
  u = B_2^-1 C_2 1 (over F_2), interpreted as 0/1 integers;
  d = (Bu+C1)/2 mod 2;
  v = C_2^-1 d;
  w = (u, 1-2v, 0,...).
Then A w = 0 mod 4, and x=(q/4)w is a nonzero SIS solution mod q
with infinity norm q/4. Only binary linear algebra is required.

Uniform random square binary matrices are invertible with probability about
0.2888, so the event for both blocks has probability about 0.0834. That is
already a constant-success attack on the uniform distribution. This script
conditions on that public event to exhibit and independently verify witnesses.
Higher bits of A are irrelevant; random full-modulus lifts are also checked.
"""
import require_checks
import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from sage.all import GF, matrix, vector


def run(n, seed, destination):
    start = time.monotonic()
    rng = np.random.Generator(np.random.PCG64(seed))
    f2 = GF(2)
    square = []
    binary = []
    trials = []
    for _ in range(2):
        count = 0
        while True:
            count += 1
            a = rng.integers(0, 4, size=(n, n), dtype=np.int32)
            a2 = matrix(f2, a & 1)
            if a2.rank() == n:
                square.append(a)
                binary.append(a2)
                trials.append(count)
                break
    b, c = square
    b2, c2 = binary
    one = vector(f2, [1] * n)
    u2 = b2.solve_right(c2 * one)
    u = np.asarray(list(u2), dtype=np.int32)
    even = b @ u + c.sum(axis=1)
    assert not np.any(even % 2)
    rhs = vector(f2, (even // 2) & 1)
    v2 = c2.solve_right(rhs)
    v = np.asarray(list(v2), dtype=np.int32)
    w = np.concatenate((u, 1 - 2 * v))
    residue = b @ w[:n] + c @ w[n:]
    assert not np.any(residue % 4)
    assert np.max(np.abs(w)) == 1
    q = 2**24
    x = w.astype(np.int64) * (q // 4)
    # Verify random full-modulus lifts in small blocks to bound RAM use.
    digest = hashlib.sha256()
    for begin in range(0, n, 128):
        end = min(begin + 128, n)
        low = np.concatenate((b[begin:end], c[begin:end]), axis=1)
        full = low.astype(np.int64) + 4 * rng.integers(
            0, q // 4, size=low.shape, dtype=np.int64)
        digest.update(full.astype('<u4').tobytes())
        assert not np.any((full @ x) % q)
    witness_file = destination / ("sis_witness_%d.npz" % n)
    np.savez_compressed(witness_file, B_mod4=b.astype(np.uint8),
                        C_mod4=c.astype(np.uint8), x=x)
    result = {
        "kind": "relaxed_SIS_counterexample_NOT_a_signature_forgery",
        "q": q, "n": n, "m": 2*n, "also_valid_at_m": 3*n,
        "seed": seed, "invertible_block_sampling_trials": trials,
        "norm_infinity": int(np.max(np.abs(x))),
        "nonzero_coordinates": int(np.count_nonzero(x)),
        "verified_mod4": True, "verified_random_full_q_lift": True,
        "full_q_lift_sha256": digest.hexdigest(),
        "B_EUF_512": 4947969, "B_SUF_512": 4194306,
        "strict_Delta_z_limit_512": 4193956,
        "fits_512_single_bound_SIS": bool(np.max(np.abs(x)) < 4194306),
        "is_actual_signature_forgery": False,
        "seconds_including_generation_and_verification": time.monotonic()-start,
        "witness": witness_file.name,
    }
    print(json.dumps(result, indent=2), flush=True)
    (destination / ("composite_sis_%d.json" % n)).write_text(
        json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--n", type=int, default=5120)
    p.add_argument("--seed", type=int, default=20260922)
    p.add_argument("--output", type=Path, default=Path("verification-sis"))
    args = p.parse_args()
    if args.n < 1 or 2*args.n*3*(2**22) >= 2**63 or 6*args.n >= 2**31:
        p.error("Dimension is outside the supported safe integer range.")
    args.output.mkdir(parents=True, exist_ok=True)
    run(args.n, args.seed, args.output)

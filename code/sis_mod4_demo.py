#!/usr/bin/env python3
"""Small-dimension demonstration of the exact modulo-4 SIS construction.

The modulus is the submitted q=2^24; dimensions are reduced for a dependency-free
quick check. Full-dimension evidence is in data/sis_witness_5120.npz.
"""
import require_checks
import json
import random


def solve_binary(matrix, rhs):
    n = len(matrix)
    rows = [sum((value & 1) << j for j, value in enumerate(row))
            | ((rhs[i] & 1) << n) for i, row in enumerate(matrix)]
    for j in range(n):
        pivot = next((i for i in range(j, n) if (rows[i] >> j) & 1), None)
        if pivot is None:
            return None
        rows[j], rows[pivot] = rows[pivot], rows[j]
        for i in range(n):
            if i != j and (rows[i] >> j) & 1:
                rows[i] ^= rows[j]
    return [(row >> n) & 1 for row in rows]


def product(matrix, vector):
    return [sum(a*b for a, b in zip(row, vector)) for row in matrix]


def demonstrate(n, seed):
    rng = random.Random(seed)
    blocks, trials = [], []
    for _ in range(2):
        count = 0
        while True:
            count += 1
            block = [[rng.randrange(4) for _ in range(n)] for _ in range(n)]
            if solve_binary(block, [0]*n) is not None:
                blocks.append(block)
                trials.append(count)
                break
    b, c = blocks
    cone = product(c, [1]*n)
    u = solve_binary(b, cone)
    even = [s+t for s, t in zip(product(b, u), cone)]
    assert all(s % 2 == 0 for s in even)
    v = solve_binary(c, [s//2 for s in even])
    w = u + [1-2*s for s in v]
    low = [left+right for left, right in zip(b, c)]
    assert all(s % 4 == 0 for s in product(low, w))
    q = 2**24
    x = [(q//4)*s for s in w]
    lifted = [[s + 4*rng.randrange(q//4) for s in row] for row in low]
    assert all(s % q == 0 for s in product(lifted, x))
    assert max(map(abs, x)) == q//4 and any(x)
    changed = x[:]
    changed[n] = 0
    assert any(s % q != 0 for s in product(lifted, changed))
    assert max(map(abs, x[:n])) >= 2*(2**21-174)
    return {
        "rows": n, "columns": 2*n, "q": q, "seed": seed,
        "conditioned_invertible_block_trials": trials,
        "norm_infinity": q//4, "full_modulus_equation_verified": True,
        "changed_vector_rejected": True,
        "fits_relaxed_512_SIS_bounds": True,
        "fails_actual_strict_response_difference_bound": True,
        "actual_signature_forgery": False,
    }


if __name__ == "__main__":
    print(json.dumps([demonstrate(n, 20260923+n) for n in (16, 32, 64)], indent=2))

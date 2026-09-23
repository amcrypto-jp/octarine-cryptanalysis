#!/usr/bin/env python3
"""Exact and numerical checks supporting the standalone Octarine analysis.

Run with the Python interpreter in a Sage environment. NumPy is also required.
The saved SIS witness is verified directly, without executing its generator.
The singular-value experiment checks small instances of an analytic formula;
it is a diagnostic, not a substitute for the proof or a security experiment.
"""
import require_checks
import json
from pathlib import Path

import numpy as np
from sage.all import GF, PolynomialRing, QQ, ZZ


def index_counterexample():
    zz = PolynomialRing(ZZ, "X")
    x = zz.gen()
    f = (x**17 - 2)**2 + 1
    g = (x - 2)**2 + 1
    difference = f - g**17
    assert all(c % 17 == 0 for c in difference)
    t = zz([c // 17 for c in difference])
    fp = PolynomialRing(GF(17), "X")
    xp = fp.gen()
    assert fp(f) == fp(g)**17
    assert fp(g).gcd(fp(g).derivative()) == 1
    remainder = fp(t) % fp(g)
    common = fp(t).gcd(fp(g))
    assert remainder == 8 + 10*xp
    assert common == xp - 6
    assert f.change_ring(QQ).is_irreducible()
    return {
        "n": 2, "k": 17, "prime": 17,
        "irreducible_over_Q": True,
        "T_mod_g_mod_17": str(remainder),
        "gcd_T_g_mod_17": str(common),
        "Dedekind_criterion_implies_17_divides_index": True,
    }


def embedding_diagnostic():
    checks = []
    n = 8
    for k in (1, 2, 5):
        zeta = np.exp(1j*np.pi*(2*np.arange(n) + 1)/n)
        roots = np.exp(np.log(2 + zeta)/k)
        matrix = np.asarray([
            [zeta[j]**a * (roots[j]*np.exp(2j*np.pi*t/k))**b
             for b in range(k) for a in range(n)]
            for j in range(n) for t in range(k)
        ])
        observed = np.sort(np.linalg.svd(matrix, compute_uv=False))
        predicted = np.sort(np.asarray([
            np.sqrt(n*k)*abs(2 + zeta[j])**(b/k)
            for j in range(n) for b in range(k)
        ]))
        discrepancy = float(np.max(np.abs(observed - predicted)))
        assert discrepancy < 1e-10
        checks.append({"n": n, "k": k,
                       "maximum_absolute_singular_value_discrepancy": discrepancy})
    n = 1024
    return {
        "small_instance_numerical_checks": checks,
        "submitted_condition_numbers_from_formula": {
            str(k): float((5 + 4*np.cos(np.pi/n))**((k-1)/(2*k)))
            for k in (1, 2, 5)
        },
    }


def saved_witness():
    root = Path(__file__).resolve().parents[1]
    path = root / "data/sis_witness_5120.npz"
    with np.load(path, allow_pickle=False) as witness:
        b, c, x = (witness[key] for key in ("B_mod4", "C_mod4", "x"))
    q, n = 2**24, 5120
    assert b.shape == c.shape == (n, n)
    assert x.shape == (2*n,)
    assert np.issubdtype(x.dtype, np.signedinteger)
    assert np.all(b <= 3) and np.all(c <= 3)
    assert np.any(x) and np.all(x % (q//4) == 0)
    assert int(np.max(np.abs(x))) == q//4
    # The maximum dot-product magnitude is <= 2*n*3*(q/4) < 2^63.
    for begin in range(0, n, 128):
        end = min(begin + 128, n)
        residue = b[begin:end].astype(np.int64) @ x[:n]
        residue += c[begin:end].astype(np.int64) @ x[n:]
        assert np.all(residue % q == 0)
    # Any lift adds 4D to [B|C], and 4D*x is divisible by q.
    return {
        "rows": n, "columns": 2*n, "modulus": q,
        "nonzero_coordinates": int(np.count_nonzero(x)),
        "infinity_norm": int(np.max(np.abs(x))),
        "saved_witness_verified": True,
        "valid_for_every_full_modulus_lift_of_saved_mod4_matrix": True,
        "actual_signature_forgery": False,
    }


if __name__ == "__main__":
    print(json.dumps({
        "index_counterexample": index_counterexample(),
        "embedding_diagnostic": embedding_diagnostic(),
        "saved_witness": saved_witness(),
    }, indent=2))

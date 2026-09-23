#!/usr/bin/env python3
"""Verify the saved full-dimension SIS certificate without its generator.

Requires NumPy, but not Sage. All arithmetic is exact and its int64 range is
bounded before multiplication. Higher matrix bits do not enter the certificate.
"""
import require_checks
import argparse
import json
from pathlib import Path
import numpy as np

DEFAULT = Path(__file__).resolve().parents[1] / "data/sis_witness_5120.npz"


def verify(path, n=5120):
    with np.load(path, allow_pickle=False) as certificate:
        assert set(certificate.files) == {"B_mod4", "C_mod4", "x"}
        b, c, x = (certificate[key] for key in ("B_mod4", "C_mod4", "x"))
    q, scale = 2**24, 2**22
    assert b.shape == c.shape == (n, n) and x.shape == (2*n,)
    assert b.dtype == c.dtype == np.uint8
    assert np.issubdtype(x.dtype, np.signedinteger)
    assert np.all(b <= 3) and np.all(c <= 3)
    assert np.all(x >= -scale) and np.all(x <= scale)
    assert np.any(x) and np.all(x % scale == 0)
    assert int(np.max(np.abs(x))) == scale
    assert np.all(np.abs(x[n:]) == scale)
    assert 2*n*3*scale < 2**63
    x = x.astype(np.int64)
    for start in range(0, n, 128):
        end = min(start + 128, n)
        residue = b[start:end].astype(np.int64) @ x[:n]
        residue += c[start:end].astype(np.int64) @ x[n:]
        assert np.all(residue % q == 0)
    # Replacing x[n] by zero must fail; this computes the change in M*x.
    assert np.any((c[:, 0].astype(np.int64)*x[n]) % q != 0)
    response_norm = int(np.max(np.abs(x[:n])))
    assert response_norm >= 2*(2**21-174)
    return {
        "rows": n, "columns": 2*n, "q": q, "norm_infinity": scale,
        "nonzero_coordinates": int(np.count_nonzero(x)),
        "all_rows_verified": True,
        "valid_for_every_lift_of_saved_mod4_matrix": True,
        "changed_vector_rejected": True,
        "response_block_norm": response_norm,
        "strict_response_difference_limit": 2*(2**21-174),
        "actual_signature_forgery": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("witness", nargs="?", type=Path, default=DEFAULT)
    parser.add_argument("--rows", type=int, default=5120)
    args = parser.parse_args()
    print(json.dumps(verify(args.witness, args.rows), indent=2))

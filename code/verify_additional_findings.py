#!/usr/bin/env python3
"""Reproduce the additional conformance and 2-adic observations.

This script does not estimate attack cost. It evaluates the exact integer
boundaries. With --submission-root, it also checks the challenge-map source
at all nine implementation/profile combinations after verifying source hashes.
"""

from __future__ import annotations

import require_checks
import argparse

import json
from math import comb, log2
from pathlib import Path


FAMILIES = (
    "Reference_Implementation",
    "Optimized_Implementation",
    "Additional_Implementation",
)
PARAMETERS = {
    128: {"tau": 16, "gamma1": 2**18, "gamma2": 2**17, "beta": 64},
    256: {"tau": 36, "gamma1": 2**19, "gamma2": 2**18, "beta": 72},
    512: {"tau": 87, "gamma1": 2**21, "gamma2": 2**20, "beta": 174},
}
Q = 2**24


def check_implementations(root: Path) -> list[dict[str, object]]:
    rows = []
    for family in FAMILIES:
        for level, params in PARAMETERS.items():
            base = root / "Implementations" / family / f"Octarine-{level}"
            sign_ring = (base / "sign_ring.c").read_text()
            header = (base / "hash_domain.h").read_text()
            parameter_text = (base / "parameters.h").read_text()

            fixed_call = (
                "RRLWR_SIGN_HASH_SAMPLE_C_DOMAIN(signs_buffer, "
                "RRLWR_SIGN_MAX_TAU_BYTES, ctilde, 0, 0);"
            )
            assert fixed_call in sign_ring
            assert "#define RRLWR_SIGN_MAX_TAU_BYTES     (11)" in parameter_text

            sample_start = header.index("RRLWR_SIGN_HASH_SAMPLE_C_DOMAIN")
            sample_end = header.index("#endif", sample_start)
            sample_wrapper = header[sample_start:sample_end]
            assert "rrlwr_domain_encode_3" in sample_wrapper
            assert "outlen," in sample_wrapper

            required = (params["tau"] + 7) // 8
            rows.append(
                {
                    "family": family,
                    "level": level,
                    "pdf_sign_stream_bytes": required,
                    "implementation_sign_stream_bytes": 11,
                    "domain_header_includes_output_length": True,
                    "same_challenge_map_as_pdf": required == 11,
                }
            )
    return rows


def arithmetic_rows() -> list[dict[str, object]]:
    rows = []
    torsion_denominator = {128: 32, 256: 16, 512: 4}
    for level, params in PARAMETERS.items():
        tau = params["tau"]
        z_strict_threshold = 2 * (params["gamma1"] - params["beta"])
        r_bound = 4 * params["gamma2"] + 2
        scale = Q // torsion_denominator[level]
        rows.append(
            {
                "level": level,
                "tau": tau,
                "challenge_evaluation_at_y_1_mod_2": tau % 2,
                "challenge_is_unit_mod_2": bool(tau % 2),
                "suF_z_condition": f"abs(z) < {z_strict_threshold}",
                "largest_accepted_integer_z_coefficient": z_strict_threshold - 1,
                "nearby_q_over_power_of_two": scale,
                "threshold_gap_to_scale": scale - z_strict_threshold,
                "integer_gap_to_scale": scale - (z_strict_threshold - 1),
                "suF_r_bound": r_bound,
                "r_bound_minus_scale": r_bound - scale,
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission-root", type=Path)
    args = parser.parse_args()
    source_rows = None
    if args.submission_root:
        from verify_submission import verify
        verify(args.submission_root)
        source_rows = check_implementations(args.submission_root)
    candidate_weights = []
    for level, tau in ((128, 21), (256, 37)):
        entropy = log2(comb(1024, tau)) + tau
        candidate_weights.append(
            {
                "level": level,
                "illustrative_odd_tau": tau,
                "challenge_entropy": entropy,
                "grover_query_exponent": entropy / 2,
                "warning": "requires full parameter retuning",
            }
        )
    result = {
        "sample_in_ball_source_checks": source_rows,
        "original_source_checked": source_rows is not None,
        "two_adic_boundaries_and_challenge_parity": arithmetic_rows(),
        "illustrative_odd_challenge_weights": candidate_weights,
        "parity_reason": (
            "Over F_2, y^1024+1=(y+1)^1024 and signs +/-1 both equal 1; "
            "therefore c(1)=tau mod 2."
        ),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

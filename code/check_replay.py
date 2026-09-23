#!/usr/bin/env python3
"""Compare a full SIS/ring replay with the recorded evidence, excluding timings."""
import require_checks
import argparse
import json
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def without_seconds(record):
    return {k: v for k, v in record.items() if "seconds" not in k}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    generated = args.run_directory / "sis-replay"
    saved_result = json.loads((ROOT / "evidence/composite_sis_5120.json").read_text())
    new_result = json.loads((generated / "composite_sis_5120.json").read_text())
    assert without_seconds(saved_result) == without_seconds(new_result)
    with np.load(ROOT / "data/sis_witness_5120.npz", allow_pickle=False) as old:
        with np.load(generated / "sis_witness_5120.npz", allow_pickle=False) as new:
            assert set(old.files) == set(new.files)
            for key in old.files:
                assert np.array_equal(old[key], new[key]), key
    saved_ring = json.loads((ROOT / "evidence/ring_structure.json").read_text())
    new_ring = json.loads((args.run_directory / "ring_structure.json").read_text())
    assert without_seconds(saved_ring) == without_seconds(new_ring)
    print(json.dumps({
        "saved_mod4_matrices_reproduced_exactly": True,
        "saved_SIS_vector_reproduced_exactly": True,
        "random_full_modulus_lift_digest_reproduced_exactly": True,
        "ring_diagnostic_reproduced": True,
        "excluded_from_comparison": "wall-clock timings",
    }, indent=2))

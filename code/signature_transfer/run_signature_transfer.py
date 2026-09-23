#!/usr/bin/env python3
"""Reproduce the OCT-01 scaled signature-transfer experiment from this package.

All generated files are written under --output-dir. The original submission is
obtained separately and checked against the distributed 397-file inventory.

  1. generate build/reduced/auxfunc_reduced.c from the shipped
     utils/auxfunc.c (SHA-256 checked against the review source inventory)
     and store the unified diff in patches/;
  2. build three drivers from the UNMODIFIED submission sources plus the
     hash implementation of each variant:
        vst_orig    shipped auxfunc.c                 (full 256-bit state)
        vst_red256  auxfunc_reduced.c, default 256    (must be inert)
        vst_red48   auxfunc_reduced.c, state = 48 bit (attack instance)
  3. selftest: SM3 known-answer tests (full width) and deterministic
     keygen/sign/verify digests; require vst_orig == vst_red256, proving
     the reduction is inert at full width;
  4. campaign (vst_red48): the executed EUF-CMA signature-transfer
     instance -- birthday collision at SM3 block offset 3 of the H_MU
     pseudoXOF input, mu equality over 1024 bits, one signing query,
     signature accepted on the never-signed message;
  5. probe (vst_orig): full-width replay of the recorded pair (states and
     mu differ, transfer fails) plus driver-side emulation reproducing
     the campaign's reduced-construction artifacts from the recorded tr;
  6. public-artifact verification: a separate executable verifies the
     recorded signature without the signing key, including a full-length
     corrupted-signature negative control;
  7. scale (vst_orig): measured birthday trials vs state width, for comparison
     alongside an idealized birthday-search estimate.

Outputs: a JSON summary on stdout and per-mode transcripts under --output-dir.

Requires: Python >= 3.10, GCC, ~3 GB RAM for the 48-bit search table, and
about 2 minutes of wall time. No network access is used.
"""
import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parents[1]
SRC = BUILD = REDUCED_DIR = EVIDENCE = OUTPUT = None
sys.path.insert(0, str(PACKAGE / "code"))
from verify_submission import verify

STATE_BITS_CAMPAIGN = 48

SCHEME_SOURCES = [
    "arith/fprime.c", "arith/poly.c", "arith/ring.c", "arith/packing.c",
    "arith/uniform.c", "sign_ring.c", "sign.c", "crt.c", "utils/drng.c",
]
DRIVER = HERE / "verify_signature_transfer.c"
PUBLIC_DRIVER = HERE / "verify_recorded_signature.c"
CFLAGS = None


def note(*args):
    print(*args, file=sys.stderr, flush=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd, **kw):
    note("+", " ".join(str(c) for c in cmd)[:200])
    # Keep the orchestrator's stdout as a single machine-readable JSON record.
    return subprocess.run(cmd, check=True, stdout=sys.stderr, **kw)


def build(target: str, extra_defs, include_reduced: bool) -> Path:
    out = BUILD / target
    cmd = list(CFLAGS) + list(extra_defs)
    if include_reduced:
        cmd.append(f"-I{REDUCED_DIR}")
    cmd += [str(SRC / s) for s in SCHEME_SOURCES]
    cmd += [str(DRIVER), "-o", str(out)]
    run(cmd)
    return out


def compare_full_width_preprocessing(cc: str, original: Path, generated: Path, include_dir: Path):
    """Check that the 256-bit build differs only in diagnostic source locations."""
    def preprocess(path):
        return subprocess.run([cc, "-E", "-P", "-std=c99", "-I" + str(include_dir), str(path)],
                              check=True, capture_output=True, text=True).stdout.splitlines()

    left, right = preprocess(original), preprocess(generated)
    pattern = re.compile(r', "[^"\n]*auxfunc(?:_reduced)?\.c", \d+\);$')
    def normalize(lines):
        normalized = []
        for line in lines:
            match = pattern.search(line)
            if match:
                normalized.append(line[:match.start()] + ', "<source-location>", <line>);')
            else:
                normalized.append(line)
        return normalized

    same = normalize(left) == normalize(right)
    diff_count = sum(a != b for a, b in zip(left, right)) + abs(len(left) - len(right))
    if not same:
        raise SystemExit("Full-width preprocessed SM3 cryptographic code differs")
    return {"equal_after_diagnostic_location_normalization": True,
            "raw_preprocessed_lines_differing": diff_count,
            "diagnostic_lines_normalized": diff_count}


def run_mode(binary: Path, args, dest: Path):
    note(f"+ {binary.name} {' '.join(args)[:100]} > {dest.relative_to(OUTPUT)}")
    t0 = time.time()
    with open(dest, "w") as fh:
        subprocess.run([str(binary)] + list(args), check=True, stdout=fh)
    data = json.loads(dest.read_text())
    note(f"    ({time.time() - t0:.1f}s, status={data.get('status', data.get('all_controls_passed'))})")
    return data


def main() -> int:
    global SRC, BUILD, REDUCED_DIR, EVIDENCE, OUTPUT, CFLAGS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    source_root = args.submission_root.resolve()
    OUTPUT = args.output_dir.resolve()
    if OUTPUT == PACKAGE or OUTPUT.is_relative_to(PACKAGE / "code") or \
       OUTPUT.is_relative_to(PACKAGE / "data") or OUTPUT.is_relative_to(PACKAGE / "evidence"):
        parser.error("Choose an output directory outside distributed inputs.")
    verified_count = verify(source_root)
    if verified_count != 397:
        raise SystemExit(f"Unexpected source inventory size: {verified_count}")
    SRC = source_root / "Implementations/Reference_Implementation/Octarine-256"
    BUILD = OUTPUT / "build"
    REDUCED_DIR = BUILD / "reduced"
    EVIDENCE = OUTPUT / "evidence"
    CFLAGS = [args.cc, "-O3", "-std=c99", "-UNDEBUG", "-w",
              "-DRRLWR_SECURITY_LEVEL=256", f"-I{SRC}",
              f"-I{SRC / 'arith'}", f"-I{SRC / 'utils'}"]
    BUILD.mkdir(parents=True, exist_ok=True)
    REDUCED_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)

    # 1. generate the reduced-state variant (verifies pristine SHA-256)
    run([sys.executable, str(HERE / "make_reduced_auxfunc.py"),
         str(SRC / "utils" / "auxfunc.c"), str(REDUCED_DIR / "auxfunc_reduced.c"),
         "--emit-diff", str(EVIDENCE / "auxfunc-reduced-state.patch")])
    recorded_patch = PACKAGE / "evidence/signature_transfer/auxfunc-reduced-state.patch"
    if (EVIDENCE / "auxfunc-reduced-state.patch").read_bytes() != recorded_patch.read_bytes():
        raise SystemExit("Generated instrumentation diff differs from distributed evidence")
    full_width_preprocessed = compare_full_width_preprocessing(
        args.cc, SRC / "utils/auxfunc.c", REDUCED_DIR / "auxfunc_reduced.c", SRC / "utils")

    # 2. builds
    b_orig = build("vst_orig", ["-DOCT_DRIVER_ORIGINAL_AUXFUNC"], False)
    b_red256 = build("vst_red256", [], True)
    b_red48 = build("vst_red48", [f"-DOCTARINE_STATE_BITS={STATE_BITS_CAMPAIGN}"], True)

    # 3. selftest / inertness at full width
    s_orig = run_mode(b_orig, ["selftest"], EVIDENCE / "selftest_shipped.json")
    s_red = run_mode(b_red256, ["selftest"], EVIDENCE / "selftest_reduced256.json")
    compare_keys = ["sm3_kat_0", "sm3_kat_1", "pk_sm3", "sk_sm3", "sig_sm3", "verify_rc"]
    inert = all(s_orig[k] == s_red[k] for k in compare_keys)
    note(f"reduced generator inert at 256 bits: {inert}")
    if not inert:
        raise SystemExit("reduced generator NOT inert at full width; aborting")

    # 4. the executed transfer instance
    camp = run_mode(b_red48, ["campaign"], EVIDENCE / "campaign_48.json")
    if camp["status"] != 0 or camp["states_equal"] != 1 or \
       camp["mu_equal_over_1024_bits"] != 1 or camp["mu_control_differs"] != 1 or \
       camp["signing_oracle_queries"] != 1 or \
       camp["signature_transferred_to_never_signed_message"] != 1:
        raise SystemExit("campaign failed")

    # 5. full-width replay + emulation validation
    probe = run_mode(b_orig, ["probe", str(STATE_BITS_CAMPAIGN), camp["tr"],
                              camp["block_B0"], camp["block_B1"]],
                     EVIDENCE / "probe_fullwidth.json")
    cross = {
        "emulated_header_state_matches": probe["emulated_header_state_words"] == camp["state_after_header_words"],
        "emulated_state_B0_matches": probe["emulated_state_words_B0"] == camp["state_after_B0_words"],
        "emulated_state_B1_matches": probe["emulated_state_words_B1"] == camp["state_after_B1_words"],
        "emulated_mu_matches": probe["emulated_mu"] == camp["mu_M0"],
    }
    note("cross-build emulation checks:", cross)
    if probe["status"] != 0 or not all(cross.values()):
        raise SystemExit("probe/emulation validation failed")

    # 6. independently verify the recorded public artifacts using no secret key
    binary_public = BUILD / "vst_public_artifact"
    run([*CFLAGS, *[str(SRC / s) for s in SCHEME_SOURCES], str(PUBLIC_DRIVER),
         f"-I{REDUCED_DIR}", f"-DOCTARINE_STATE_BITS={STATE_BITS_CAMPAIGN}",
         "-o", str(binary_public)])
    public_inputs = []
    for key in ("pk", "signature", "M0", "M1", "M2_control_different_suffix"):
        artifact = BUILD / (key + ".bin")
        artifact.write_bytes(bytes.fromhex(camp[key]))
        public_inputs.append(str(artifact))
    public = run_mode(binary_public, public_inputs, EVIDENCE / "public_artifact_verification.json")
    if not public["all_controls_passed"] or public["uses_signing_key"]:
        raise SystemExit("public-artifact verifier failed")

    # 7. illustrative scaling measurements
    scale = run_mode(b_orig, ["scale", str(STATE_BITS_CAMPAIGN)], EVIDENCE / "scale.json")
    per_width = {}
    for r in scale["runs"]:
        per_width.setdefault(r["t"], []).append(r["trials"])
    law = {str(t): {"reps": len(v), "mean_trials": sum(v) / len(v),
                    "mean_ratio": sum(v) / len(v) / 2 ** (t // 2)}
           for t, v in sorted(per_width.items())}
    for t, row in law.items():
        note(f"    t={t}: reps={row['reps']} mean_trials={row['mean_trials']:.0f} "
              f"ratio vs 2^(t/2)={row['mean_ratio']:.3f} (random map: 1.2533)")

    record = {
        "artifact": "OCT-01 executed signature-transfer instance (scaled SM3 state)",
        "profile": "ARCANE-Octarine Octarine-256 reference scheme, 48-bit reduced-state SM3 model",
        "state_bits_campaign": STATE_BITS_CAMPAIGN,
        "original_files_verified": verified_count,
        "environment": {
            "python": platform.python_version(),
            "gcc": subprocess.run(["gcc", "--version"], capture_output=True,
                                  text=True).stdout.splitlines()[0],
            "platform": platform.platform(),
        },
        "source_hashes": {
            "shipped_auxfunc_sha256": sha256(SRC / "utils" / "auxfunc.c"),
            "auxfunc_reduced_sha256": sha256(REDUCED_DIR / "auxfunc_reduced.c"),
            "driver_sha256": sha256(DRIVER),
            "public_verifier_sha256": sha256(PUBLIC_DRIVER),
        },
        "inert_at_256": inert,
        "full_width_preprocessed_code": full_width_preprocessed,
        "campaign_file": "campaign_48.json",
        "probe_file": "probe_fullwidth.json",
        "cross_build_emulation": cross,
        "public_artifact_checks": public,
        "scaling_law_mean_ratio_vs_1.2533": law,
        "headline_results": {
            "collision_search_trials": camp["collision_search_trials"],
            "states_equal": camp["states_equal"],
            "mu_equal_over_1024_bits": camp["mu_equal_over_1024_bits"],
            "signing_oracle_queries": camp["signing_oracle_queries"],
            "verify_M0_rc": camp["verify_M0_rc"],
            "verify_M1_rc": camp["verify_M1_rc"],
            "signature_transferred": camp["signature_transferred_to_never_signed_message"],
            "full_width_states_differ": probe["full_width_states_differ"],
            "full_width_mu_differ": probe["full_width_mu_differ"],
            "full_width_transfer_fails": probe["control_verify_M1_rc"] != 0,
        },
    }
    (EVIDENCE / "signature_transfer.json").write_text(json.dumps(record, indent=2) + "\n")
    note("ALL CHECKS PASSED")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

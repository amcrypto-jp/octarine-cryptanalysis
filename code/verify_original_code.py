#!/usr/bin/env python3
"""Run focused C checks against a hash-verified, separately obtained submission.

Builds nine challenge-stream checks, six SM3 descriptor checks, one SM3
continuation check, and a supplied-state 20-step collision replay with
submitted 64-step controls. It executes no submitted Makefile, script, or binary.
"""
import require_checks
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from verify_submission import verify
from verify_additional_findings import check_implementations

CODE = Path(__file__).resolve().parent
FAMILIES = ("Reference_Implementation", "Optimized_Implementation",
            "Additional_Implementation")


def checked(command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit("Requested compilation/check failed:\n" +
                         result.stdout + result.stderr)
    return result.stdout


def values(output):
    fields = {}
    for token in output.split():
        if "=" in token:
            key, value = token.split("=", 1)
            # Preserve hexadecimal byte streams, including leading zeroes.
            if key.endswith("stream") or key.endswith("prefix"):
                fields[key] = value
            elif value.isdigit():
                fields[key] = int(value)
            elif value in ("true", "false"):
                fields[key] = value == "true"
            else:
                fields[key] = value
    return fields


def run(root, cc):
    root = root.resolve()
    verified_count = verify(root)
    source_checks = check_implementations(root)
    challenges, descriptors = [], []
    flags = ["-O2", "-std=c99", "-UNDEBUG"]
    with tempfile.TemporaryDirectory(prefix="octarine-source-check-") as tmp:
        for family in FAMILIES:
            for level in (128, 256, 512):
                base = root / "Implementations" / family / f"Octarine-{level}"
                command = [cc, *flags, f"-DRRLWR_SECURITY_LEVEL={level}",
                           "-I" + str(base), "-I" + str(base / "utils")]
                binary = Path(tmp) / f"challenge-{family}-{level}"
                primitive = "fips202.c" if family == "Additional_Implementation" else "auxfunc.c"
                checked([*command, str(CODE / "verify_challenge_stream.c"),
                         str(base / "utils" / primitive), "-o", str(binary)])
                row = values(checked([str(binary)]))
                row["family"] = family
                assert row["level"] == level
                challenges.append(row)
                if family != "Additional_Implementation":
                    binary = Path(tmp) / f"descriptor-{family}-{level}"
                    checked([*command, str(CODE / "verify_secret_descriptor.c"),
                             "-o", str(binary)])
                    row = values(checked([str(binary)]))
                    row["family"] = family
                    assert row["all_stream_bytes_match"] is True
                    assert row["descriptor_bits"] == 344
                    descriptors.append(row)
        base = root / "Implementations/Reference_Implementation/Octarine-128"
        binary = Path(tmp) / "sm3-continuation"
        checked([cc, *flags, "-I" + str(base / "utils"),
                 str(CODE / "verify_sm3_mechanism.c"), "-o", str(binary)])
        continuation = checked([str(binary)])
        assert "model matches" in continuation and "yes (mechanism confirmed" in continuation
        binary = Path(tmp) / "sm3-reduced-collision"
        checked([cc, *flags, "-I" + str(base / "utils"),
                 str(CODE / "verify_sm3_reduced_collision.c"), "-o", str(binary)])
        reduced_collision = checked([str(binary)])
        row = values(reduced_collision)
        for key in ("concrete_20step_collision", "matches_published_h2",
                    "adapter_64step_matches_submitted",
                    "equal_20step_state_plus_identical_suffix_remains_equal"):
            assert row[key] == "yes", (key, row)
        for key in ("states_equal_after_64", "full_sm3_collision", "octarine_prefix_reached",
                    "octarine_signature_campaign_executed", "octarine_signature_transferred"):
            assert row[key] == "no", (key, row)
        assert row["differing_bytes"] == 8
        assert row["equal_20step_counter_blocks"] == row["checked_counters"] == 64
    return {
        "original_files_verified": verified_count,
        "compiler": checked([cc, "--version"]).splitlines()[0],
        "compile_flags": flags,
        "source_checks": source_checks,
        "challenge_streams": challenges,
        "secret_descriptors": descriptors,
        "sm3_continuation": continuation.splitlines(),
        "sm3_reduced_collision": reduced_collision.splitlines(),
        "full_sm3_collision_found": False,
        "unknown_signing_key_recovered": False,
        "actual_signature_forgery": False,
        "full_sign_verify_or_KAT_campaign": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission-root", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    print(json.dumps(run(args.submission_root, args.cc), indent=2))

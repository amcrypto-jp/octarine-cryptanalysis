#!/usr/bin/env python3
"""Run focused C checks against a hash-verified, separately obtained submission.

Builds nine challenge-stream checks, six SM3 descriptor checks, and one SM3
continuation check. It executes no submitted Makefile, script, or binary.
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
    return {
        "original_files_verified": verified_count,
        "compiler": checked([cc, "--version"]).splitlines()[0],
        "compile_flags": flags,
        "source_checks": source_checks,
        "challenge_streams": challenges,
        "secret_descriptors": descriptors,
        "sm3_continuation": continuation.splitlines(),
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

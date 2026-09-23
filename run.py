#!/usr/bin/env python3
"""Run portable Octarine evidence checks.

Quick mode needs Python >=3.10 and its standard library.
--full adds the saved certificate, exact Sage algebra, and seeded 5120-row replay.
Use --sage-python for the Python executable in a Sage environment, or --sage
for a standard Sage launcher. --submission-root adds hash-verified C checks.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent


def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE") not in (None, "", "0"):
        raise SystemExit("Checks require assertions: disable -O and PYTHONOPTIMIZE.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true")
    sage = parser.add_mutually_exclusive_group()
    sage.add_argument("--sage", help="Standard Sage executable")
    sage.add_argument("--sage-python", help="Python executable in a Sage environment")
    parser.add_argument("--submission-root", type=Path)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--output-dir", type=Path, default=Path("verification-output"))
    args = parser.parse_args()
    if args.full and not (args.sage or args.sage_python):
        parser.error("--full requires --sage sage or --sage-python /path/to/python.")
    if not args.full and (args.sage or args.sage_python):
        parser.error("Use --full with the Sage interpreter option.")
    output = args.output_dir.resolve()
    for protected in ("code", "data", "evidence", "assets", "LICENSES"):
        if output.is_relative_to(ROOT / protected):
            parser.error("The output directory must not overwrite distributed artifacts.")
    if output == ROOT:
        parser.error("Choose a separate output directory.")
    output.mkdir(parents=True, exist_ok=True)
    # A failed rerun must not leave a previous success summary in place.
    (output / "summary.json").unlink(missing_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    steps = []

    def execute(label, command, extension="json"):
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, env=env)
        log = output / f"{label}.{extension}"
        log.write_text(result.stdout)
        (output / f"{label}.stderr.txt").unlink(missing_ok=True)
        if result.stderr:
            (output / f"{label}.stderr.txt").write_text(result.stderr)
        if result.returncode:
            raise SystemExit(f"FAIL: {label} (exit {result.returncode})\n" +
                             result.stdout + result.stderr)
        if extension == "json":
            json.loads(result.stdout)
        elapsed = time.monotonic() - start
        steps.append({"check": label, "output": log.name, "seconds": elapsed})
        print(f"PASS: {label} ({elapsed:.2f}s)", flush=True)

    if args.full:
        interpreter = [args.sage_python] if args.sage_python else [args.sage, "-python"]
        execute("sage_environment", [*interpreter, "-c",
                "import json,sys,numpy; from sage.env import SAGE_VERSION; "
                "print(json.dumps(dict(sage=SAGE_VERSION,python=sys.version.split()[0],"
                "numpy=numpy.__version__)))"])
    for name in ("verify_parameters", "verify_algebra", "verify_additional_findings",
                 "sis_mod4_demo"):
        execute(name, [sys.executable, str(ROOT / "code" / (name + ".py"))])
    execute("verify_kdf_collision", [sys.executable, str(ROOT / "code/verify_kdf_collision.py")],
            extension="txt")
    if args.submission_root:
        execute("original_code", [sys.executable, str(ROOT / "code/verify_original_code.py"),
                "--submission-root", str(args.submission_root.resolve()), "--cc", args.cc])
    if args.full:
        for name in ("verify_sis_witness", "verify_publication_supplement", "ring_structure"):
            execute(name, [*interpreter, str(ROOT / "code" / (name + ".py"))])
        execute("composite_sis_replay", [*interpreter, str(ROOT / "code/composite_sis.py"),
                "--n", "5120", "--seed", "20260922", "--output", str(output / "sis-replay")])
        execute("verify_replayed_witness", [*interpreter, str(ROOT / "code/verify_sis_witness.py"),
                str(output / "sis-replay/sis_witness_5120.npz")])
        execute("check_replay", [*interpreter, str(ROOT / "code/check_replay.py"), str(output)])
    summary = {
        "release": "1.0.0",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "quick_checks": True,
        "full_mathematical_replay": args.full,
        "original_source_C_checks": args.submission_root is not None,
        "steps": steps,
        "all_requested_checks_passed": True,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("PASS: all requested checks completed.")
    if not args.full:
        print("Coverage: standard-library mathematics and small SIS examples; "
              "full-dimension certificate/Sage replay not requested.")
    if not args.submission_root:
        print("Coverage: original-source C checks not requested.")


if __name__ == "__main__":
    main()

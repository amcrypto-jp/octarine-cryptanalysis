#!/usr/bin/env python3
"""Check release integrity against SHA256SUMS; this does not authenticate authorship."""
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent


def main():
    manifest = ROOT / "SHA256SUMS"
    seen, failures = set(), []
    for line in manifest.read_text().splitlines():
        try:
            expected, name = line.split("  ", 1)
        except ValueError:
            raise SystemExit("FAIL: malformed manifest line")
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or name in seen:
            raise SystemExit("FAIL: invalid hash or duplicate manifest path")
        seen.add(name)
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file():
            failures.append(name + ": missing or invalid path")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            failures.append(name + ": hash mismatch")
    if not seen:
        failures.append("empty manifest")
    if failures:
        raise SystemExit("FAIL:\n" + "\n".join(failures))
    print(f"PASS: {len(seen)} distributed files match SHA256SUMS.")


if __name__ == "__main__":
    main()

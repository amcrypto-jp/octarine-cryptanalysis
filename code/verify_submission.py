#!/usr/bin/env python3
"""Verify the separately obtained Octarine specification and source snapshot."""
import argparse
import hashlib
import json
from pathlib import Path

INVENTORY = Path(__file__).resolve().parents[1] / "data/submission-sha256.json"


def verify(submission_root):
    root = Path(submission_root).resolve()
    inventory = json.loads(INVENTORY.read_text())
    failures = []
    for item in inventory["files"]:
        path = (root / item["path"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            failures.append(item["path"] + ": missing or outside source root")
        elif path.stat().st_size != item["bytes"]:
            failures.append(item["path"] + ": size mismatch")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            failures.append(item["path"] + ": hash mismatch")
    if failures:
        raise SystemExit("Source verification failed:\n" + "\n".join(failures))
    return len(inventory["files"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("submission_root", type=Path)
    args = parser.parse_args()
    count = verify(args.submission_root)
    print(f"PASS: {count} original specification/source files match the reviewed snapshot.")

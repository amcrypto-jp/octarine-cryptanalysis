"""Reject execution modes that remove the mathematical assertions."""
import os

if not __debug__ or os.environ.get("PYTHONOPTIMIZE") not in (None, "", "0"):
    raise SystemExit("Checks require assertions: disable -O and PYTHONOPTIMIZE.")

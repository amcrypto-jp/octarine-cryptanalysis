#!/usr/bin/env python3
"""Generate the reduced-width SM3 variant for the OCT-01 model experiment.

The 48-bit experiment makes two changes to the submitted SM3 utility:

* Mask the chaining state after each message compression block.
* Tile the live state bytes across the 32-byte digest output. This is an
  injective serialization of the reduced state; it adds no collision
  entropy but changes the digest output distribution.

Both changes affect all SM3 roles. Octarine's C signing and verification
functions and domain encoders are unmodified. The signature-transfer result
therefore describes this reduced primitive, not the submitted 256-bit SM3
profile. Small-width measurements illustrate birthday search and do not
empirically establish the 256-bit state's attack cost.

The input must match the package's 397-file source inventory. The 256-bit
run compares known hash, key, and signature outputs and separately checks
the preprocessed cryptographic code. Error diagnostics retain source paths
and line numbers, so their preprocessed text can differ.

Usage:
    python3 make_reduced_auxfunc.py AUXFUNC_ORIGINAL_C OUTPUT_C [--emit-diff DIFF]

The original file's SHA-256 is checked against the package source inventory
(Implementations/Reference_Implementation/Octarine-256/utils/auxfunc.c,
sha256 27446371...).
"""
import argparse
import difflib
import hashlib
import json
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]
INVENTORY = PACKAGE / "data" / "submission-sha256.json"
INVENTORY_KEY = "Implementations/Reference_Implementation/Octarine-256/utils/auxfunc.c"

MACRO_BLOCK = """
/* ==== BEGIN OCT-01 review instrumentation (reduced chaining state) ====
 * OCTARINE_STATE_BITS (default 256): when < 256, the SM3 chaining value is
 * truncated to its first OCTARINE_STATE_BITS bits in serialization order
 * after every compression, and the digest is rendered by tiling the live
 * state bytes across the 32-byte block (see sm3_bit below). At the default
 * the reduced-state branches are inactive in the 256-bit build (SHA-256
 * 27446371eccf1438...). Added for the executed OCT-01 signature-transfer
 * instance; not part of the submission. */
#ifndef OCTARINE_STATE_BITS
#define OCTARINE_STATE_BITS 256
#endif
#if (OCTARINE_STATE_BITS < 256)
#define OCTARINE_STATE_LIVE_BYTES ((OCTARINE_STATE_BITS + 7) / 8)
static void octarine_mask_state(unsigned int dgst[8])
{
	unsigned int remaining = (unsigned int)OCTARINE_STATE_BITS;
	int octarine_i;
	for (octarine_i = 0; octarine_i < 8; octarine_i++) {
		if (remaining >= 32U) {
			remaining -= 32U;
			continue;
		}
		dgst[octarine_i] &= (remaining == 0U) ? 0U : (0xFFFFFFFFU << (32U - remaining));
		remaining = 0U;
	}
}
#endif
/* ==== END OCT-01 review instrumentation ==== */
"""

MASK_CALL = """#if (OCTARINE_STATE_BITS < 256)
		octarine_mask_state(dgst);
#endif
		msg += 64;"""

TILED_SERIALIZATION = """#if (OCTARINE_STATE_BITS < 256)
	/* reduced model: render the t-bit final state by tiling its live bytes
	   across the 32-byte digest block (injective serialization of the
	   state; keeps hash streams byte-dense for the shipped scheme) */
	for (int octarine_j = 0; octarine_j < 32; octarine_j++)
	{
		int octarine_src = octarine_j % OCTARINE_STATE_LIVE_BYTES;
		dgst[octarine_j] = (unsigned char)(digest[octarine_src >> 2] >> (24 - 8 * (octarine_src & 3)));
	}
#else
	for (int i = 0; i < 8; i++)
	{
		PUT32(dgst + i * 4, digest[i]);
	}
#endif"""

INIT_ANCHOR = "\tinit_digest[7] = 0xB0FB0E4E;\n}\n"
XOR_ANCHOR = "\t\tdgst[7] ^= H;\n\t\tmsg += 64;"
XOR_REPLACEMENT = "\t\tdgst[7] ^= H;\n" + MASK_CALL
SER_ANCHOR = "\tfor (int i = 0; i < 8; i++)\n\t{\n\t\tPUT32(dgst + i * 4, digest[i]);\n\t}\n"


def load_expected_sha256() -> str:
    inventory = json.loads(INVENTORY.read_text())
    for row in inventory["files"]:
        if row["path"] == INVENTORY_KEY:
            return row["sha256"]
    raise SystemExit(f"inventory entry not found: {INVENTORY_KEY}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("original", type=Path, help="shipped utils/auxfunc.c")
    ap.add_argument("output", type=Path, help="generated auxfunc_reduced.c")
    ap.add_argument("--emit-diff", type=Path, default=None,
                    help="also write a unified diff for the record")
    args = ap.parse_args()

    src = args.original.read_bytes()
    expected = load_expected_sha256()
    actual = hashlib.sha256(src).hexdigest()
    if actual != expected:
        raise SystemExit(
            f"SHA-256 mismatch for {args.original}:\n  got      {actual}\n"
            f"  expected {expected} (package inventory {INVENTORY_KEY})")
    text = src.decode("utf-8")

    # The shipped file uses CRLF line endings; preserve them exactly.
    nl = "\r\n" if "\r\n" in text else "\n"
    init_anchor = INIT_ANCHOR.replace("\n", nl)
    xor_anchor = XOR_ANCHOR.replace("\n", nl)
    xor_replacement = XOR_REPLACEMENT.replace("\n", nl)
    ser_anchor = SER_ANCHOR.replace("\n", nl)
    ser_replacement = TILED_SERIALIZATION.replace("\n", nl) + nl
    macro_block = MACRO_BLOCK.replace("\n", nl)

    if "OCTARINE_STATE_BITS" in text:
        raise SystemExit("input already instrumented; pass the pristine shipped file")
    if text.count(init_anchor) != 1:
        raise SystemExit("init anchor not found exactly once; refusing to edit")
    if text.count(xor_anchor) != 1:
        raise SystemExit("compression anchor not found exactly once; refusing to edit")
    if text.count(ser_anchor) != 1:
        raise SystemExit("serialization anchor not found exactly once; refusing to edit")

    reduced = text.replace(init_anchor, init_anchor + macro_block, 1)
    reduced = reduced.replace(xor_anchor, xor_replacement, 1)
    reduced = reduced.replace(ser_anchor, ser_replacement, 1)

    args.output.write_bytes(reduced.encode("utf-8"))

    if args.emit_diff is not None:
        diff = difflib.unified_diff(
            text.splitlines(keepends=True),
            reduced.splitlines(keepends=True),
            fromfile="a/utils/auxfunc.c (shipped, sha256 27446371...)",
            tofile="b/utils/auxfunc_reduced.c (OCT-01 reduced-state variant)",
        )
        args.emit_diff.write_text("".join(diff), encoding="utf-8")

    print(f"original sha256 verified: {hashlib.sha256(src).hexdigest()}")
    print(f"wrote {args.output} ({len(reduced)} bytes, "
          f"{reduced.count('OCTARINE_STATE_BITS')} instrumentation references)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

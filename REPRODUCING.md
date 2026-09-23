# Reproducing the results

Run the commands below from the repository root. Scripts also resolve their
distributed inputs relative to their own location, so they can be invoked by
absolute path from another directory.

## 1. Integrity and quick checks

Requires Python 3.10 or later, with no third-party Python packages.

~~~sh
python3 verify_package.py
python3 run.py
~~~

The integrity command verifies all files listed in *SHA256SUMS*. A checksum
detects changes relative to the manifest; it does not authenticate the author.
The quick runner executes:

| Program | Checked result |
|---|---|
| [verify_parameters.py](code/verify_parameters.py) | Parameter arithmetic, challenge entropy, sizes, rejection approximations, and CRT ranges |
| [verify_algebra.py](code/verify_algebra.py) | Local ring/index calculations, Fermat-factor arithmetic, parity, and exhaustive small-modulus rounding/hint identities |
| [verify_additional_findings.py](code/verify_additional_findings.py) | Strict response/residual thresholds and candidate odd challenge weights |
| [sis_mod4_demo.py](code/sis_mod4_demo.py) | Two binary solves and exact SIS relations at dimensions 16, 32, and 64, with q = 2^24 |
| [verify_kdf_collision.py](code/verify_kdf_collision.py) | A 12-bit toy state collision and its propagation through counter expansion |

The runner prints the checks it executed and the optional coverage it did not
execute. Quick mode does not check the large certificate or execute original C
source. Assertions are part of the checks: the programs reject Python's *-O*
mode and a nonzero *PYTHONOPTIMIZE* setting.

Each successful run writes *summary.json* and per-check outputs under
*verification-output/* in the current directory. Select another destination
with *--output-dir /path/to/results*. Use separate output directories when
comparing runs or coverage modes. The runner protects the distributed
*code/*, *data/*, *evidence/*, *assets/*, and *LICENSES/* directories.

## 2. Full mathematical replay

Requires SageMath and NumPy. A standard installation can use:

~~~sh
python3 run.py --full --sage sage
~~~

For an environment with a directly callable Sage-enabled Python:

~~~sh
python3 run.py --full \
  --sage-python /path/to/sage-env/bin/python
~~~

This runs the quick checks, verifies the saved full-dimension witness, performs
the supplementary exact algebra and numerical embedding checks, repeats the
ring diagnostic, and regenerates the 5,120-row SIS instance with seed 20260922.
The replay uses NumPy's explicit PCG64 generator. The separate checker compares
the two matrices modulo 4, the witness vector, the full-modulus lift digest,
and the mathematical ring results with the distributed data. Timings are
excluded from those comparisons.

The full replay allocates dense matrices and can use several hundred megabytes
of memory; allow approximately 1 GB for the process and its Sage environment.
The original saved SIS generation took 10.56 seconds on the recorded machine.
This is an illustrative run, not a performance guarantee or a cost estimate
for an actual signature forgery.

The generator samples each block until it is invertible modulo 2. That
conditioning is explicit. The roughly 8.34% two-block success probability on
uniform random matrices follows from the formula in report Section 6.2,
not from the conditioned timing experiment.

### Verify only the saved certificate

Python and NumPy suffice; Sage is not needed:

~~~sh
python3 code/verify_sis_witness.py
~~~

This checks all 5,120 rows with bounded exact integer arithmetic, including the
nonzero and norm conditions. A changed-coordinate check must reject the
modified vector. Since the witness is a multiple of q/4, the modulo-4 matrix
data certify the relation for every lift to modulus q.

The verifier also checks that the response block violates the actual
signature's stricter bound. Acceptance of the certificate therefore proves a
solution of the relaxed SIS instance, not a valid Octarine forgery.

### Run individual Sage checks

~~~sh
sage -python code/verify_publication_supplement.py
sage -python code/ring_structure.py
sage -python code/composite_sis.py \
  --n 5120 --seed 20260922 --output verification-sis
~~~

The ring script prints JSON; its optional *--output* argument writes a JSON
file. The generator writes its JSON record and NPZ certificate in the selected
directory. Preserve the distributed evidence when experimenting with different
seeds or dimensions.

## 3. Checks against the original C implementation

Obtain the original submission using the links in [PROVENANCE.md](PROVENANCE.md).
The root supplied to *--submission-root* must contain both
*Algorithm Specifications/Octarine.pdf* and *Implementations/*, with their
original names.

~~~sh
python3 code/verify_submission.py /path/to/Octarine
python3 run.py --submission-root /path/to/Octarine
~~~

The runner performs the same inventory check automatically. It requires an
exact SHA-256 match for 397 original inputs before compilation. A newer or
locally edited submission is not silently accepted. This is a snapshot check,
not a trust assertion about any download location.

GCC must be available; select another compatible C compiler executable with
*--cc /path/to/compiler*. The driver uses explicit compilation commands with
*-O2 -std=c99 -UNDEBUG*, builds in a temporary directory, and does not invoke
the submission's Makefiles or supplied executables.

| Experiment | Executed coverage |
|---|---|
| Source-level challenge-length/header checks | All nine families/profile combinations |
| [verify_challenge_stream.c](code/verify_challenge_stream.c) | Three levels in each of reference SM3, optimized SM3, and additional SHAKE |
| [verify_secret_descriptor.c](code/verify_secret_descriptor.c) | Three levels in each of reference and optimized SM3 |
| [verify_sm3_mechanism.c](code/verify_sm3_mechanism.c) | SM3 continuation in the reference level-128 utility implementation |

The compilation driver is [verify_original_code.py](code/verify_original_code.py).
The descriptor and continuation drivers include the SM3 utility source
directly; the driver avoids linking a second copy. All C results, including
the exact challenge streams, are captured in *original_code.json*.

To run both optional groups:

~~~sh
python3 run.py --full --sage sage \
  --submission-root /path/to/Octarine
~~~

These are targeted mechanism and conformance checks. They do not execute a full
key-generation/sign/verify or KAT campaign, find a full SM3 collision, recover
an unknown signing key, demonstrate a practical forgery, or audit side-channel
behavior.

## 4. Recorded publication run

The distributed [summary](evidence/summary.json) records success of all quick,
full mathematical, and original-source checks. Individual machine-readable
outputs are in [evidence/](evidence/).

| Component | Recorded version |
|---|---|
| Quick/C runner Python | 3.14.4 |
| SageMath | 10.9 |
| Sage environment Python | 3.13.15 |
| NumPy | 2.5.3 |
| GCC | 15.2.0 |
| Platform | Linux x86-64 under WSL2 |
| Pandoc | 3.11 |
| Tectonic | 0.17.0 |

The Python and Sage versions are also recorded in
[summary.json](evidence/summary.json) and
[sage_environment.json](evidence/sage_environment.json). Timings and platform
strings may vary. Reproduction compares mathematical data, not NPZ container
metadata or PDF bytes.

## 5. Build the report and release archive

Requires Pandoc 3.11 or later and Tectonic on the executable search path:

~~~sh
python3 build_documents.py
~~~

Explicit executable paths are supported:

~~~sh
python3 build_documents.py \
  --pandoc /path/to/pandoc --tectonic /path/to/tectonic
~~~

This builds *REPORT.html*, *REPORT.tex*, and *REPORT.pdf* from *REPORT.md*.
The HTML embeds its stylesheet and uses native MathML, with no hosted
JavaScript requirement. Tectonic may download TeX support files on its first
run; a populated local cache permits an offline build. Rebuilding with
different typesetting versions may change output bytes and pagination.

After an intentional change, refresh the manifest or create the release ZIP:

~~~sh
python3 package_release.py --manifest-only
python3 verify_package.py
python3 package_release.py --output-dir /path/to/release-output
~~~

The packager includes only the publication files and documented asset
directories. It excludes Git history, Python caches, and generated verification
directories. It writes the ZIP and its separate SHA-256 checksum and never
contacts GitHub.

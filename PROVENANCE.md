# Provenance and scope

**Report:** *Security Analysis of ARCANE-Octarine*, version 1.0.1  
**Author:** Mounir IDRASSI, [mounir@amcrypto.jp](mailto:mounir@amcrypto.jp)  
**Package date:** 23 September 2026  
**Repository:** https://github.com/amcrypto-jp/octarine-cryptanalysis

## Evaluated specification

The evaluated document is *ARCANE-Octarine: Algorithm Specifications and
Supporting Documentation*, attributed in the submission to the ARCANE team.
It has 53 PDF pages. The report uses printed page numbers; add two to obtain
the one-based PDF page number.

Original relative path:

~~~text
Algorithm Specifications/Octarine.pdf
~~~

SHA-256:

~~~text
b88fbdd019beb8f0ae85c1554b48c87a42c5447b39171ce559ae30988c1bf09f
~~~

An identical public PDF was checked at the pinned NGCC harness revision:

- [PDF at revision 31de7d4d57aca530a65c2c9de6ddaeb25c66548d](https://github.com/ngcc-dev/ngcc-harness/blob/31de7d4d57aca530a65c2c9de6ddaeb25c66548d/sign-16/sign-16-spec.pdf)
- [Raw PDF at the same revision](https://raw.githubusercontent.com/ngcc-dev/ngcc-harness/31de7d4d57aca530a65c2c9de6ddaeb25c66548d/sign-16/sign-16-spec.pdf)
- [Official candidate page](https://www.niccs.org.cn/niccs/Round1Additional/pc/content/content_2101561078258946048.html)
- [Official submission archive](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Octarine.zip)

The official archive is an acquisition link, not an immutable identifier. Use
the inventory below to determine whether downloaded files match the evaluated
snapshot. The pinned NGCC PDF alone is insufficient for the optional C checks.

## Implementation inventory

[data/submission-sha256.json](data/submission-sha256.json) lists relative paths,
byte lengths, and SHA-256 hashes for 397 original inputs:

| Group | Files |
|---|---:|
| Specification PDF | 1 |
| Reference implementation source/build inputs | 102 |
| Optimized implementation source/build inputs | 135 |
| Additional implementation source/build inputs | 159 |
| Total | 397 |

The three implementation families each contain levels 128, 256, and 512.
The reference and optimized families use the SM3 counter construction; the
additional family uses SHA3/SHAKE. The inventory includes the source, headers,
assembly support, and Makefiles used to identify these trees. It is not an
inventory of the entire downloaded archive: KATs, executable files, and other
unneeded submission material are outside this package.

The original PDF and source files are not redistributed. The optional C
driver requires every inventoried input to match before compiling its research
programs. See [REPRODUCING.md](REPRODUCING.md).

## Estimator reference

The submission cites lattice-estimator revision *be81b18*, resolved to:

~~~text
be81b183195fb0d62fd882c65620237c6218b981
~~~

The inspected [SIS implementation at that revision](https://github.com/malb/lattice-estimator/blob/be81b183195fb0d62fd882c65620237c6218b981/estimator/sis_lattice.py)
has SHA-256:

~~~text
df8d15a2ecb2d98750a66dac83a9fb3909ae20bbae069e62531bc8f55b0207bb
~~~

It is referenced for the attack model in the security estimate and is not
bundled or required to run the supplied witness construction. The package
does not claim to reproduce every estimator output, fit, or benchmark in the
submission.

## Research evidence

The research programs implement mathematical constructions and targeted
checks described in the report. The C research drivers use separately obtained
submission utilities at compile time. The OCT-01 signature-transfer model
checks all 397 inventoried source inputs, generates a reduced-state SM3 utility
from the submitted Octarine-256 reference utility, and writes build outputs to
an external directory. Its 48-bit state truncation and tiled digest
serialization change every SM3 role in that model; its signature result does
not apply to the submitted 256-bit profile.

The saved full-dimension SIS certificate and its
[generation record](evidence/composite_sis_5120.json) use seed 20260922. The
recorded generation on 22 September 2026 took approximately 10.56 seconds.
It contains two matrices modulo 4 and one integer vector; no secret signing
key or victim data is involved.

The publication replay on 23 September 2026 reproduced those matrices, the
vector, and the digest of a generated full-modulus lift exactly. The
[comparison output](evidence/check_replay.json) records these checks.
[evidence/summary.json](evidence/summary.json) records the full publication
run; other files in *evidence/* are the corresponding outputs, except for the
explicitly retained initial *composite_sis_5120.json* record.

The full-modulus lift is regenerated from the seed rather than stored a second
time. Its SHA-256 is:

~~~text
3761563dedbeb22e5eb38a4db6c73b55d14a95373862ef02ba228161d9f733f1
~~~

The C challenge examples use an all-zero public challenge seed. The secret
descriptor check uses a fixed, known test seed. The SM3 continuation check
forces equal internal states. These are reproducible mechanism tests and
must not be represented as an unknown-key recovery or a computed full SM3
collision.

The separate reduced-step replay uses the two second blocks and chaining
values from Mendel, Nad, and Schläffer, *Finding Collisions for Round-Reduced
SM3*, CT-RSA 2013, Section 5.1, Table 3, p. 182
([publisher record](https://doi.org/10.1007/978-3-642-36095-4_12),
[institutional copy](https://pure.tugraz.at/ws/portalfiles/portal/80044228/sm3.pdf)).
The collision itself is prior work. The checker supplies the table's chaining
input directly, adapts the submitted operations to 20 steps, and cross-checks
the adapter against the unmodified function at 64 steps. It makes no claim
to reproduce the table's first-block connection from the standard IV.
The text output in *evidence/verify_sm3_reduced_collision.txt* is extracted
from the same recorded run as *original_code.json*.

The separate 48-bit signature-transfer campaign uses a deterministic test key
and records the public key, signature, messages, states, representatives, and
verification outcomes. Its campaign transcript does not include the synthetic
secret key. A second verifier independently checks the public artifacts and
negative controls without a signing key. The generator and patch are included
under *code/signature_transfer/* and *evidence/signature_transfer/*. The
recorded full-width control uses the submitted SM3 utility on the campaign's
recorded message pair; state and representative equality do not hold there.
The finite-width measurements from 8 to 48 bits are model observations, not
an empirical estimate at 256 bits.

The exact integer and finite-ring checks are distinguished from floating-point
embedding diagnostics and idealized attack-cost calculations. Published
Fermat-number factorization results are cited where used; the package does
not independently prove the primality of the largest factor.

## Integrity, authorship, and disclosure

*SHA256SUMS* identifies this publication package and is distinct from the
original-submission inventory. The release ZIP has its own checksum sidecar.
Checksums bind file contents relative to those manifests; they do not provide
a digital signature or independent confirmation of the analysis.

The report is a standalone assessment. External programs and evidence files
support reproducibility, and the cited publications identify the theoretical
sources. No prior author correspondence, external acceptance, or peer review
is asserted. AI assistance is disclosed in [AI_DISCLOSURE.md](AI_DISCLOSURE.md)
and report Section 12.3. Reuse terms are in [LICENSING.md](LICENSING.md).

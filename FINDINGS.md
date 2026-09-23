# Finding index

This index accompanies *Security Analysis of ARCANE-Octarine*, version 1.0.1.
OCT-01 through OCT-04 are identifiers local to this repository. They are not
identifiers assigned by an external evaluation project, and no external
confirmation or author acknowledgment is claimed.

All findings concern the exact snapshot identified in
[PROVENANCE.md](PROVENANCE.md). The report supplies the full constructions and
assumptions.

## OCT-01 — Insufficient message-collision strength

**Affected:** reference and optimized SM3 families at levels 256 and 512;
additional SHAKE family at level 512.  
**Category:** concrete hash instantiation and advertised security level.  
**Report:** Sections 3 and 11.

In the SM3 counter construction, equal-length messages that reach the same
256-bit chaining state before a common suffix produce identical outputs for
every counter. For the fixed public-key prefix in the message-hash input, a
generic birthday search has work near 2^128 classical evaluations. One signing
query on one member of the collision pair transfers the signature to the
other. Expanding to a 1,024-bit message representative does not raise this
collision strength.

The SHAKE256 variant has generic collision strength capped at 256 bits, also
insufficient for the 512-bit classical target. This is the standard capacity
limit for the message-hash role, not an asserted defect in SHAKE256.

**Evidence:** a 12-bit toy collision and propagation experiment in
[verify_kdf_collision.py](code/verify_kdf_collision.py); actual SM3 continuation
checks in [verify_sm3_mechanism.c](code/verify_sm3_mechanism.c);
[toy output](evidence/verify_kdf_collision.txt) and
[C results](evidence/original_code.json). A supplied-state 20-step compression
collision is checked using an adaptation of the submitted function in
[verify_sm3_reduced_collision.c](code/verify_sm3_reduced_collision.c), with
[recorded output](evidence/verify_sm3_reduced_collision.txt). An end-to-end
one-query transfer is also executed in the [48-bit reduced-state model](code/signature_transfer/run_signature_transfer.py),
with its [campaign](evidence/signature_transfer/campaign_48.json),
[full-width replay](evidence/signature_transfer/probe_fullwidth.json), and
[independent public-artifact checks](evidence/signature_transfer/public_artifact_verification.json).

The example uses the two second blocks from Mendel, Nad, and Schläffer,
[CT-RSA 2013, Table 3](https://doi.org/10.1007/978-3-642-36095-4_12).
They differ in eight bytes and collide at the published output after 20
steps and XOR feed-forward from the supplied chaining input. The adapter is
cross-checked against the unmodified submitted function at 64 steps, where
the pair does not collide. Common padding and all 64 tested counter
continuations preserve equality in the custom-IV, 20-step variant.

**Limit:** the 20-step replay supplies the paper's chaining input directly and
is not an Octarine signature transfer. The separate end-to-end experiment
reduces the SM3 state to 48 bits and tiles its live bytes into a digest; both
changes apply to all SM3 roles. It demonstrates the transfer mechanism on that
variant, not a forgery under the submitted 256-bit profile. The full-width
replay of the same pair has different states and representatives. The
classical work figures for the deployed function remain generic bounds; the
quantum collision estimate in the report counts queries and requires
substantial additional resources. The published reduced-step collision is
attributed prior work, not a new attack on reduced-step SM3.

**Required correction:** define every hash role and its required strength,
replace inadequate instantiations or lower the security claims, and revise
the security analysis accordingly.

## OCT-02 — Polynomial solutions of the estimated 512-level SIS problem

**Affected:** the relaxed homogeneous SIS instances used in the 512-level EUF
and SUF estimates, for both hash families.  
**Category:** hardness model and security estimation.  
**Report:** Section 6.

For q = 2^24 and a matrix with two invertible square blocks modulo 2, two binary
linear solves construct a nonzero kernel vector of infinity norm q/4 =
4,194,304. The event has limiting probability about 8.34% for two independent
uniform square blocks. Thus a polynomial algorithm has constant success
probability on the claimed random-instance distribution.

The norm is below both relaxed bounds used at level 512:
4,194,306 (SUF) and 4,947,969 (EUF). The included witness has 5,120 rows and
10,240 columns; adding a zero block gives the corresponding 15,360-column
instance.

**Evidence:** [composite_sis.py](code/composite_sis.py),
[saved certificate](data/sis_witness_5120.npz),
[generation record](evidence/composite_sis_5120.json),
[separate NumPy verifier](code/verify_sis_witness.py), and
[full replay comparison](evidence/check_replay.json). A standard-library
[small-dimension demonstration](code/sis_mod4_demo.py) is also included.

**Limit:** the nonzero response block has norm 4,194,304 and fails the actual
strict response-difference limit of 4,193,956. This certificate is not an
Octarine signature forgery. The generator conditions on the publicly testable
invertibility event; its recorded runs do not estimate the event probability.
The probability follows from the binary-matrix formula in the report.

**Required correction:** analyze the constrained extraction relations,
including separate block bounds and challenge/oracle consistency. Generic SIS
lattice-reduction estimates cannot establish security for a problem with this
polynomial attack.

## OCT-03 — A 344-bit equivalent-secret descriptor

**Affected:** reference and optimized SM3 families; below the advertised target
at level 512.  
**Category:** secret expansion and equivalent-key search.  
**Report:** Section 5.

The 141-byte secret-expansion input has a common two-block prefix across all
secret polynomials. A 256-bit SM3 chaining state and the remaining 11 seed
bytes determine every output stream once the public domain fields are fixed.
This gives a 344-bit descriptor of the complete secret vector s1.

At most 2^344 descriptor evaluations suffice to enumerate a candidate that
matches the public key. From a matching s1 and the public matrix, the other
algebraic signing fields can be derived and a new signing-randomness key can
be chosen. The generic quantum bound is of order 2^172 predicate queries,
with candidate-evaluation costs additional.

**Evidence:** [verify_secret_descriptor.c](code/verify_secret_descriptor.c)
reconstructs every secret-expansion byte from the descriptor in all six
SM3 implementation/profile combinations. See
[C results](evidence/original_code.json).

**Limit:** the experiment uses a deterministic known seed. It does not perform
unknown-key search, recover the original seed, or bound the entropy of every
stored secret-key field. This bound is less severe than OCT-01 for the current
SM3 family, but concerns a separate hash role and matters to a revision.

**Required correction:** analyze the actual preimage/equivalent-key search space
of secret expansion. Replacing only the message hash does not remove this
descriptor.

## OCT-04 — Challenge expansion differs between the PDF and code

**Affected:** reference, optimized, and additional implementations at levels
128 and 256.  
**Category:** specification conformance and interoperability.  
**Report:** Section 10.1.

Algorithm 2 requests ceil(tau/8) sign-stream bytes: 2, 5, and 11 for the three
levels. Every implementation requests 11. Because the requested output length
is hashed into the domain header, taking a prefix of the longer stream changes
the challenge map.

For an all-zero challenge seed:

| Family | Level | PDF-length stream | Prefix of implemented stream | Differing used sign bits |
|---|---:|---|---|---:|
| Reference and optimized SM3 | 128 | 3b80 | 9bc5 | 5 |
| Reference and optimized SM3 | 256 | 120021c7c5 | 82543e7c36 | 18 |
| Additional SHAKE | 128 | 6da1 | 3930 | 6 |
| Additional SHAKE | 256 | 40f92b5756 | 3598e19826 | 18 |

The index stream is unchanged, so these sign-bit differences change the
expanded challenge. All three families agree with the PDF's sign-stream
length at level 512.

**Evidence:** the source checker in
[verify_additional_findings.py](code/verify_additional_findings.py),
[verify_challenge_stream.c](code/verify_challenge_stream.c), and
[executed results across all nine combinations](evidence/original_code.json).

**Limit:** this establishes a deterministic disagreement, without establishing
lower challenge entropy or a forgery. Cross-testing implementations that share
the same discrepancy does not settle specification conformance.

**Required correction:** select one normative map, version it, and provide
vectors that compare the specification and implementations.

## Additional assessment

The following are included in the report without promoting an unproved
consequence to a break:

| Topic | Established observation | Qualification |
|---|---|---|
| Challenge search, Section 4 | A fixed challenge and zero response/hint give a generic forgery strategy; level 128 has about 65.79 Grover-query bits. | A query count alone does not establish a break of an 80-bit gate-cost claim. |
| Proof instantiation, Section 7 | Statistical losses, simulator analysis, seeded sampling, and reduction hypotheses are not quantitatively discharged. | An explicit signing simulator is possible in principle; impossibility is not claimed. |
| Ring structure, Section 8 | Nonunit mass, a two-component decomposition at k = 5, and nonisometric embedding transport are explicit. | The supplied projection diagnostic destroys coefficient smallness and is not a useful forgery. |
| Maximality, Section 8.4 | The submitted profiles pass the required local checks, with the cited published Fermat factorization. | A separate small-parameter counterexample refutes unrestricted generalization, not these profiles. |
| Rounding and encoding, Sections 9–10 | Size arithmetic and small-modulus identities check out; normative boundary and interface issues remain. | This is not a full implementation or side-channel audit. |

## Relation to public evaluation reports

Generic hash-state/capacity limits and specification mismatches are established
categories of cryptographic review. For example, the public
[DOVE report, sign-09-1](https://ngcc.dev/reports/sign-09.html#sign-09-1)
discusses an SM3 expansion collision limit, and
[CEDRUS-alpha, sign-04-3](https://ngcc.dev/reports/sign-04.html#sign-04-3)
records a specification/implementation discrepancy.

These are related examples, not validation of the Octarine-specific
constructions. This package makes no priority claim for the general
collision-propagation method and no claim that these Octarine findings have
been accepted by NGCC.

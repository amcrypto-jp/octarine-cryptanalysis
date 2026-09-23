# Changes

## Version 1.0.1 — 23 September 2026

- Add an attributed replay of the second-block collision pair from Mendel,
  Nad, and Schläffer, CT-RSA 2013, Table 3, using its supplied chaining input
  and a 20-step adaptation of the submitted SM3 compression function.
- Cross-check the adapter against the unmodified 64-step function, require
  differing full-step states and full SM3 digests, and verify common padding
  and 64 counter continuations from the computed reduced-step states.
- Integrate the replay into the hash-verified original-source driver and
  record its output alongside the other C checks.
- Add a portable, hash-verified 48-bit reduced-state model that executes the
  chosen-message signature-transfer mechanism end to end with one signing
  query, plus full-width, public-artifact, and negative controls. The state
  truncation and injective digest tiling affect all SM3 roles in the model;
  this is not a forgery against the submitted 256-bit profile.
- Update attribution, finding scope, reproduction instructions, report
  editions, issue draft, citation metadata, and package checksums.

The generic Octarine bounds and the four finding classifications are unchanged.
The reduced-step replay does not establish a full SM3 collision or reach
Octarine's public-key prefix. The separate signature-transfer execution uses a
48-bit model and does not transfer a signature under the submitted parameters.

## Version 1.0.0 — 23 September 2026

Initial publication package for *Security Analysis of ARCANE-Octarine*.

- Standalone report covering the submitted parameters, hash instantiations,
  security estimates, proof obligations, ring structure, and conformance.
- Four indexed findings with affected profiles and explicit limits on the
  claimed consequences.
- Full-dimension relaxed SIS certificate, separate verifier, deterministic
  replay, and small standard-library demonstrations.
- Optional hash-verified C checks across nine challenge configurations and six
  SM3 equivalent-secret configurations, plus an SM3 continuation test.
- PDF, Markdown, LaTeX, and offline HTML editions; citation metadata,
  provenance, licenses, and AI-use disclosure.
- Recorded successful full reproduction, input and package manifests, and
  scripts to rebuild the documents and release archive.

No practical signature forgery, full SM3 collision, unknown-key recovery, or
external acceptance of the findings is claimed.

# Octarine cryptanalysis

**Security Analysis of ARCANE-Octarine**  
Mounir IDRASSI · [mounir@amcrypto.jp](mailto:mounir@amcrypto.jp)  
Version 1.0.0 · 23 September 2026

This repository contains a standalone technical report, research programs, and
reproducible evidence for the submitted ARCANE-Octarine signature scheme. It
covers all three parameter levels and the reference SM3, optimized SM3, and
additional SHA3/SHAKE implementation families.

Read the **[PDF report](REPORT.pdf)**, [Markdown source](REPORT.md), or
[offline HTML edition](REPORT.html). The HTML edition uses native MathML and
can be opened locally in a modern browser without a network connection.

## Principal findings

| ID | Result | Interpretation |
|---|---|---|
| OCT-01 | SM3 counter expansion permits a generic message-collision signature-transfer attack near 2^128 classical work. SHAKE256 also caps message-collision strength at 256 bits. | The SM3 256- and 512-level claims, and the SHAKE 512-level claim, exceed these bounds. No full SM3 collision was computed. |
| OCT-02 | Binary linear algebra solves the relaxed homogeneous SIS problems used in the 512-level estimates on a constant fraction of random instances. A full-dimension certificate is included. | This invalidates hardness of the estimated auxiliary problem. The certificate fails the actual signature response bound and is not a forgery. |
| OCT-03 | A 344-bit descriptor determines the complete SM3-expanded signing secret polynomial vector. | Equivalent-key search takes at most 2^344 candidates, below the 512-bit claim. The demonstration uses a known seed; it does not recover an unknown key. |
| OCT-04 | Algorithm 2 and all three implementation families expand challenges differently at levels 128 and 256. | Executed C checks confirm a specification-conformance defect. No entropy loss is inferred from it alone. |

The report also analyzes challenge-search forgery bounds, quantitative proof
gaps, ring structure, embedding distortion, and rounding/encoding details.
Quantum query counts are distinguished from gate costs. See
[FINDINGS.md](FINDINGS.md) for precise scope and evidence.

The evidence does not establish a practical Octarine forgery. It does establish
concrete limits below several advertised security levels and a failure of the
512-level relaxed SIS hardness model.

## Reproduce

Python's standard library is sufficient for integrity verification, parameter
and rounding checks, the toy collision experiment, and small SIS examples:

~~~sh
python3 verify_package.py
python3 run.py
~~~

For the full mathematical replay, including the 5,120-row SIS certificate:

~~~sh
python3 run.py --full --sage sage
~~~

Alternatively, replace *--sage sage* with
*--sage-python /path/to/sage-env/bin/python*. Sage and NumPy must be available
in that interpreter. Results are written to *verification-output/*.

The original specification and implementations are not bundled. To execute the
C checks against a separately obtained submission:

~~~sh
python3 run.py --submission-root /path/to/Octarine
~~~

The runner verifies 397 original-file hashes before compiling any C driver.
See [REPRODUCING.md](REPRODUCING.md) for dependencies, individual checks, exact
coverage, and the recorded environment. All quick checks, the full Sage replay,
and the optional original-source C checks passed in the recorded
[publication run](evidence/summary.json).

## Contents

| Path | Purpose |
|---|---|
| [REPORT.pdf](REPORT.pdf), [REPORT.md](REPORT.md), [REPORT.html](REPORT.html), [REPORT.tex](REPORT.tex) | Standalone report and rendered editions |
| [FINDINGS.md](FINDINGS.md) | Finding index, affected profiles, evidence, and limits |
| [code/](code/) | Inspectable research and verification programs |
| [data/](data/) | Full SIS witness and input identities |
| [evidence/](evidence/) | Recorded outputs and reproduction summary |
| [PROVENANCE.md](PROVENANCE.md) | Evaluated snapshot, acquisition links, and evidence provenance |
| [REPRODUCING.md](REPRODUCING.md) | Execution and document-build instructions |
| [CITATION.cff](CITATION.cff), [references.bib](references.bib) | Citation metadata and bibliography |
| [AI_DISCLOSURE.md](AI_DISCLOSURE.md), [LICENSING.md](LICENSING.md) | AI-use disclosure and reuse terms |
| [CHANGES.md](CHANGES.md) | Version history |
| [ABSTRACT.txt](ABSTRACT.txt) | Plain-text abstract |

## Citation and reuse

Suggested citation:

> Mounir IDRASSI. *Security Analysis of ARCANE-Octarine*. Version 1.0.0,
> 23 September 2026. https://github.com/amcrypto-jp/octarine-cryptanalysis

Original research software is licensed under [MIT](LICENSE). The report,
documentation, and original results are licensed under
[CC BY 4.0](LICENSES/CC-BY-4.0.txt); see [LICENSING.md](LICENSING.md) for scope.

DeepSeek V4 Pro 0831, Meta Muse Spark 1.3, and OpenAI Codex were used in preparing
the work. Codex contributed analysis, cross-checking, reproducibility code and
execution, and publication preparation. Mounir IDRASSI is responsible for the
report and its conclusions. The complete disclosure is in
[AI_DISCLOSURE.md](AI_DISCLOSURE.md) and in the report.

---
title: "Security Analysis of ARCANE-Octarine"
subtitle: "Concrete attack bounds, proof obligations, and specification consistency — Version 1.0.0"
author: "Mounir IDRASSI"
date: "23 September 2026"
lang: en-US
fontsize: 10pt
papersize: a4
geometry: margin=24mm
colorlinks: true
linkcolor: MidnightBlue
urlcolor: MidnightBlue
toc-depth: 2
header-includes:
  - \usepackage{microtype}
  - \usepackage{xurl}
  - \setlength{\emergencystretch}{3em}
---

# Abstract {.unnumbered}

ARCANE-Octarine is a Fiat–Shamir signature scheme using learning with rounding over a radical ring and a power-of-two modulus. This document analyzes the submitted 128-, 256-, and 512-level profiles, their concrete hash instantiations, the relations used in the security estimates, and the supplied implementations. It gives a chosen-message signature-transfer attack through the SM3 counter-mode hash construction, a secret-free challenge-search forgery, a 344-bit description of an equivalent signing secret in the SM3 family, and a polynomial-time solution of the relaxed homogeneous SIS instances used in the 512-level estimates. The last result is an attack on the estimated auxiliary problem; its witness violates the stricter response bound of the actual signature relation. The document also identifies missing quantitative proof arguments, modular structure requiring analysis, and deterministic disagreements between Algorithm 2 and all implementation families at levels 128 and 256.

The evidence does not establish a practical forgery or recovery of an unknown signing key at the submitted parameters. It does establish that the advertised security claims are unsupported, with explicit generic attack bounds far below the 256- and 512-bit classical targets for the SM3 implementations. Neither supplied hash family supports 512-bit message-collision strength. Continued consideration requires revised primitives, parameters, normative specifications, and analysis of the actual verification relations.

# 1. Scope, notation, and interpretation

## 1.1 Evaluated artifact

The subject is *ARCANE-Octarine: Algorithm Specifications and Supporting Documentation*, attributed in the submission to the ARCANE team [S], together with the supplied reference SM3, optimized SM3, and additional SHA3/SHAKE implementation families. The specification is a 53-page PDF, identified by SHA-256:

~~~text
b88fbdd019beb8f0ae85c1554b48c87a42c5447b39171ce559ae30988c1bf09f
~~~

All specification page references below use printed page numbers; the corresponding one-based PDF page number is two greater. Findings apply to this snapshot and the source files identified in the evidence manifest [E9]. They do not presume that a future revision has the same behavior.

Author contact: [mounir@amcrypto.jp](mailto:mounir@amcrypto.jp). Report and original results: CC BY 4.0; research software: MIT. The accompanying repository is [octarine-cryptanalysis](https://github.com/amcrypto-jp/octarine-cryptanalysis). The evidence inventory in Section 12 identifies the programs and data needed to reproduce the checks.

An *exact construction* below is a mathematical algorithm with stated hypotheses. A *generic work bound* assumes the indicated idealized hash or search model. An *estimator output* describes a modeled attack, and does not lower-bound the cost of every possible attack. A *diagnostic* tests one property or example and does not establish security.

## 1.2 Parameters and verification

Write

$$
R_q=(\mathbb Z/q\mathbb Z)[y]/(y^{1024}+1),\qquad
S_q=R_q[x]/(x^k-y-2),\qquad N=1024k,
$$

where $q=2^{24}$. Norms refer to coefficient infinity norms in the submitted $(y^i x^j)$ representation. Put $g=q/p$ and $m=2\gamma_2$. A challenge $c$ is a polynomial in $R_q$, embedded in the constant $x$ component of $S_q$.

| Parameter | Octarine-128 | Octarine-256 | Octarine-512 |
| :--- | ---: | ---: | ---: |
| $k$ | 1 | 2 | 5 |
| $N$ | 1024 | 2048 | 5120 |
| $p$ | $2^{21}$ | $2^{22}$ | $2^{22}$ |
| $\eta=q/(2p)$ | 4 | 2 | 2 |
| $d$ | 11 | 13 | 14 |
| $\tau$ | 16 | 36 | 87 |
| $\gamma_1$ | $2^{18}$ | $2^{19}$ | $2^{21}$ |
| $\gamma_2$ | $2^{17}$ | $2^{18}$ | $2^{20}$ |
| $\beta=\tau\eta$ | 64 | 72 | 174 |
| $\omega$ | 79 | 210 | 399 |
| Challenge-seed bytes | 32 | 64 | 128 |
| Claimed classical / quantum bits | 128 / 80 | 256 / 128 | 512 / 256 |

Key generation produces $s_1$ with coefficients in $[-\eta,\eta-1]$, and defines

$$
b=\lfloor(p/q)As_1\rceil,\qquad
s_2=As_1-gb,\qquad b=b_1 2^d+b_0.
$$

The public key contains the seed for $A$ and the compressed value $b_1$. For a message $M$, the verifier computes

$$
tr=H_{tr}(pk),\quad \mu=H_\mu(tr,M),\quad
c=\operatorname{SampleInBall}(\widetilde c),
$$

$$
v=Az-cgb_1 2^d,\qquad
w_1=\operatorname{UseHint}(h,v,m).
$$

After canonical decoding, acceptance requires

$$
\|z\|_\infty<\gamma_1-\beta,\qquad
\operatorname{HW}(h)\leq\omega,\qquad
\widetilde c=H_{ch}(\mu,w_1).
$$

Domain labels, output lengths, and length-delimited fields are implicit in these hash expressions. All three profiles have 128-byte $tr$ and $\mu$ values. The stored challenge seed has $2\lambda$ bits, where $\lambda$ is the profile label.

EUF-CMA means existential unforgeability under chosen-message attack; SUF-CMA additionally prohibits a fresh signature on a previously signed message. Every EUF-CMA attack is also a SUF-CMA attack.

# 2. Main findings and their scope

| Finding | Established result | Scope limit |
| :--- | :--- | :--- |
| SM3 message-hash construction | An equal-length internal-state collision transfers a signature; generic classical work is about $2^{128}$ | No full SM3 collision was computed |
| Challenge search | A fixed challenge with $z=h=0$ gives a complete generic forgery strategy | Quantum figures count oracle queries, not logical gates |
| SM3 secret expansion | A 344-bit descriptor generates the complete $s_1$; equivalent-key search needs at most $2^{344}$ candidates | No unknown-key search was performed |
| 512-level relaxed SIS | A nonzero norm-$q/4$ vector is found by binary linear algebra with constant success probability | The vector fails the actual stricter response bound |
| Proof instantiation | Statistical terms, simulator behavior, seeded sampling, and relation modeling are not concretely discharged | This does not prove that a suitable proof is impossible |
| Ring structure | Nonunit mass, a two-component decomposition at $k=5$, and even-weight challenge restrictions are explicit | A useful projection or transcript attack remains unestablished |
| Specification conformance | Algorithm 2 and every source family use different challenge maps at levels 128 and 256 | This alone does not show lower challenge entropy |

The central recommendation is to withhold endorsement of the submitted security levels and withdraw the present 512-bit claim. Sections 3–6 give the attack constructions and bounds. Sections 7–10 distinguish the remaining proof, algebraic, and implementation issues from attacks.

# 3. Hash instantiation and chosen-message signature transfer

## 3.1 The implemented counter construction

The specification names an SM3-based pseudoXOF for the reference and optimized families, but does not give its full algorithm on pp. 16–17. The supplied function *pseudoXOF* in the corresponding *utils/auxfunc.c* files, starting at line 482, implements

$$
\operatorname{XOF}_{\ell}(X)=
\operatorname{prefix}_{\ell}\big(
\operatorname{SM3}(X\Vert\operatorname{ctr}_{32}(1))
\Vert\operatorname{SM3}(X\Vert\operatorname{ctr}_{32}(2))
\Vert\cdots\big),
$$

where $\ell$ is the output length in bits and the counter is encoded big-endian. The parameter macros bind this construction to the signature hash roles and to public, secret, mask, and challenge expansion.

SM3 uses a 256-bit chaining value and 512-bit message blocks. Suppose two distinct equal-length strings reach the same chaining value at the same block boundary, before a common suffix. For every counter value, the subsequent input blocks and length padding are identical. Determinism then implies equality of every counter output block, and hence of the entire requested XOF output.

This argument requires a collision before the common suffix. Equality of only the first final digest block, without equality of the relevant internal state, would not suffice.

For an idealized 256-bit state map, birthday search gives about $2^{128}$ classical evaluations. Generic quantum collision algorithms give an approximately $2^{256/3}=2^{85.33}$ query bound, with substantial storage and coherent-computation requirements [BHT98]. These are generic resource bounds, not measured attack implementations. For an output shorter than 256 bits, its ordinary output-length collision bound must also be included.

The toy program [E3] exhibits a state collision and its propagation through 64 output blocks. The C program [E4] checks SM3 continuation against the submitted implementation. It forces the same internal state to validate propagation; it does not find colliding SM3 messages.

## 3.2 Consequence for unforgeability

For a fixed public key, the signature uses $M$ only through $\mu=H_\mu(tr,M)$. An adversary can choose sufficiently long, equal-length messages with a common alignment prefix and vary a complete message block. The encoded length fields remain identical. A collision of the internal state after that block, followed by the same suffix, makes the complete 1024-bit $\mu$ equal.

The attack is:

1. Find distinct messages $M_0,M_1$ with the same $\mu$ using the state-collision construction.
2. Request a signature $\sigma$ on $M_0$.
3. Output $(M_1,\sigma)$.

The verifier performs identical computations for the two messages, so $\sigma$ verifies for the never-signed $M_1$. The construction breaks EUF-CMA and message binding at the collision-search cost. It needs one signing query. Length delimiters and domain separation prevent ambiguity between inputs; they do not prevent equal-length collisions within one domain.

Consequently, the SM3 families have a generic classical signature-transfer bound near $2^{128}$ at every profile. This is at the 128-level target, and far below the 256- and 512-level targets. It does not by itself establish an attack in a two-key exclusive-ownership game.

## 3.3 SHAKE and per-role requirements

The additional implementation uses SHAKE256 for signature hashes and secret/challenge expansion, and SHAKE128 for public expansion. FIPS 202, Appendix A, gives SHAKE256 collision strength $\min(d_{\mathrm{out}}/2,256)$ for $d_{\mathrm{out}}$ output bits [F202]. Thus the 1024-bit message representative has generic collision strength capped at 256 bits. Increasing its output length cannot supply the claimed 512-bit classical message-binding strength.

The preimage entry in FIPS 202 is a lower bound. It should not be restated as a universal 256-bit upper bound on every SHAKE256 preimage problem. The conclusion here concerns collisions in the message-hash role.

| Backend for $H_\mu$ | Generic classical collision exponent | Consequence |
| :--- | ---: | :--- |
| SM3 counter construction | 128 | Insufficient for 256- and 512-bit claims |
| SHAKE256, 1024-bit output | 256 | Insufficient for a 512-bit claim |

The specification's generic requirement of $\lambda/2$ collision bits and $\lambda$ preimage bits is insufficient for this role. If $\lambda$ denotes a claimed classical unforgeability work factor, the signature-transfer route must itself cost at least $2^\lambda$ in the chosen resource convention. A per-role security table is necessary; a long output is not evidence that the underlying construction meets that table.

# 4. A secret-free challenge-search forgery

## 4.1 Construction

Let $C_\tau$ be the set of signed weight-$\tau$ polynomials in $R_q$:

$$
|C_\tau|=\binom{1024}{\tau}2^\tau.
$$

Choose any fixed $c_0\in C_\tau$ and compute from the public key

$$
u=\operatorname{HighBits}(-c_0gb_1 2^d,m).
$$

For each candidate message $M$, compute $\mu=H_\mu(tr,M)$ and $\widetilde c=H_{ch}(\mu,u)$. If $\operatorname{SampleInBall}(\widetilde c)=c_0$, output the canonical encoding of $(\widetilde c,z=0,h=0)$.

The verifier recomputes $c=c_0$ and $v=-c_0gb_1 2^d$. Since $\operatorname{UseHint}(0,v,m)=\operatorname{HighBits}(v,m)$, it obtains $u$ and reconstructs the supplied $\widetilde c$. The response and hint bounds hold. Therefore a successful trial is an accepted signature obtained without any signing query.

In the ideal challenge-expansion model, a fresh trial succeeds with probability $1/|C_\tau|$. For a fixed deterministic expander, the exact probability is the mass of $c_0$ under a uniformly sampled challenge seed; uniformity is the modeling assumption behind the stated entropy. This construction also applies to the implementation's alternative sign-stream map.

## 4.2 Work bounds and units

Classical search needs approximately $|C_\tau|$ trials. Grover search reduces this to order $\sqrt{|C_\tau|}$ predicate queries [G96]. The entropy calculation in [E1] gives:

| Profile | $\log_2\lvert C_\tau\rvert$ | Classical trial exponent | Grover query exponent |
| :--- | ---: | ---: | ---: |
| 128 | 131.579934 | 131.579934 | 65.789967 |
| 256 | 257.007637 | 257.007637 | 128.503819 |
| 512 | 512.004143 | 512.004143 | 256.002071 |

The 128 profile is 14.21 bits below an 80-bit quantum-*query* target. A comparison with an 80-bit logical-*gate* target requires a reversible circuit, success-probability convention, memory model, and depth accounting. None is supplied here. In particular, a query exponent is not an unconditional gate-count break.

The 256 and 512 profiles exceed their corresponding nominal targets by only 1.008 and 0.004 classical trial bits, or 0.504 and 0.002 Grover-query bits. These are single-route differences, not certified margins against every attack. The longer stored challenge seed does not change the search space used by this construction.

The theorem's $2^{-|\widetilde c|}$ term can bound an unqueried random-oracle guess. It does not bound the attack above, which makes the relevant query and searches for a matching expanded challenge.

For illustration, $\tau=21$ is the first weight giving at least 80 Grover-query bits at $n=1024$; it gives 82.616220 bits. This is not a validated replacement profile. At level 128 it also raises $\beta$ from 64 to 84, the two-test expected repetition count from 2.129771 to 2.692582, and the stated EUF residual bound from 393,217 to 434,177 [E1]. Compression and hint behavior must be analyzed again.

# 5. A 344-bit descriptor for an equivalent SM3 signing secret

## 5.1 Byte layout

The compact secret-XOF encoding in the SM3 implementations has the following form before the outer counter:

| Field | Bytes |
| :--- | ---: |
| Fixed prefix, role, level, rank, output length, seed length | 11 |
| Secret seed $\rho'$ | 128 |
| Polynomial index | 1 |
| Lane index, zero for $s_1$ | 1 |
| Total | 141 |

The first 128 input bytes are two complete SM3 blocks. They contain the fixed header and the first 117 bytes of $\rho'$, and are shared by every polynomial expansion in one profile. The polynomial index occurs later.

Let $V$ be the 256-bit chaining state after those two blocks. Every remaining secret-dependent input byte is in the final 11 bytes of $\rho'$. Hence

$$
D=(V,\rho'[117:128])
$$

is a descriptor of length $256+88=344$ bits from which the complete $s_1$ can be generated. Polynomial indices, lane identifiers, counter values, total input lengths, and padding are fixed or public. This is an exact data-flow property of the implemented construction.

## 5.2 Equivalent-key search

An adversary can enumerate all descriptors $D$, continue SM3 from the candidate state, and decode the resulting streams into a candidate $s_1$. With $A$ regenerated from the public seed, it can compute the candidate rounded $b$, compress to $b_1$, and compare with the target public key.

The actual descriptor is included in this finite search. A candidate yielding the public key supplies the same KeyGen relations: derive $s_2=As_1-gb$ and $b_0=b-b_1 2^d$, retain the public seed and $tr$, and choose a new signing-randomness key $K$. Verification does not test the original $K$ or require that the new secret fields arose from the original KeyGen seed.

Thus an equivalent signing key has a search bound of at most $2^{344}$ descriptor evaluations, or order $2^{172}$ Grover predicate queries. Candidate evaluation includes hash expansion and public-key arithmetic. The original key-generation seed, public-seed derivation, and stored secret-key bytes need not be recovered.

This bound is incompatible with the 512-bit classical / 256-bit quantum target under the corresponding search conventions. It is separate from, and more expensive than, the SM3 message-collision forgery. It does not apply this particular descriptor calculation to SHAKE.

The result is a search-space bound on an equivalent signing key. It is not a measurement of the entropy of every stored secret-key field, and no unknown-key recovery experiment is claimed. The relevant source locations are the compact encoding in *hash_domain.h*, secret expansion in *arith/uniform.c*, and *pseudoXOF* in *utils/auxfunc.c* [E9]. The executable check [E11] reconstructs every secret-expansion byte from this descriptor for a known test seed in all six SM3 implementation/profile combinations.

# 6. Polynomial solutions of the relaxed 512-level SIS instances

## 6.1 The estimated problems

The specification's Appendix A passes ordinary homogeneous infinity-norm SIS instances to lattice-estimator. Their dimensions and single bounds are

$$
(N,3N,q,B_{\mathrm{EUF}}),\qquad (N,2N,q,B_{\mathrm{SUF}}),
$$

where

$$
B_{\mathrm{EUF}}=\max\{\gamma_1-\beta,\;2\gamma_2+1+g\tau 2^{d-1}\},
$$

$$
B_{\mathrm{SUF}}=\max\{2(\gamma_1-\beta),\;4\gamma_2+2\}.
$$

At level 512,

$$
N=5120,\quad B_{\mathrm{EUF}}=4,947,969,\quad
B_{\mathrm{SUF}}=4,194,306.
$$

Both bounds exceed $q/4=4,194,304$.

## 6.2 A binary-linear-algebra construction

**Proposition.** Let $q$ be divisible by four. For a matrix $M$ with at least $2N$ columns, suppose its first two $N\times N$ blocks $B,C$ are invertible modulo 2. A nonzero vector $X$ with $MX=0\bmod q$ and $\|X\|_\infty=q/4$ can be constructed in polynomial time.

**Proof.** Put $B_2=B\bmod2$ and $C_2=C\bmod2$. Solve

$$
B_2u=C_2\mathbf 1
$$

over $\mathbb F_2$ and lift $u$ to a binary integer vector. Then $Bu+C\mathbf1$ is even. Define

$$
d_2=(Bu+C\mathbf1)/2\bmod2
$$

and solve $C_2v=d_2$, again lifting $v$ to a binary vector. The vector

$$
w=(u,\mathbf1-2v,0,\ldots,0)
$$

satisfies

$$
Mw=Bu+C\mathbf1-2Cv=0\bmod4.
$$

Its second block consists of $\pm1$, so it is nonzero and has infinity norm one. Set $X=(q/4)w$. Then $MX=0\bmod q$ and $\|X\|_\infty=q/4$. This uses two linear solves over $\mathbb F_2$ and elementary integer operations. $\square$

For a uniformly random binary square matrix, the invertibility probability is

$$
\prod_{j=1}^{N}(1-2^{-j})\longrightarrow 0.288788\ldots.
$$

The two-block event has limiting probability approximately 0.0834. It is publicly testable. Consequently, the construction succeeds in polynomial time on a constant fraction of uniformly random SIS instances. A constant success probability is sufficient to invalidate a cryptographic hardness claim for this distribution.

The result applies to both Appendix A instances at level 512. Extra columns are assigned zero.

## 6.3 Evidence and structured extension

The artifact [E5] records an $N=5120$ run with a norm-4,194,304 witness. It checks the relation modulo 4 and a random full-modulus lift modulo $2^{24}$. The recorded run took 10.56 seconds including generation, solving, checking, and storage; this is one illustrative run, not a general benchmark. It samples each block until the public invertibility condition holds. The probability claim comes from the formula above, not from this conditioned experiment. The saved witness can be checked independently without trusting the reported timing.

For the structured relation $A\Delta z-\Delta r=0$, assume multiplication by $A\bmod2$ is invertible. Let $u$ be the binary lift of $A_2^{-1}\mathbf1$, and let $r$ be the centered lift of $Au\bmod4$. Every coefficient of $r$ is odd, hence in $\{-1,1\}$. Then

$$
(\Delta z,\Delta r)=(q/4)(u,r)
$$

solves the relation with both block norms at most $q/4$. For a uniformly sampled $A$ at $k=5$, the unit probability is $15/32$, as derived in Section 8.1.

## 6.4 Why this does not yet forge a signature

The actual SUF extraction on pp. 31–33 retains separate conditions:

$$
\|\Delta z\|_\infty<2(\gamma_1-\beta),\qquad
\|\Delta r\|_\infty\leq4\gamma_2+2.
$$

At level 512 the strict response threshold is 4,193,956. It is 348 below $q/4$; the largest permitted integer coefficient is 4,193,955, or 349 below $q/4$. The structured witness has a response coefficient equal to $q/4$ and therefore fails this condition. Even a short solution of the extracted relation would still need to be turned into accepting signatures with consistent commitments, hashes, and hints.

The EUF relation additionally restricts $c$ to an expanded sparse challenge and binds the target to the random oracle. Assigning zero to a relaxed challenge block does not satisfy that relation.

The established conclusion is that the *relaxed SIS instances used in the estimates are easy*. Hardness of the more constrained signature relations remains unestablished. The 691/692-bit figures in Table 2 cannot be interpreted as hardness of the relaxed problems, even if they correctly price one lattice-reduction attack.

All three profiles lie near analogous powers-of-two boundaries:

| Profile | Scale | Strict response-difference threshold | Residual bound |
| :--- | ---: | ---: | ---: |
| 128 | $q/32=524,288$ | $<524,160$ | 524,290 |
| 256 | $q/16=1,048,576$ | $<1,048,432$ | 1,048,578 |
| 512 | $q/4=4,194,304$ | $<4,193,956$ | 4,194,306 |

The modulo-4 construction does not automatically extend to the modulo-16 or modulo-32 problems needed for the first two rows. Those rows identify boundaries requiring analysis, not attacks on the 128 or 256 profiles.


# 7. What the security proof still needs

## 7.1 The assumed relations are more specific than generic SIS

Theorem 4, pp. 31–32, assumes hardness of a self-targeted relation. Given $(A,b)$, the adversary must produce $(\mu,z,\widetilde c,c,r,w_1)$ satisfying

$$
Az-cgb-r=mw_1,\qquad
c=\operatorname{SampleInBall}(\widetilde c),\qquad
\widetilde c=H_{ch}(\mu,w_1),
$$

together with the response, challenge, and residual constraints. This is neither ordinary homogeneous SIS nor a target problem with an independently uniform right-hand side. Theorem 5 also retains two separate norm bounds in the homogeneous relation $A\Delta z-\Delta r=0$.

Appendix A estimates homogeneous SIS with $N$ rows, $3N$ or $2N$ columns, and one bound. Pricing lattice reduction on that relaxation does not establish hardness of the actual assumption. In particular, an efficient solution of the relaxation need not yield a forgery, while failure of one attack on the relaxation does not imply that all attacks on the original relation are expensive. Section 6 supplies an explicit omitted attack on the relaxation itself.

The key-generation hybrid uses *decision* RR-LWR with the submitted small-secret distribution. A search-LWE estimate does not establish that decisional assumption without a reduction applicable to the ring, basis, distribution, sample count, and rounding parameters.

## 7.2 An explicit signing simulator is possible in principle

The proof refers to a public transcript distribution without specifying an executable sampler or its acceptance probability. That omission should be repaired constructively.

The reduction receives the full $(A,b)$ and can compute $b_0$ even though it publishes only $b_1$. The following is a candidate simulator for a fresh idealized signing attempt with a fixed message representative $\mu$:

1. Sample $\widetilde c$ uniformly and expand $c$.
2. Sample $z$ uniformly in the strict response box $\|z\|_\infty<\gamma_1-\beta$.
3. Set $t=Az-cgb$ and $\delta=cgb_0$. Reject unless
   $\|\operatorname{LowBits}(t,m)\|_\infty<\gamma_2-\beta$ and
   $\|\delta\|_\infty<\gamma_2$.
4. Set $v=t+\delta$ and $h=\operatorname{MakeHint}(-\delta,v,m)$. Reject if $\operatorname{HW}(h)>\omega$.
5. Set $w_1=\operatorname{HighBits}(t,m)$ and program a fresh $H_{ch}(\mu,w_1)$ to $\widetilde c$.

For a real key, write $Y=z-cs_1$. The response box and $\|cs_1\|_\infty\leq\beta$ place $Y$ in the original mask box. Also,

$$
AY+cs_2=A(z-cs_1)+c(As_1-gb)=t.
$$

Thus, for one fresh idealized attempt, the change of variables $(Y,c)\leftrightarrow(z,c)$ matches the tests and hints, after conditioning on the response test. This observation does not require $AY$ for bounded $Y$ to be uniform modulo $q$. It gives a plausible route to a proof; it is not a completed adaptive simulation.

A full argument must handle rejected attempts, prior oracle queries, repeated messages, the seeded mask stream and its lane indices, counter exhaustion, and the acceptance probability after replacing $b$ by uniform. One useful proof order is to establish the simulator in the real-key distribution and then analyze the RR-LWR hybrid. The specification must make clear which distributions and oracle interfaces each step uses.

## 7.3 Uninstantiated statistical losses

Theorem 4 introduces $\Delta_{\mathrm{sim}}$ and a commitment point-probability bound $2^{-\alpha}$, but supplies no concrete values. The resulting loss includes

$$
Q_S\Delta_{\mathrm{sim}}+Q_S(Q_H+Q_S)2^{-\alpha}.
$$

These terms cannot be omitted when assigning concrete security levels. For example, if $Q_S=Q_H=2^{64}$, making the programming term alone at most $2^{-\lambda}$ requires

$$
\alpha\geq\lambda+129.
$$

The required values are 257, 385, and 641 for the three nominal classical targets. Making the simulation term alone at most $2^{-\lambda}$ requires $\Delta_{\mathrm{sim}}\leq2^{-(\lambda+64)}$. These are illustrative necessary budgets for the individual terms, not a complete security calculation.

A basic counting argument can help with a commitment bound. For fixed $A$, let $K_A=|\ker(A:S_q\to S_q)|$. If $Y$ is uniform in the full mask box, then each value of $AY$ has at most $K_A$ preimages in that box. A high-bit vector has $m^N$ possible low-bit lifts. Since $\gamma_1=m$,

$$
\max_u\Pr[\operatorname{HighBits}(AY,m)=u]
\leq\frac{K_A m^N}{(2\gamma_1)^N}
=K_A2^{-N}.
$$

Conditioning on an acceptance event of probability $a$ can enlarge this bound by a factor $1/a$. This is a starting point for analysis, not a bound on every adaptive simulator transcript. It requires control of the kernel, acceptance probability, and conditioning on oracle history.

The theorem defines worst-case quantities over keys in the post-RR-LWR hybrid. Degenerate keys, such as $A=b=0$, show why an unrestricted uniform high-entropy claim cannot hold: the candidate commitment is then fixed. Such keys may have negligible probability, but a proof must explicitly isolate bad-key events and charge their probabilities.

## 7.4 The public seed remains observable

The public key contains $\rho$, from which an adversary can recompute $A$. Replacing the expanded $A$ by an independently uniform element while retaining an unprogrammed $\rho$ is distinguishable by that recomputation.

A seeded-sampler hybrid needs an explicit interface: for example, programming the selected public-expansion oracle calls and bounding the probability that those inputs were queried earlier. Merely assigning a symbol $\Delta_A$ to this step does not quantify its cost. Exact uniformity of coefficients produced by an ideal stream, which is particularly simple for a power-of-two modulus, is a different issue from consistency with the public seed.

## 7.5 LWR-to-LWE comparisons require their actual hypotheses

The bounded-error LWR result of Bogdanov et al. [BGM16, Theorems 1–2] uses an auxiliary error bound $B$ and the strict condition $q>2pB$. Its comparison includes a factor of the form

$$
(1+2pB/q)^{m_s},
$$

as well as a square of the relevant success probability. Here $m_s$ counts scalar coordinates in the comparison. The parameter $B$ is not automatically the scheme's $\eta$ or $\beta$.

For the submitted parameters, setting $B=\eta=q/(2p)$ violates the strict inequality. Setting $B=1$ satisfies it, but changes the error distribution being compared. For illustration, taking $m_s=N$ gives

$$
\log_2(1+2p/q)^N=N\log_2(1+1/\eta),
$$

which is approximately 329.65, 1198.00, and 2995.01 bits. These figures describe the size of this factor under that substitution; they are not standalone security losses for a fully instantiated radical-ring reduction.

The convenient sufficient condition $q\geq2m_sBp$ keeps this factor at most $e$; failure of that sufficient condition does not invalidate every possible reduction. The ring theorem additionally assumes a secret supported on units. The submitted secret distribution has substantial nonunit mass, and its coefficient representation must be matched to the theorem. The required decisional, distributional, and basis arguments remain to be supplied.

## 7.6 Classical ROM, deterministic signing, and stronger properties

The specification explicitly limits Theorems 4–5 to the classical random-oracle model. Its quantum attack estimates are not a QROM proof. A revised document should distinguish a conjectured post-quantum work factor from a proven QROM reduction.

The signing interface also permits deterministic operation. The specification correctly states that the randomized signing oracle used in its proof excludes this case. Repeated deterministic signing of the same message must repeat the signature, with the corresponding oracle and seed correlations. Claims covering that interface require a separate argument.

Theorem 6's collision-based reasoning for stronger binding properties is useful in the stated ideal model. Its instantiation still needs the actual primitive collision bounds and any high-min-entropy assumptions used for the weak non-resignability experiment. Neither a 1024-bit digest length nor the existence of a classical ROM unforgeability argument discharges those assumptions. No two-key exclusive-ownership attack is established in this document.

# 8. Ring structure, basis geometry, and challenge algebra

## 8.1 Reduction modulo 2 and nonunits

Eliminating $y$ gives

$$
S_q\cong(\mathbb Z/q\mathbb Z)[X]/\big((X^k-2)^{1024}+1\big).
$$

Modulo 2 the defining polynomial factors as follows:

$$
\begin{aligned}
k=1:\quad &(X+1)^{1024},\\
k=2:\quad &(X+1)^{2048},\\
k=5:\quad &(X+1)^{1024}
  (X^4+X^3+X^2+X+1)^{1024}.
\end{aligned}
$$

The quartic is irreducible over $\mathbb F_2$. An element modulo $2^{24}$ is a unit exactly when its reduction modulo 2 is coprime to these distinct factors. Hence the unit probabilities for a uniformly random element are

$$
\frac12,\quad\frac12,\quad
(1-2^{-1})(1-2^{-4})=\frac{15}{32}.
$$

The same probabilities hold in the ideal independent-coefficient model for $s_1$, because its coefficient intervals give unbiased independent parity bits. These facts are verified in [E2, E6].

For a fixed nonunit $s_1$, a uniform $A$ gives $As_1$ in the proper ideal generated by $s_1$, rather than uniformly over the ring. Thus an unconditional uniform-product heuristic is false. This does not itself refute RR-LWR: rounding can obscure ideal membership, and the assumption concerns rounded samples.

## 8.2 A decomposition of the $k=5$ ring

In $R_q$, set $t=y^{1229}$. Since $5\cdot1229=1\bmod2048$ and $y^{2048}=1$, one has $t^5=y$. Therefore

$$
a=x-t,\qquad
b=x^4+tx^3+t^2x^2+t^3x+t^4
$$

satisfy the exact identity $ab=x^5-t^5=2$. In particular, $a^{24}b^{24}=0$ modulo $2^{24}$.

There is also a coprime factorization. Hensel lifting starts from $t\bmod2$ and produces $r\in R_q$ such that $r^5=y+2$, since the derivative $5t^4$ is a unit. Then

$$
x^5-y-2=(x-r)
(x^4+rx^3+r^2x^2+r^3x+r^4).
$$

The quartic evaluated at $x=r$ is $5r^4$, a unit, so the factors are comaximal. The Chinese remainder theorem decomposes $S_q$ into components of ranks 1024 and 4096 over $\mathbb Z/q\mathbb Z$.

This is an exact algebraic decomposition. Its usefulness for an attack depends on what it does to the small-secret distribution and coefficient norm. In the diagnostic [E6], projecting one vector with original coefficients in $[-2,1]$ produced a maximum centered coefficient of 8,386,517, close to $q/2=8,388,608$. The explicit annihilators above had norms 8,370,000 and 8,260,608. Neither example supplies a short response satisfying the signature bounds.

These observations rule out using those particular projected vectors as immediate attacks. They do not rule out other projections, smaller annihilators, multilevel lifting, or attacks exploiting the two components jointly.

## 8.3 Even-weight challenges are nonunits

Over $\mathbb F_2$, signs disappear and a weight-$\tau$ challenge satisfies

$$
c(1)=\tau\bmod2.
$$

At levels 128 and 256, every challenge has even weight, so it is divisible by $y+1$ and is a nonunit. Multiplication by such a challenge has a nontrivial kernel. At level 512, the odd weight makes $c$ a unit in $R_q$ and hence in $S_q$.

Nonunit challenges are not, by themselves, a forgery. The extraction displayed in the specification does not simply invert $c$. Nevertheless, this deterministic restriction matters for distribution claims and for any argument involving multiplication by a challenge or challenge difference. Changing the parity of $\tau$ would require a fresh parameter and rejection analysis; it would not repair the other issues.

## 8.4 Maximality should be proved for the submitted parameters

For $f(X)=(X^k-2)^n+1$, direct resultant calculation gives

$$
|\operatorname{disc}(f)|=(nk)^{nk}(2^n+1)^{k-1}.
$$

The defining polynomial is irreducible for the relevant radical-ring family [BRVW26, Lemma 1]. To identify $\mathbb Z[X]/(f)$ with the full ring of integers, one must additionally exclude primes dividing the index.

For $n=1024$, $k\in\{1,2,5\}$, the calculations in [E2] establish the required local checks at 2 and, for $k=5$, at 5. At a prime dividing $2^{1024}+1$, with $p\nmid nk$, the Dedekind criterion reduces to whether $p^2$ divides that Fermat number. Its published complete factorization contains four distinct prime factors [B99]. Together, these facts establish maximality for the submitted profiles. The code checks the arithmetic of the factors; the primality of the largest factor relies on the published factorization.

A general claim for arbitrary ranks needs additional hypotheses. For example, take $n=2$, $k=17$, and

$$
f=(X^{17}-2)^2+1,\qquad g=(X-2)^2+1.
$$

Modulo 17, $f=g^{17}$. For $T=(f-g^{17})/17$,

$$
T\bmod(17,g)=8+10X,\qquad
\gcd(T,g)\bmod17=X-6.
$$

Since $g$ is squarefree modulo 17, Dedekind's index criterion implies that 17 divides the index. The exact calculation and irreducibility check appear in [E10]. This is a counterexample to unrestricted extrapolation; it is not an index defect in any submitted profile.

Even when the global index question is settled, maximality alone is not a hardness theorem. For arithmetic modulo $2^{24}$, the local analysis at 2 is the directly relevant order check.

## 8.5 Exact embedding distortion

Let $\zeta_j=\exp((2j+1)\pi i/n)$. In the coefficient basis $y^a x^b$, with $0\leq a<n$ and $0\leq b<k$, the singular values of the full complex evaluation matrix are

$$
\sqrt{nk}\,|2+\zeta_j|^{b/k},
\qquad 0\leq j<n,\quad0\leq b<k.
$$

To see this, group embeddings by $\zeta_j$ and by the $k$ choices of the radical root. Fourier orthogonality in the root index separates the $b$ blocks; Fourier diagonalization in the $y$ index then gives the displayed values. This uses the usual Euclidean norm on all complex embeddings, equivalent to the standard $\sqrt2$-weighted real representation.

The condition number is

$$
\kappa=(5+4\cos(\pi/n))^{(k-1)/(2k)}.
$$

At $n=1024$ it is approximately 1, 1.732049902, and 2.408222670. Small numerical matrix checks are recorded in [E10]. The distortion is modest, but the transport is not isometric for $k>1$; both covariance and volume factors must be accounted for in a reduction using canonical geometry. A generic estimator call does not incorporate them merely by setting the dimension to $nk$.

For $k=5$, the field is also not Galois over $\mathbb Q$. Normality would require all five radical roots and hence $\zeta_5$, alongside the existing $\zeta_{2048}$. The compositum has degree 4096, which cannot divide the field degree 5120. Cyclotomic Ring-LWE arguments using a full automorphism group therefore cannot be imported without checking their hypotheses. Complex conjugation still exists; non-Galois does not mean the absence of every symmetry.

# 9. Public transcript information and functional checks

## 9.1 Signatures give bounded observations of the omitted key part

An observer can reconstruct $c$ and $w_1$ from a valid signature and calculate

$$
e=\operatorname{ctr}_q(Az-cgb_1 2^d-mw_1).
$$

For an honest accepted signature, put $r_0=\operatorname{LowBits}(Az-cgb,m)$. The signing tests give

$$
e=cgb_0+r_0,\qquad
\|r_0\|_\infty<\gamma_2-\beta,\qquad
\|cgb_0\|_\infty<\gamma_2.
$$

There is no centered-modulus ambiguity because $2\gamma_2-\beta<q/2$. Thus multiple signatures expose bounded linear observations of $b_0$.

The noise is affected by rejection and by the other transcript variables. It must not be treated as independent Gaussian noise without justification. A useful next experiment would measure the conditional distributions and attempt recovery of $b_0$ in controlled, known-key tests.

Recovering $b_0$ would reveal the full rounded value $b$, which is already public in the stated RR-LWR assumption. It would not automatically recover $s_1$ or supply a forgery. The purpose of this observation is to identify a concrete transcript-analysis problem and avoid silently treating the omitted key part as permanently hidden.

## 9.2 Results that do check out

The following arithmetic is internally consistent with the parameter macros and encodings [E1]:

| Quantity | 128 | 256 | 512 |
| :--- | ---: | ---: | ---: |
| Public-key bytes | 1344 | 2368 | 5184 |
| Secret-key bytes | 2432 | 4608 | 11776 |
| Signature bytes | 2564 | 5449 | 14713 |
| Encoded hint bytes | 100 | 265 | 505 |
| Two-test expected repetitions | 2.129771 | 2.338962 | 3.590045 |
| $B_{\mathrm{EUF}}$ | 393,217 | 1,114,113 | 4,947,969 |
| $B_{\mathrm{SUF}}$ | 524,290 | 1,048,578 | 4,194,306 |

The repetition calculation covers the stated response and low-bit model. It is not a measurement of the complete signer with all rejection tests and correlations.

The key-generation residual bound and the accepted-signature verification identities are consistent with the centered rounding conventions. Exhaustive small-modulus checks in [E2] verify hint recovery, high-bit stability under the stated strict inequalities, and the residual bound for both hint values. The SUF argument's nonzero-extraction step is consistent with canonical encodings and uniqueness of the hint when the high-bit moduli are 64, 32, and 8.

The two NTT primes have product

$$
1,152,837,945,367,908,353.
$$

Against the supplied worst-case CRT reconstruction bounds, the corresponding headroom factors are approximately 255.98, 32.00, and 2.46 [E1]. This verifies the integer reconstruction range used in that calculation. It is not a proof that every implementation intermediate avoids overflow.

These positive checks matter: the unsupported security claims should not be conflated with a demonstrated failure of the basic signing identity or an incorrect byte count.

# 10. Specification, implementation, and estimate consistency

## 10.1 A reproducible disagreement in the challenge map

Algorithm 2 on p. 22 requests $\lceil\tau/8\rceil$ bytes for the sign stream: 2, 5, and 11 bytes. All nine implementation trees request 11 bytes. The requested output length is part of the hashed domain encoding. Consequently, requesting 11 bytes and then taking a prefix changes the hash input; it is not equivalent to requesting the shorter output.

The source check [E7] covers the three levels in each of the reference, optimized, and additional families. The C regression [E8] executes the submitted wrappers in all nine combinations with an all-zero public challenge seed. The SM3 results, identical in the reference and optimized families, are:

| Profile | Specified bytes | Implementation bytes | Differing used sign bits |
| :--- | ---: | ---: | ---: |
| 128 | 2 | 11 | 5 |
| 256 | 5 | 11 | 18 |
| 512 | 11 | 11 | 0 |

At level 128 the specification-length stream is hexadecimal *3b80*, while the corresponding prefix of the implementation stream is *9bc5*. At level 256 the two values are *120021c7c5* and *82543e7c36*. The index stream is unchanged, so these sign differences alter the expanded challenge itself.

The additional SHAKE family exhibits the same disagreement: *6da1* versus *3930* at level 128, and *40f92b5756* versus *3598e19826* at level 256. There are respectively 6 and 18 differing used sign bits. At level 512, the specified and implemented lengths coincide in all families.

This disagreement does not establish lower entropy for either map. It establishes that the PDF and implementations define different schemes at two levels. Agreement among implementations or known-answer tests sharing the same map would not resolve that discrepancy.

## 10.2 Other normative ambiguities and interface issues

Several smaller differences should be resolved in a normative revision:

- *UseHint* treats a zero low part differently: the PDF's branch for $r_0\leq0$ decrements, while the code increments when $r_0=0$. Honest nonzero hints avoid this boundary under the signing bounds. An arbitrary candidate signature can contain such a hint, so the verification language still needs one definition.
- The document defines a generic *Pack* operation for keys and signatures. It should explicitly require $H_{ch}$ to receive $\operatorname{Pack}(w_1,\log_2(q/m))$, or state another exact encoding. The coefficient widths are 6, 5, and 3 bits. The current hash notation leaves this connection to be inferred.
- The deterministic signing option needs a matching algorithm and security statement, as discussed in Section 7.6.
- Challenge-refill limits need one definition. Both the specification and wrapper encode the index-stream counter in 32 bits, but the code aborts after counter 255, having exhausted 256 buffers; Algorithm 2 gives no such cap. Counter exhaustion or wraparound in sampling and signing needs specified behavior and a quantified failure probability.
- The current domain header identifies the level and rank. It does not bind every parameter. This separates the submitted profiles, but future parameter changes under the same identifiers would require explicit version separation.

These items call for executable specification tests, including adversarial encodings and boundary inputs, as well as honest-signature test vectors.

## 10.3 Randomness and side-channel claims

The supplied SM3 random-generation wrapper uses global generator selection and error-return interfaces. Some callers do not propagate failure to the signing or key-generation API. A production interface must make initialization, entropy acquisition, generator selection, and error handling explicit.

A 55-byte seed length is not evidence of 440-bit or 512-bit security. NIST SP 800-90A's 440-bit seed length for SHA-256 Hash_DRBG is an internal-state parameter; the standard separately specifies security strength and approved hash instantiations [SP90A]. Substituting SM3 and reusing the seed length does not inherit an SP 800-90A validation claim. This is an integration and assurance issue; no additional mathematical forgery is inferred solely from the seed length.

A power-of-two modulus can simplify arithmetic and permit constant-time implementations. It does not establish resistance to timing, cache, power, electromagnetic, or fault attacks. Such claims need implementation-specific evidence, particularly for secret expansion, rejection loops, arithmetic, and error paths.

## 10.4 Estimator output is not a security lower bound

Appendix A uses *lattice-estimator*, including a pinned source revision [LE]. That revision's SIS implementation prices lattice-reduction strategies; it does not test the modulo-4 construction in Section 6. A large returned exponent is therefore compatible with an easy instance through another algorithm.

The different numbers labeled Core-SVP, arithmetic operations, and refined attack costs need not be numerically equal. A Core-SVP exponent based on a block size omits algorithm-specific preprocessing and other overhead. Such differences should be explained using the exact attack variant, cost model, success probability, and operation convention, rather than treated automatically as contradictions or combined selectively.

The supplied cost-fitting range ends at block size 1024, while reported 512-level choices reach roughly 2181–2788. This is extrapolation. The submission should publish the fitting data, residuals, extrapolation rule, uncertainty, estimator revision, full inputs, and unedited outputs. No fit can repair the use of an inapplicable problem model.

## 10.5 Parameter and presentation corrections

The following points also affect reproducibility or interpretation:

- Increasing $d$ changes the public-key compression error and the stated EUF bound. For example, changing the 128-level value from 11 to 12 changes $B_{\mathrm{EUF}}$ from 393,217 to 524,289. A claim that this change has no security effect is too broad. Increasing $\omega$ similarly enlarges the accepted hint set; its effect needs analysis.
- *Power2Round* directly compresses the public key. Any signature-size benefit is indirect and must be explained through the chosen parameters.
- The appendix's generic signature-size expression using a fixed 64-byte challenge and omitting hints is not valid for all three profiles. The actual encoded sizes in Section 9.2 are consistent with the tables and code.
- An expected number of *additional* 64-word refill blocks must exclude the initial block and account for the discrete threshold. Under the stated sampling approximation the expectations are near 0, 0, and 1, rather than simply the expected word count divided by 64.
- Table 7 gives 204,968 signing cycles for Octarine-128 and 203,781 for its ML-DSA comparison, contrary to a blanket signing-speed advantage. The difference is about 0.58%; differing compiler flags further limit the comparison. Performance claims need comparable builds, platform details, and dispersion across runs.

# 11. Disposition and requirements for a revision

The submitted document should not be used to endorse the advertised security levels. The 512-bit classical claim must be withdrawn for both supplied hash families. The SM3 256-level implementation also has a direct generic signature-transfer bound around $2^{128}$.

| Family and profile | Principal established obstruction |
| :--- | :--- |
| SM3, 128 | Challenge-search bound of $2^{65.79}$ quantum queries; unresolved proof and conformance issues |
| SM3, 256 | Message-collision signature transfer near $2^{128}$ classical work |
| SM3, 512 | Same collision bound; 344-bit equivalent-key descriptor; easy relaxed SIS instances |
| SHAKE, 128 | Same challenge-search query bound and unresolved proof/conformance issues |
| SHAKE, 256 | No below-target classical forgery established here; proof and model obligations remain |
| SHAKE, 512 | Message-collision strength capped at 256 bits; easy relaxed SIS instances |

The quantum-query entry for level 128 must retain the gate-cost qualification in Section 4.2. A profile without a below-target attack in this document is not thereby validated.

A technically reviewable revision should satisfy the following requirements:

1. **Define the claim and the primitives.** State classical and quantum resource models, allowable query counts, target advantages, and per-role hash requirements. Specify each XOF and generator completely.
2. **Analyze the actual forgery relations.** Preserve the separate response and residual bounds, challenge support, target dependence, and oracle consistency. Include powers-of-two methods, modular projections, and structured kernels alongside lattice reduction.
3. **Complete the proof instantiation.** Give an executable simulator, acceptance bounds, commitment entropy, seeded-oracle programming, bad-key terms, and the applicable LWR reduction or an explicitly stated independent decisional assumption. Separate randomized ROM, deterministic, and QROM claims.
4. **Reconcile specification and code.** Provide one challenge map, one rounding and hint convention, exact encodings, versioned domains, failure semantics, and conformance tests.
5. **Re-estimate and reproduce.** Publish parameter derivations, complete estimator inputs and outputs, benchmark settings, and test artifacts. Reassess rejection rates and signature sizes after changes.
6. **Invite analysis of the revised construction.** Priority questions are constrained powers-of-two attacks near the response thresholds, multitranscript information about $b_0$, componentwise attacks at $k=5$, and the real distribution of accepted commitments.

Further research on a corrected SHAKE-based construction at lower claimed levels may be reasonable. It should proceed as an unvalidated candidate with revised claims and a frozen specification. The available evidence does not justify deployment or a claim that the current submission has survived cryptanalysis at its advertised levels.

# 12. Reproducibility and evidence

## 12.1 Evidence inventory

Paths below are relative to the distribution root. They identify programs, source code, and data; none is a prerequisite for following the mathematical constructions in Sections 3–8.

**[E1] Parameter arithmetic.** [*verify_parameters.py*](code/verify_parameters.py) recomputes challenge entropies, byte counts, stated bounds, rejection approximations, and CRT ranges using Python's standard library. Its [recorded output](evidence/verify_parameters.json) is included.

**[E2] Algebra and rounding checks.** [*verify_algebra.py*](code/verify_algebra.py) checks the discriminant formula on small degrees, the relevant full-degree local index calculations, Fermat-factor arithmetic, parity identities, and exhaustive small-modulus hint properties. It does not independently prove the primality of the largest published Fermat factor. See [output](evidence/verify_algebra.json).

**[E3] Collision-propagation model.** [*verify_kdf_collision.py*](code/verify_kdf_collision.py) gives a toy state-collision experiment with a 12-bit state. Its reduced state size is intentional; it is not a collision in full SM3. See [output](evidence/verify_kdf_collision.txt).

**[E4] SM3 continuation.** [*verify_sm3_mechanism.c*](code/verify_sm3_mechanism.c) checks continuation against the supplied SM3 code. Any forced internal-state equality is a mechanism test, not a found collision. Results are in [*original_code.json*](evidence/original_code.json).

**[E5] Relaxed SIS witness.** [*composite_sis.py*](code/composite_sis.py), [run data](evidence/composite_sis_5120.json), and the [saved witness](data/sis_witness_5120.npz) implement and record the full-dimension construction. The witness contains the two matrices modulo 4 and the nonzero vector; higher matrix bits are unnecessary for verification. A [publication replay](evidence/composite_sis_replay.json) reproduced the matrices, vector, and full-modulus lift digest exactly, excluding timings from the comparison.

**[E6] Modular structure.** [*ring_structure.py*](code/ring_structure.py) and [its data](evidence/ring_structure.json) verify the modular factorization, units, annihilators, Hensel factorization, and one projection diagnostic.

**[E7] Source consistency.** [*verify_additional_findings.py*](code/verify_additional_findings.py) checks threshold arithmetic and odd-weight challenge candidates. With a separately obtained submission, its source checker also checks challenge-stream lengths across nine source trees. [*verify_original_code.py*](code/verify_original_code.py) invokes that checker and records its results with the C experiments.

**[E8] Executed sign-stream discrepancy.** [*verify_challenge_stream.c*](code/verify_challenge_stream.c) and [output](evidence/original_code.json) give the all-zero-seed examples in Section 10.1 for all nine implementation/profile combinations.

**[E9] Artifact identities.** [*submission-sha256.json*](data/submission-sha256.json) identifies 397 original files: the specification and the implementation source/build inputs. These third-party inputs are not bundled. [*SHA256SUMS*](SHA256SUMS) fingerprints the publication package itself. [*PROVENANCE.md*](PROVENANCE.md) gives acquisition links and the complete estimator revision.

**[E10] Certificate and supplementary checks.** [*verify_publication_supplement.py*](code/verify_publication_supplement.py) and [output](evidence/verify_publication_supplement.json) verify the saved SIS witness directly, check the $(n,k)=(2,17)$ index counterexample, and numerically test the embedding formula on small instances. Witness verification proves the relation for every full-modulus lift of the saved modulo-4 matrices.

**[E11] Equivalent-secret descriptor.** [*verify_secret_descriptor.c*](code/verify_secret_descriptor.c) and [output](evidence/original_code.json) check the 141-byte encoding, the common two-block prefix, and exact reconstruction of every $s_1$ expansion byte using a 344-bit descriptor in all six SM3 combinations. The seed is a deterministic test value; no unknown secret is recovered.

**[E12] Separate SIS verifier and small demonstration.** [*verify_sis_witness.py*](code/verify_sis_witness.py) checks every row, the norm, nonzero status, and response-bound failure of the saved certificate using NumPy without Sage. [*sis_mod4_demo.py*](code/sis_mod4_demo.py) implements the two binary solves at small dimensions using only standard Python. Both include a changed-vector rejection check. Their [certificate output](evidence/verify_sis_witness.json) and [small-example output](evidence/sis_mod4_demo.json) are included.

## 12.2 Running the checks

From the distribution root, verify package integrity and run the standard-library checks:

~~~sh
python3 verify_package.py
python3 run.py
~~~

The full mathematical replay additionally requires Sage and NumPy. It verifies the saved certificate, regenerates the full 5120-dimensional witness, and compares all mathematical data with the saved records:

~~~sh
python3 run.py --full --sage sage
~~~

Where the Sage launcher is unavailable, use *--sage-python /path/to/sage-env/bin/python* in place of *--sage sage*. Fresh results go to *verification-output/* by default; *--output-dir* selects another directory. Recorded publication evidence is preserved. Wall-clock timings are recorded separately from the comparisons.

To execute [E4], [E7], [E8], and [E11] against the original C implementation, obtain the submission separately and point to its root:

~~~sh
python3 run.py --submission-root /path/to/Octarine
~~~

This verifies all 397 original-file hashes before compilation. It compiles the small research drivers with GCC and runs the nine challenge-stream, six descriptor, and one SM3-continuation configurations. It does not run the submission's build scripts or bundled executables. The source checks can be combined with the full replay:

~~~sh
python3 run.py --full --sage sage \
  --submission-root /path/to/Octarine
~~~

The [reproduction summary](evidence/summary.json) records a successful run of all these checks. Full environment details, individual commands, and coverage limits are in [*REPRODUCING.md*](REPRODUCING.md). The separate certificate verifier needs only Python and NumPy:

~~~sh
python3 code/verify_sis_witness.py
~~~

The artifact checks demonstrate the stated algebra, arithmetic, source behavior, and saved witness. They do not constitute a full implementation audit, a full-parameter SM3 collision, recovery of an unknown signing key, a practical Octarine forgery, or a QROM security proof.

## 12.3 AI-use disclosure

DeepSeek V4 Pro 0831 and Meta Muse Spark 1.3 were used in preparing the analysis. OpenAI Codex was used for additional technical analysis, cross-checking of claims, development and execution of reproducibility code, and preparation of this package. The computational evidence is available for inspection and replay. Mounir IDRASSI is responsible for the report and its conclusions. See [*AI_DISCLOSURE.md*](AI_DISCLOSURE.md).

# References {.unnumbered}

**[S]** ARCANE team. *ARCANE-Octarine: Algorithm Specifications and Supporting Documentation*. Submission snapshot, 53 PDF pages. [Pinned public copy](https://github.com/ngcc-dev/ngcc-harness/blob/31de7d4d57aca530a65c2c9de6ddaeb25c66548d/sign-16/sign-16-spec.pdf). SHA-256 is given in Section 1.1.

**[F202]** National Institute of Standards and Technology. *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*. FIPS PUB 202, August 2015, Appendix A, Table 4. [Official publication](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf).

**[G96]** Lov K. Grover. *A Fast Quantum Mechanical Algorithm for Database Search*. Proceedings of STOC 1996, pp. 212–219. [Author preprint](https://arxiv.org/abs/quant-ph/9605043).

**[BHT98]** Gilles Brassard, Peter Høyer, and Alain Tapp. *Quantum Algorithm for the Collision Problem*. LATIN 1998, LNCS 1380, pp. 163–169; preprint 1997. [Author preprint](https://arxiv.org/abs/quant-ph/9705002).

**[BGM16]** Andrej Bogdanov, Siyao Guo, Daniel Masny, Silas Richelson, and Alon Rosen. *On the Hardness of Learning with Rounding over Small Modulus*. TCC 2016-A, LNCS 9562, pp. 209–224. [Author-hosted paper](https://people.csail.mit.edu/sirichel/lwr.pdf), [publisher record](https://doi.org/10.1007/978-3-662-49096-9_9).

**[BRVW26]** Joppe W. Bos, Joost Renes, Frederik Vercauteren, and Peng Wang. *Structured Module Lattice-based Cryptography: Fine-Grained Parameter Selection without Compromising Performance*. IACR Cryptology ePrint Archive, Report 2026/098. [Paper record](https://eprint.iacr.org/2026/098).

**[B99]** Richard P. Brent. *Factorization of the Tenth Fermat Number*. Mathematics of Computation 68 (1999), pp. 429–451. [Author's publication page](https://maths-people.anu.edu.au/~brent/pub/pub161.html).

**[LE]** Martin R. Albrecht et al. *lattice-estimator*. Source snapshot identified in the submission by revision *be81b18*, resolved to *be81b183195fb0d62fd882c65620237c6218b981*. [SIS implementation at that revision](https://github.com/malb/lattice-estimator/blob/be81b183195fb0d62fd882c65620237c6218b981/estimator/sis_lattice.py).

**[SP90A]** Elaine Barker and John Kelsey. *Recommendation for Random Number Generation Using Deterministic Random Bit Generators*. NIST SP 800-90A Revision 1, June 2015. [Official publication](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-90ar1.pdf).

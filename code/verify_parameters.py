#!/usr/bin/env python3
"""Parameter and attack-accounting verification for the ARCANE-Octarine review.

Python 3.10+, stdlib only. Run: python3 verify_parameters.py

  P1. Encoded sizes (pk/sk/signature) from the spec's formulas.
  P2. Challenge entropy log2 C(n,tau) + tau; minimality of tau per level;
      minimal tau for a 160-bit entropy (80-bit quantum-search objective).
  P3. Rejection probabilities (two-test model) and expected rounds;
      the tau = 21 candidate change and its side effects.
  P4. B_EUF / B_SUF; sensitivity of B_EUF to the compression parameter d.
  P5. Challenge-search margins in exponent bits and work factors.
  P6. CRT two-prime certificate: primality, NTT congruence, product, and the
      worst-case signed-lift requirement 2(3k-2) n (q/2) gamma1 with margins.
  P7. Transcript-identity unambiguous-lift check:
      |a*c*b0 + r0| <= a*tau*2^{d-1} + (gamma2-beta) < q/2.
  P8. Toy challenge-search forgery (tiny challenge space, toy hash mapping):
      a (z=0, h=0) forgery that verifies without the secret key, demonstrating
      the generic construction only (not an attack on any submitted profile).
"""
import require_checks
from math import comb, log2, sqrt

def isprime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True

PARAMS = [  # level, k, eta, log2 p, d, tau, log2 gamma1, log2 gamma2, omega
    (128, 1, 4, 21, 11, 16, 18, 17, 79),
    (256, 2, 2, 22, 13, 36, 19, 18, 210),
    (512, 5, 2, 22, 14, 87, 21, 20, 399),
]
Q, N = 2 ** 24, 1024

def p1_sizes():
    out = []
    for lvl, k, eta, ep, d, tau, g1, g2, om in PARAMS:
        nkc = k * N
        sk = 64 + 64 + 128 + (2 * int(log2(2 * eta)) + d) * nkc // 8
        pk = 64 + (ep - d) * nkc // 8
        sig = lvl // 4 + int(log2(2 ** (g1 + 1))) * nkc // 8 + 10 * (om + k) // 8
        out.append({"level": lvl, "sk": sk, "pk": pk, "sig": sig})
    assert [(r["sk"], r["pk"], r["sig"]) for r in out] == [
        (2432, 1344, 2564), (4608, 2368, 5449), (11776, 5184, 14713)]
    return out

def p2_entropy():
    out = []
    for lvl, k, eta, ep, d, tau, g1, g2, om in PARAMS:
        ent = log2(comb(N, tau)) + tau
        ent_prev = log2(comb(N, tau - 1)) + tau - 1
        out.append({"level": lvl, "tau": tau, "entropy": ent,
                    "quantum_search_exponent": ent / 2,
                    "tau_minimal": ent_prev < lvl <= ent})
    out.append({"min_tau_for_160_bits": next(
        t for t in range(1, 513) if log2(comb(N, t)) + t >= 160)})
    return out

def p3_rejections():
    out = []
    for lvl, k, eta, ep, d, tau, g1, g2, om in PARAMS:
        beta = tau * eta
        pz = ((2 * (2 ** g1 - beta) - 1) / (2 * 2 ** g1)) ** (k * N)
        pr = ((2 * (2 ** g2 - beta) - 1) / (2 * 2 ** g2)) ** (k * N)
        out.append({"level": lvl, "P_z": pz, "P_r0": pr,
                    "expected_rounds": 1 / (pz * pr)})
    beta = 21 * 4
    pz = ((2 * (2 ** 18 - beta) - 1) / (2 * 2 ** 18)) ** N
    pr = ((2 * (2 ** 17 - beta) - 1) / (2 * 2 ** 17)) ** N
    rounds_new = 1 / (pz * pr)
    out.append({"tau_21_candidate": {
        "expected_rounds": rounds_new,
        "rounds_increase_percent": (rounds_new / out[0]["expected_rounds"] - 1) * 100}})
    return out

def p4_bounds():
    out = []
    for lvl, k, eta, ep, d, tau, g1, g2, om in PARAMS:
        beta = tau * eta
        a = Q // (2 ** ep)
        comp = a * tau * 2 ** (d - 1)
        out.append({"level": lvl,
                    "B_EUF": max(2 ** g1 - beta, 2 * 2 ** g2 + 1 + comp),
                    "B_SUF": max(2 * (2 ** g1 - beta), 4 * 2 ** g2 + 2),
                    "compression_term": comp, "gamma2": 2 ** g2,
                    "compression_term_gt_gamma2": comp > 2 ** g2})
    b11 = max(2 ** 18 - 64, 2 * 2 ** 17 + 1 + 8 * 16 * 2 ** 10)
    b12 = max(2 ** 18 - 64, 2 * 2 ** 17 + 1 + 8 * 16 * 2 ** 11)
    b21 = max(2 ** 18 - 84, 2 * 2 ** 17 + 1 + 8 * 21 * 2 ** 10)
    out.append({"B_EUF_d11": b11, "B_EUF_d12": b12, "B_EUF_tau21": b21})
    return out

def p5_margins():
    out = []
    for lvl, k, eta, ep, d, tau, g1, g2, om in PARAMS[1:]:
        ent = log2(comb(N, tau)) + tau
        dc, dq = ent - lvl, ent / 2 - lvl / 2
        out.append({"level": lvl, "extra_classical_bits": dc,
                    "classical_work_factor": 2 ** dc,
                    "extra_quantum_bits": dq, "quantum_work_factor": 2 ** dq})
    return out

def p6_crt():
    p1, p2 = 0x3fff7801, 0x3fff5801
    M = p1 * p2
    assert isprime(p1) and isprime(p2)
    assert p1 % 2048 == 1 and p2 % 2048 == 1
    rows = []
    for lvl, k, eta, ep, d, tau, g1, g2, om in PARAMS:
        need = 2 * (3 * k - 2) * N * (Q // 2) * 2 ** g1
        rows.append({"level": lvl, "log2_requirement": log2(need),
                     "margin": M / need})
    return {"p1": p1, "p2": p2, "M": M, "log2_M": log2(M), "rows": rows}

def p7_lift():
    rows = []
    for lvl, k, eta, ep, d, tau, g1, g2, om in PARAMS:
        beta = tau * eta
        a = Q // (2 ** ep)
        bound = a * tau * 2 ** (d - 1) + (2 ** g2 - beta)
        rows.append({"level": lvl, "lift_bound": bound,
                     "unambiguous": bound < Q // 2})
    return rows

def p8_toy_forgery():
    import hashlib
    n, q, p, d, g1, g2, beta = 8, 256, 128, 1, 16, 8, 1
    b1 = [-11, 9, 12, -17, 1, 24, -30, 8]
    def ctr_l(a, m):
        return (a + m // 2) % m - m // 2
    def high_l(a, m):
        return ctr_l((a - ctr_l(a, m)) // m, q // m)
    def nega(a, b):
        c = [0] * n
        for i, ai in enumerate(a):
            for j, bj in enumerate(b):
                c[(i + j) % n] += (1 if i + j < n else -1) * ai * bj
        return c
    def toy_challenge(seed):
        v = seed[0] % (2 * n)
        c = [0] * n
        c[v % n] = 1 if v < n else -1
        return c
    T = [ctr_l((q // p) * 2 ** d * v, q) for v in b1]
    tr = hashlib.sha256(b"toy-tr" + bytes(v % 256 for v in b1)).digest()
    c0 = [1] + [0] * (n - 1)
    w1 = [high_l(-v, 2 * g2) for v in nega(c0, T)]
    enc = lambda a: bytes(v % 256 for v in a)
    for trial in range(1, 10001):
        mu = hashlib.sha256(b"toy-mu" + tr + f"toy message {trial}".encode()).digest()
        seed = hashlib.sha256(b"toy-ch" + mu + enc(w1)).digest()
        if toy_challenge(seed) == c0:
            z, hs = [0] * n, [0] * n
            v = [ctr_l(-u, q) for u in nega(c0, T)]
            rec = [high_l(u, 2 * g2) for u in v]  # h = 0
            check = hashlib.sha256(b"toy-ch" + mu + enc(rec)).digest()
            ok = max(map(abs, z)) < g1 - beta and seed == check and sum(hs) == 0
            return {"challenge_space": 2 * n, "trials": trial,
                    "forgery_verifies": ok, "secret_key_used": False,
                    "warning": "toy parameters and toy hash only"}
    raise AssertionError("toy search failed unexpectedly")

def main():
    import json
    print(json.dumps({
        "P1_sizes": p1_sizes(),
        "P2_challenge_entropy": p2_entropy(),
        "P3_rejection_model": p3_rejections(),
        "P4_extraction_bounds": p4_bounds(),
        "P5_challenge_search_margins": p5_margins(),
        "P6_crt_certificate": p6_crt(),
        "P7_transcript_lift": p7_lift(),
        "P8_toy_forgery": p8_toy_forgery(),
    }, indent=2))

if __name__ == "__main__":
    main()

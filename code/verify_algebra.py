#!/usr/bin/env python3
"""Algebraic verification for the ARCANE-Octarine review (Python 3.10+, stdlib only).

Covers, for f(x) = (x^k - 2)^n + 1 with n = 1024, k in {1, 2, 5}:
  A1. |disc(f)| = (nk)^{nk} (2^n + 1)^{k-1}, checked against direct Sylvester/
      Bareiss discriminant computations on small degrees.
  A2. Dedekind index criterion at p = 2 (all submitted k): T = (f - g^e)/2 mod 2
      has the single monomial X^{nk/2}, coprime to the squarefree kernel g.
  A3. Dedekind index criterion at p = 5 (k = 5): direct computation on the
      degree-5120 polynomial, plus the closed-form cross-check with
      w = 2u^4+3u^3+u^2+u+1, u = x-2: gcd(w, u^1024+1) = 1 over F_5.
  A4. F_10 = 2^1024+1 cofactor arithmetic: the three small published prime
      factors divide F_10 exactly once; the remaining cofactor has 835 bits
      (252 decimal digits). Primality of the 252-digit cofactor is the
      published result of Brent (Math. Comp. 68 (1999), 429-451); this script
      verifies only the divisibility arithmetic, not primality.
  A5. Parity homomorphism: eps : S_{q,n,k} -> F_2, g -> g(1,1) mod 2, satisfies
      eps(a*s) = eps(a) eps(s) on random toy radical-ring products.
  A6. Exhaustive small-modulus checks: hint correctness, high-bit stability,
      and the |v - m*UseHint(h,v)| <= m residual bound for arbitrary h in {0,1}.

Run: python3 verify_algebra.py
"""
import require_checks
from math import comb, gcd as igcd

# ---------- generic polynomial helpers (ascending coefficient order) ----------

def trim(a):
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a

def pmul_mod(a, b, m):
    c = [0] * (len(a) + len(b) - 1)
    for i, u in enumerate(a):
        if u:
            for j, v in enumerate(b):
                if v:
                    c[i + j] = (c[i + j] + u * v) % m
    return c

def ppow_mod(a, e, m):
    r = [1]
    while e:
        if e & 1:
            r = pmul_mod(r, a, m)
        a = pmul_mod(a, a, m)
        e >>= 1
    return r

def pdiv_mod(a, b, m):
    a = trim(a[:])
    inv = pow(b[-1], -1, m)
    q = [0] * max(1, len(a) - len(b) + 1)
    while len(a) >= len(b) and a != [0]:
        s, t = len(a) - len(b), a[-1] * inv % m
        q[s] = t
        for i, v in enumerate(b):
            a[s + i] = (a[s + i] - t * v) % m
        trim(a)
    return trim(q), a

def pmod(a, b, m):
    return pdiv_mod(a, b, m)[1]

def pgcd(a, b, m):
    a = trim([x % m for x in a])
    b = trim([x % m for x in b])
    while b != [0]:
        a, b = b, pmod(a, b, m)
    inv = pow(a[-1], -1, m)
    return [x * inv % m for x in a]

def ppowmod_poly(a, e, b, m):
    r = [1]
    while e:
        if e & 1:
            r = pmod(pmul_mod(r, a, m), b, m)
        a = pmod(pmul_mod(a, a, m), b, m)
        e >>= 1
    return r

# ---------- A1: discriminant closed form on small degrees ----------

def sylvester_det_bareiss(f, g):
    """|Res(f,g)| via Sylvester matrix + Bareiss fraction-free elimination."""
    n, m = len(f) - 1, len(g) - 1
    N = n + m
    M = [[0] * N for _ in range(N)]
    fr = f[::-1]
    gr = g[::-1]
    for i in range(m):
        for j in range(n + 1):
            M[i][i + j] = fr[j]
    for i in range(n):
        for j in range(m + 1):
            M[m + i][i + j] = gr[j]
    det, sign, prev = 1, 1, 1
    for k in range(N - 1):
        if M[k][k] == 0:
            for r in range(k + 1, N):
                if M[r][k]:
                    M[k], M[r] = M[r], M[k]
                    sign = -sign
                    break
            else:
                return 0
        for i in range(k + 1, N):
            for j in range(k + 1, N):
                M[i][j] = (M[i][j] * M[k][k] - M[i][k] * M[k][j]) // prev
        prev = M[k][k]
    return abs(sign * M[N - 1][N - 1])

def make_f(n, k):
    # f = (x^k - 2)^n + 1 over Z (ascending order)
    base = [0] * (k + 1)
    base[0], base[k] = -2, 1
    f = [1]
    for _ in range(n):
        c = [0] * (len(f) + len(base) - 1)
        for i, u in enumerate(f):
            for j, v in enumerate(base):
                c[i + j] += u * v
        f = c
    f[0] += 1
    return trim(f)

def a1():
    cases = [(2, 1), (2, 2), (2, 3), (2, 5), (4, 2), (4, 3)]
    out = []
    for n, k in cases:
        f = make_f(n, k)
        d = len(f) - 1
        fp = trim([(i) * f[i] for i in range(1, len(f))])  # f'
        res = sylvester_det_bareiss(f, fp)
        disc = res  # monic f: |disc| = |Res(f,f')|
        expect = (n * k) ** (n * k) * (2 ** n + 1) ** (k - 1)
        assert disc == expect, (n, k, disc, expect)
        out.append((n, k, disc))
    return out

# ---------- A2: p = 2 Dedekind, closed form T == X^{nk/2} mod 2 ----------

def a2():
    n = 1024
    out = []
    for k, g, e in [(1, [1, 1], 1024), (2, [1, 1], 2048), (5, [1, 0, 0, 0, 0, 1], 1024)]:
        deg = k * n
        f = [0] * (deg + 1)
        for j in range(n + 1):
            f[k * j] = (f[k * j] + comb(n, j) * pow(-2, n - j, 4)) % 4
        f[0] = (f[0] + 1) % 4
        ge = ppow_mod(g, e, 4)
        assert len(ge) == deg + 1
        diff = [(f[i] - ge[i]) % 4 for i in range(deg + 1)]
        assert all(x % 2 == 0 for x in diff)
        T = [(x // 2) % 2 for x in diff]
        nz = [i for i, x in enumerate(T) if x]
        assert nz == [k * n // 2], (k, nz)
        out.append((k, g, e, nz[0]))
    return out

# ---------- A3: p = 5 Dedekind for k = 5 ----------

def a3():
    n, p = 1024, 5
    m2 = p * p
    deg = 5 * n
    f = [0] * (deg + 1)
    for j in range(n + 1):
        f[5 * j] = (f[5 * j] + comb(n, j) * pow(-2, n - j, m2)) % m2
    f[0] = (f[0] + 1) % m2
    g = [0] * (n + 1)
    for j in range(n + 1):
        g[j] = (g[j] + comb(n, j) * pow(-2, n - j, m2)) % m2
    g[0] = (g[0] + 1) % m2
    g5 = ppow_mod(g, 5, m2)
    diff = [(f[i] - g5[i]) % m2 for i in range(deg + 1)]
    assert all(x % p == 0 for x in diff)
    T = [(x // p) % p for x in diff]
    gbar = [x % p for x in g]
    d = pgcd(gbar, T, p)
    assert d == [1], d
    # closed-form cross-check: T == -u^1019 * w mod (5, u^1024+1), w = 2u^4+3u^3+u^2+u+1
    w = [1, 1, 1, 3, 2]
    q1, r1 = pdiv_mod(w, [1, 1], 5)
    q2, r2 = pdiv_mod(q1, [1, 1], 5)
    assert r1 == [0] and r2 == [0] and q2 == [1, 4, 2]  # w = (u+1)^2 (2u^2 - u + 1)
    assert ppowmod_poly([0, 1], 24, q2, 5) == [1]
    assert ppowmod_poly([0, 1], 1024, q2, 5) == [3, 1]  # u^1024 = u^16 = u+3 != -1
    gg = [1] + [0] * 1023 + [1]
    assert pgcd(w, gg, 5) == [1]
    return {"direct_gcd": d, "w_factor": q2, "u^1024_mod_quad": [3, 1]}

# ---------- A4: F_10 arithmetic ----------

def a4():
    F10 = 2 ** 1024 + 1
    small = [45592577, 6487031809, 4659775785220018543264560743076778192897]
    res = {"small_factors_first_power": [], "cofactor_bits": None, "cofactor_digits": None}
    cof = F10
    for p in small:
        assert F10 % p == 0 and F10 % (p * p) != 0
        res["small_factors_first_power"].append(p)
        cof //= p
    res["cofactor_bits"] = cof.bit_length()
    res["cofactor_digits"] = len(str(cof))
    return res

# ---------- A5: parity homomorphism on toy radical rings ----------

def negacyclic(a, b):
    n = len(a)
    c = [0] * n
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            c[(i + j) % n] += (1 if i + j < n else -1) * ai * bj
    return c

def radical_mul(a, b, q):
    k, n = len(a), len(a[0])
    out = [[0] * n for _ in range(k)]
    for i in range(k):
        for j in range(k):
            c = negacyclic(a[i], b[j])
            if i + j >= k:
                yc = [-c[-1]] + c[:-1]
                c = [2 * u + v for u, v in zip(c, yc)]
            row = out[(i + j) % k]
            for t in range(n):
                row[t] += c[t]
    return [[x % q for x in row] for row in out]

def a5():
    import random
    rng = random.Random(20260922)
    eps = lambda a: sum(map(sum, a)) % 2
    tested = 0
    for k in (1, 2, 5):
        for _ in range(100):
            q, n = 256, 8
            a = [[rng.randrange(q) for _ in range(n)] for _ in range(k)]
            s = [[rng.randrange(q) for _ in range(n)] for _ in range(k)]
            t = radical_mul(a, s, q)
            assert eps(t) == eps(a) * eps(s)
            tested += 1
    return {"products_checked": tested}

# ---------- A6: exhaustive hint / stability / residual checks ----------

def ctr(a, q):
    return (a + q // 2) % q - q // 2

def high(a, q, m):
    return ctr((a - ctr(a, m)) // m, q // m)

def hint(e, r, q, m):
    return int(high(r, q, m) != high(r + e, q, m))

def use_hint(h, r, q, m):
    r1, r0 = high(r, q, m), ctr(r, m)
    return ctr(r1 + (1 if r0 > 0 else -1), q // m) if h else r1

def a6():
    q = 64
    hint_cases = stability_cases = residual_cases = 0
    for m in (4, 8, 16, 32):
        for r in range(-q // 2, q // 2):
            for e in range(-m // 2 + 1, m // 2):
                assert use_hint(hint(e, r, q, m), r, q, m) == high(r + e, q, m)
                hint_cases += 1
            for beta in range(1, m // 2):
                for e in range(-beta, beta + 1):
                    if abs(ctr(r + e, m)) < m // 2 - beta:
                        assert high(r + e, q, m) == high(r, q, m)
                        stability_cases += 1
        for v in range(-32, 32):
            for h in (0, 1):
                assert abs(ctr(v - m * use_hint(h, v, 64, m), 64)) <= m
                residual_cases += 1
    return {"hint_cases": hint_cases, "stability_cases": stability_cases,
            "residual_cases": residual_cases}

def main():
    import json
    results = {
        "A1_disc_closed_form_cases": a1(),
        "A2_p2_dedekind_T_monomial": a2(),
        "A3_p5_dedekind": a3(),
        "A4_F10_arithmetic": a4(),
        "A5_parity": a5(),
        "A6_exhaustive": a6(),
        "notes": [
            "A2/A3 prove 2 and 5 do not divide [O_K : Z[alpha]] for the submitted profiles.",
            "A4 verifies divisibility only; primality of the 252-digit cofactor is the",
            "published Brent (1999) result, so F_10 is squarefree and no F_10 prime divides",
            "the index either (for p | F_10 the Dedekind condition reduces to p^2 | F_10).",
        ],
    }
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()

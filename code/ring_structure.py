#!/usr/bin/env python3
"""Exact full-degree checks. Run with the Python interpreter in Sage's environment.

Establish a modular CRT projection, then measure what it does to a coefficient
vector. Exhibiting a factor or a projection alone is NOT a key recovery attack.
"""
import require_checks
import argparse
import json
import time
from pathlib import Path
from sage.all import GF, PolynomialRing, Zmod, ZZ, inverse_mod, set_random_seed


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, help="Optional JSON output; stdout is always emitted.")
args = parser.parse_args()
start = time.monotonic()
n, q = 1024, 2**24
p2 = PolynomialRing(GF(2), "T")
T = p2.gen()
factors = []
for k in (1, 2, 5):
    fac = list(((T**k - 2)**n + 1).factor())
    units = 1
    for f, _ in fac:
        units *= 1 - ZZ(2)**(-f.degree())
    factors.append({"k": k,
        "factors_mod2": [[str(f), int(e)] for f, e in fac],
        "unit_fraction": str(units)})

P = PolynomialRing(Zmod(q), "Y")
Y = P.gen()
R = P.quotient(Y**n + 1, "y")
y = R.gen()
PX = PolynomialRing(R, "X")
X = PX.gen()
S = PX.quotient(X**5 - y - 2, "x")
x = S.gen()
# 5d = 1 (mod 2048), so t**5 = y exactly, including the sign.
d = int(inverse_mod(5, 2*n))
t = y**d
assert t**5 == y
a = x - S(t)
b = sum(x**(4-j)*S(t**j) for j in range(5))
assert a*b == 2
assert a**24 * b**24 == 0

def flat(s):
    out = []
    coeffs = s.list()
    for j in range(5):
        r = coeffs[j] if j < len(coeffs) else R.zero()
        row = r.lift().list()
        out.extend([int(row[i]) if i < len(row) else 0 for i in range(n)])
    return [((v+q//2) % q)-q//2 for v in out]

def norms(s):
    c = flat(s)
    return {"infinity": max(map(abs,c)),
            "squared_l2": sum(v*v for v in c),
            "support": sum(v != 0 for v in c)}

# Hensel/Newton lift the unique fifth root r congruent to t modulo 2.
# r is a unit. Newton doubles 2-adic precision from 1 to >= 24 bits.
r = t
for _ in range(5):
    r -= (r**5 - y - 2) / (5*r**4)
assert r**5 == y+2
# Thus x->r maps the entire degree-5120 ring onto degree 1024 over Z/q.
# The complementary factor is also checked exactly.
factor4 = X**4+r*X**3+r**2*X**2+r**3*X+r**4
assert (X-r)*factor4 == X**5-y-2
assert (5*r**4) * (1/(5*r**4)) == 1

def project(s):
    return sum((s.list()[i] * r**i for i in range(len(s.list()))), R.zero())

set_random_seed(20260922)
small = S([R([ZZ.random_element(-2,2) for _ in range(n)]) for _ in range(5)])
projected = project(small)
proj = [int(v) for v in projected.lift().list()]
proj += [0]*(n-len(proj))
proj = [((v+q//2)%q)-q//2 for v in proj]
assert project(a*b) == project(a)*project(b)
result = {
    "kind": "exact_algebra_and_projection_diagnostic_NOT_an_attack",
    "n": n, "q": q, "factorizations": factors,
    "inverse_of_5_mod_2048": d,
    "small_factor_identity": "(x-t)*(x^4+t*x^3+t^2*x^2+t^3*x+t^4)=2",
    "a_power_24": norms(a**24), "b_power_24": norms(b**24),
    "annihilator_product_zero": True,
    "hensel_factorization_verified": True,
    "lifted_factor_ranks": [1024,4096],
    "projected_small_vector_max_abs": max(map(abs,proj)),
    "projected_small_vector_rms": (sum(v*v for v in proj)/n)**0.5,
    "unprojected_max_abs": 2,
    "root_coefficients_max_abs": max(abs(((int(c)+q//2)%q)-q//2)
                                       for c in r.lift().list()),
    "seconds": time.monotonic()-start,
}
if args.output:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps(result,indent=2))

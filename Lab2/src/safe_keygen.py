"""Safe RSA parameter generation checks for Lab2 P-4."""

from __future__ import annotations

from .math_utils import gcd, generate_prime, integer_nth_root
from .rsa_core import PrivateKey, generate_keypair_from_primes


def generate_safe_rsa_params(bits: int = 1024, e: int = 65537) -> PrivateKey:
    if bits < 64:
        raise ValueError("bits must be at least 64")
    if e < 17:
        raise ValueError("use a larger public exponent for safe parameters")
    half = bits // 2
    while True:
        p = generate_prime(bits - half)
        q = generate_prime(half)
        if p == q:
            continue
        try:
            private, _ = generate_keypair_from_primes(p, q, e)
        except ValueError:
            continue
        analysis = analyze_rsa_params(private)
        if analysis["d_gt_wiener_bound"] and analysis["p_q_ratio_ok"]:
            return private


def analyze_rsa_params(private_key: PrivateKey) -> dict[str, object]:
    p, q = sorted((private_key.p, private_key.q))
    phi = (p - 1) * (q - 1)
    fourth_root, _ = integer_nth_root(private_key.n, 4)
    wiener_bound = fourth_root // 3
    ratio = q / p
    return {
        "modulus_bits": private_key.n.bit_length(),
        "p_bits": private_key.p.bit_length(),
        "q_bits": private_key.q.bit_length(),
        "gcd_e_phi": gcd(private_key.e, phi),
        "d": private_key.d,
        "wiener_bound": wiener_bound,
        "d_gt_wiener_bound": private_key.d > wiener_bound,
        "p_q_ratio_ok": ratio < 2,
        "e_value": private_key.e,
        "cryptool_manual_check": "not_performed",
        "notes": [
            "p and q are distinct probable primes with similar bit length",
            "gcd(e, phi(n)) equals 1",
            "d is above the Wiener vulnerability bound",
            "e defaults to 65537 and is not the small broadcast demo exponent",
        ],
    }

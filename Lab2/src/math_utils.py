"""Number theory helpers for educational RSA attacks."""

from __future__ import annotations

import math
import secrets
from collections.abc import Iterable, Iterator, Sequence

gcd = math.gcd


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return gcd(a, b) and Bezout coefficients x, y."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    if old_r < 0:
        return -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Return a modular inverse of a modulo m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def integer_nth_root(value: int, n: int) -> tuple[int, bool]:
    """Return floor(value ** (1/n)) and whether the root is exact."""
    if value < 0:
        raise ValueError("value must be non-negative")
    if n <= 0:
        raise ValueError("n must be positive")
    if value in (0, 1) or n == 1:
        return value, True

    low, high = 0, 1 << ((value.bit_length() + n - 1) // n)
    while low <= high:
        mid = (low + high) // 2
        power = mid**n
        if power == value:
            return mid, True
        if power < value:
            low = mid + 1
        else:
            high = mid - 1
    return high, False


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    """Return the simple continued fraction of numerator / denominator."""
    if denominator == 0:
        raise ZeroDivisionError("denominator must be non-zero")
    terms: list[int] = []
    while denominator:
        q = numerator // denominator
        terms.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return terms


def convergents(cf: Sequence[int]) -> Iterator[tuple[int, int]]:
    """Yield numerator, denominator convergents for a continued fraction."""
    p_nm2, p_nm1 = 0, 1
    q_nm2, q_nm1 = 1, 0
    for a in cf:
        p = a * p_nm1 + p_nm2
        q = a * q_nm1 + q_nm2
        yield p, q
        p_nm2, p_nm1 = p_nm1, p
        q_nm2, q_nm1 = q_nm1, q


def crt(residues: Sequence[int], moduli: Sequence[int]) -> int:
    """Solve x == residue_i (mod modulus_i) for pairwise coprime moduli."""
    if len(residues) != len(moduli) or not residues:
        raise ValueError("residues and moduli must have equal non-zero length")
    total_modulus = 1
    for modulus in moduli:
        if modulus <= 1:
            raise ValueError("moduli must be greater than one")
        total_modulus *= modulus

    result = 0
    for residue, modulus in zip(residues, moduli):
        partial = total_modulus // modulus
        result += residue * partial * mod_inverse(partial % modulus, modulus)
    return result % total_modulus


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin primality test with deterministic small-prime filtering."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a probable prime with exactly bits bits."""
    if bits < 2:
        raise ValueError("bits must be at least 2")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

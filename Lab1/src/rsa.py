"""Small educational RSA implementation.

The code is intentionally explicit: it is suitable for a lab assignment, but it
does not implement production padding schemes such as OAEP or PSS.
"""

from __future__ import annotations

import json
import math
import secrets
from dataclasses import dataclass
from pathlib import Path


PUBLIC_EXPONENT = 65537


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def _is_probable_prime(n: int, rounds: int = 32) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("prime size is too small")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_keypair(bits: int = 1024) -> tuple[PrivateKey, PublicKey]:
    if bits < 512:
        raise ValueError("RSA modulus must be at least 512 bits for this lab")

    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(PUBLIC_EXPONENT, phi) != 1:
            continue
        n = p * q
        d = mod_inverse(PUBLIC_EXPONENT, phi)
        private = PrivateKey(n=n, e=PUBLIC_EXPONENT, d=d, p=p, q=q)
        public = PublicKey(n=n, e=PUBLIC_EXPONENT)
        return private, public


def encrypt_integer(message: int, public_key: PublicKey) -> int:
    if not 0 <= message < public_key.n:
        raise ValueError("RSA message representative is out of range")
    return pow(message, public_key.e, public_key.n)


def decrypt_integer(ciphertext: int, private_key: PrivateKey) -> int:
    if not 0 <= ciphertext < private_key.n:
        raise ValueError("RSA ciphertext representative is out of range")
    return pow(ciphertext, private_key.d, private_key.n)


def save_private_key(path: Path, key: PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(key.__dict__, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def save_public_key(path: Path, key: PublicKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(key.__dict__, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_private_key(path: Path) -> PrivateKey:
    data = json.loads(path.read_text(encoding="utf-8"))
    return PrivateKey(
        n=int(data["n"]),
        e=int(data["e"]),
        d=int(data["d"]),
        p=int(data["p"]),
        q=int(data["q"]),
    )


def load_public_key(path: Path) -> PublicKey:
    data = json.loads(path.read_text(encoding="utf-8"))
    return PublicKey(n=int(data["n"]), e=int(data["e"]))


def int_to_fixed_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder="big")


def int_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


"""Минимальные RSA-примитивы для учебной лабораторной Lab2."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .math_utils import gcd, generate_prime, mod_inverse


@dataclass(frozen=True)
class PublicKey:
    # Открытый ключ содержит только модуль n и открытый показатель e.
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    # Закрытый ключ дополнительно хранит d и множители p, q. В реальных
    # системах p и q защищают особенно строго; здесь они нужны для проверок.
    n: int
    e: int
    d: int
    p: int
    q: int


def generate_keypair_from_primes(p: int, q: int, e: int) -> tuple[PrivateKey, PublicKey]:
    if p == q:
        raise ValueError("p and q must be different")
    # Для RSA с n = p*q функция Эйлера равна (p-1)*(q-1).
    phi = (p - 1) * (q - 1)
    # Открытый показатель должен быть взаимно прост с phi(n), иначе обратный
    # показатель d не существует.
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi")
    n = p * q
    # Закрытый показатель d определяется сравнением e*d == 1 mod phi(n).
    d = mod_inverse(e, phi)
    private = PrivateKey(n=n, e=e, d=d, p=p, q=q)
    public = PublicKey(n=n, e=e)
    return private, public


def generate_keypair(bits: int = 1024, e: int = 65537) -> tuple[PrivateKey, PublicKey]:
    if bits < 16:
        raise ValueError("bits must be at least 16")
    half = bits // 2
    # Генерация повторяется, пока случайные простые не дадут допустимый e.
    while True:
        p = generate_prime(bits - half)
        q = generate_prime(half)
        if p == q:
            continue
        try:
            return generate_keypair_from_primes(p, q, e)
        except ValueError:
            continue


def encrypt_int(m: int, public_key: PublicKey) -> int:
    # Учебное RSA-шифрование одного целого представителя: c = m^e mod n.
    # Padding здесь не реализован, потому что Lab2 изучает математические атаки.
    if not 0 <= m < public_key.n:
        raise ValueError("message representative out of range")
    return pow(m, public_key.e, public_key.n)


def decrypt_int(c: int, private_key: PrivateKey) -> int:
    # Обратная операция: m = c^d mod n.
    if not 0 <= c < private_key.n:
        raise ValueError("ciphertext representative out of range")
    return pow(c, private_key.d, private_key.n)


def save_public_key(path: str | Path, public_key: PublicKey) -> None:
    # JSON используется только как простой формат обмена для демонстраций.
    Path(path).write_text(json.dumps(asdict(public_key), indent=2), encoding="utf-8")


def save_private_key(path: str | Path, private_key: PrivateKey) -> None:
    # Такие файлы нельзя коммитить как реальные секреты; artifacts игнорируется.
    Path(path).write_text(json.dumps(asdict(private_key), indent=2), encoding="utf-8")


def load_public_key(path: str | Path) -> PublicKey:
    # При чтении JSON явно приводим значения к int, чтобы формат был устойчив
    # к строковым и числовым представлениям больших чисел.
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return PublicKey(n=int(data["n"]), e=int(data["e"]))


def load_private_key(path: str | Path) -> PrivateKey:
    # Загрузка закрытого ключа нужна для CLI-демонстраций и локальных проверок.
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return PrivateKey(
        n=int(data["n"]),
        e=int(data["e"]),
        d=int(data["d"]),
        p=int(data["p"]),
        q=int(data["q"]),
    )

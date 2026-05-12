"""RSA signatures for SHA-256 and CRC32 hashes."""

from __future__ import annotations

import binascii
import hashlib
from pathlib import Path

from src.rsa import PrivateKey, PublicKey


def sha256_hash_int(data: bytes, modulus: int) -> int:
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, byteorder="big") % modulus


def crc32_hash_int(data: bytes, modulus: int) -> int:
    return (binascii.crc32(data) & 0xFFFFFFFF) % modulus


def sign_sha256(data: bytes, private_key: PrivateKey) -> int:
    h = sha256_hash_int(data, private_key.n)
    return pow(h, private_key.d, private_key.n)


def verify_sha256(data: bytes, signature: int, public_key: PublicKey) -> bool:
    h = sha256_hash_int(data, public_key.n)
    return pow(signature, public_key.e, public_key.n) == h


def sign_crc32(data: bytes, private_key: PrivateKey) -> int:
    h = crc32_hash_int(data, private_key.n)
    return pow(h, private_key.d, private_key.n)


def verify_crc32(data: bytes, signature: int, public_key: PublicKey) -> bool:
    h = crc32_hash_int(data, public_key.n)
    return pow(signature, public_key.e, public_key.n) == h


def save_signature(path: Path, signature: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(signature), encoding="utf-8")


def load_signature(path: Path) -> int:
    return int(path.read_text(encoding="utf-8").strip())


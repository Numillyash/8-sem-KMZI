"""Hashing helpers based on gostcrypto (Streebog)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from gostcrypto import gosthash

HashAlg = Literal["streebog256", "streebog512"]


def hash_bytes(data: bytes, hash_alg: HashAlg) -> bytes:
    """Return digest bytes for input data."""
    hasher = gosthash.new(hash_alg)
    hasher.update(bytearray(data))
    return bytes(hasher.digest())


def hash_file(file_path: Path, hash_alg: HashAlg) -> bytes:
    """Read file and hash its contents."""
    data = file_path.read_bytes()
    return hash_bytes(data, hash_alg)


def hash_to_alpha(file_path: Path, hash_alg: HashAlg) -> int:
    """Compute alpha = int(h(M)) for signature steps."""
    digest = hash_file(file_path, hash_alg)
    return int.from_bytes(digest, byteorder="big")

"""RSA signatures for SHA-256 and CRC32 hashes."""

from __future__ import annotations

import binascii
import hashlib
from pathlib import Path

from src.rsa import PrivateKey, PublicKey
from src.sigder import (
    SIGNATURE_VERSION,
    SignatureContainer,
    decode_signature_container,
    encode_signature_container,
)


SHA256_ALGORITHM = "rsa-sha256"
CRC32_ALGORITHM = "rsa-crc32"


def sha256_hash_int(data: bytes, modulus: int) -> int:
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, byteorder="big") % modulus


def crc32_hash_int(data: bytes, modulus: int) -> int:
    return (binascii.crc32(data) & 0xFFFFFFFF) % modulus


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def crc32_digest(data: bytes) -> bytes:
    return (binascii.crc32(data) & 0xFFFFFFFF).to_bytes(4, byteorder="big")


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


def create_sha256_container(data: bytes, private_key: PrivateKey) -> SignatureContainer:
    digest = sha256_digest(data)
    hash_mod_n = int.from_bytes(digest, byteorder="big") % private_key.n
    return SignatureContainer(
        version=SIGNATURE_VERSION,
        algorithm=SHA256_ALGORITHM,
        hash_value=digest,
        hash_mod_n=hash_mod_n,
        signature=pow(hash_mod_n, private_key.d, private_key.n),
    )


def create_crc32_container(data: bytes, private_key: PrivateKey) -> SignatureContainer:
    digest = crc32_digest(data)
    hash_mod_n = int.from_bytes(digest, byteorder="big") % private_key.n
    return SignatureContainer(
        version=SIGNATURE_VERSION,
        algorithm=CRC32_ALGORITHM,
        hash_value=digest,
        hash_mod_n=hash_mod_n,
        signature=pow(hash_mod_n, private_key.d, private_key.n),
    )


def save_signature_container(path: Path, container: SignatureContainer) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode_signature_container(container))


def load_signature_container(path: Path) -> SignatureContainer:
    return decode_signature_container(path.read_bytes())


def verify_sha256_container(data: bytes, container: SignatureContainer, public_key: PublicKey) -> bool:
    digest = sha256_digest(data)
    hash_mod_n = int.from_bytes(digest, byteorder="big") % public_key.n
    return (
        container.version == SIGNATURE_VERSION
        and container.algorithm == SHA256_ALGORITHM
        and container.hash_value == digest
        and container.hash_mod_n == hash_mod_n
        and verify_sha256(data, container.signature, public_key)
    )


def verify_crc32_container(data: bytes, container: SignatureContainer, public_key: PublicKey) -> bool:
    digest = crc32_digest(data)
    hash_mod_n = int.from_bytes(digest, byteorder="big") % public_key.n
    return (
        container.version == SIGNATURE_VERSION
        and container.algorithm == CRC32_ALGORITHM
        and container.hash_value == digest
        and container.hash_mod_n == hash_mod_n
        and verify_crc32(data, container.signature, public_key)
    )


def save_signature(path: Path, container: SignatureContainer) -> None:
    """Backward-compatible name for saving DER signature containers."""
    save_signature_container(path, container)


def load_signature(path: Path) -> SignatureContainer:
    """Backward-compatible name for loading DER signature containers."""
    return load_signature_container(path)

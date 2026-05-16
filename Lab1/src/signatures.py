"""Учебные RSA-подписи для SHA-256 и CRC32."""

from __future__ import annotations

import binascii
import hashlib
from pathlib import Path

from src.rsa import PrivateKey, PublicKey
from src.sigder import (
    RSA_CRC32_ALGORITHM_ID,
    RSA_CRC32_KEY_LABEL,
    RSA_SHA256_ALGORITHM_ID,
    RSA_SHA256_KEY_LABEL,
    SIGNATURE_VERSION,
    SignatureContainer,
    decode_signature_container,
    encode_signature_container,
)


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


def create_sha256_container(data: bytes, private_key: PrivateKey) -> SignatureContainer:
    return SignatureContainer(
        version=SIGNATURE_VERSION,
        algorithm_id=RSA_SHA256_ALGORITHM_ID,
        key_label=RSA_SHA256_KEY_LABEL,
        rsa_n=private_key.n,
        rsa_e=private_key.e,
        signature=sign_sha256(data, private_key),
    )


def create_crc32_container(data: bytes, private_key: PrivateKey) -> SignatureContainer:
    return SignatureContainer(
        version=SIGNATURE_VERSION,
        algorithm_id=RSA_CRC32_ALGORITHM_ID,
        key_label=RSA_CRC32_KEY_LABEL,
        rsa_n=private_key.n,
        rsa_e=private_key.e,
        signature=sign_crc32(data, private_key),
    )


def save_signature_container(path: Path, container: SignatureContainer) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode_signature_container(container))


def load_signature_container(path: Path) -> SignatureContainer:
    return decode_signature_container(path.read_bytes())


def _container_public_key(container: SignatureContainer) -> PublicKey:
    return PublicKey(n=container.rsa_n, e=container.rsa_e)


def verify_sha256_container(data: bytes, container: SignatureContainer, public_key: PublicKey | None = None) -> bool:
    if container.version != SIGNATURE_VERSION:
        return False
    if container.algorithm_id != RSA_SHA256_ALGORITHM_ID:
        return False
    if container.key_label != RSA_SHA256_KEY_LABEL:
        return False

    embedded_public_key = _container_public_key(container)
    if public_key is not None and (public_key.n != embedded_public_key.n or public_key.e != embedded_public_key.e):
        return False

    return verify_sha256(data, container.signature, embedded_public_key)


def verify_crc32_container(data: bytes, container: SignatureContainer, public_key: PublicKey | None = None) -> bool:
    if container.version != SIGNATURE_VERSION:
        return False
    if container.algorithm_id != RSA_CRC32_ALGORITHM_ID:
        return False
    if container.key_label != RSA_CRC32_KEY_LABEL:
        return False

    embedded_public_key = _container_public_key(container)
    if public_key is not None and (public_key.n != embedded_public_key.n or public_key.e != embedded_public_key.e):
        return False

    return verify_crc32(data, container.signature, embedded_public_key)


def save_signature(path: Path, container: SignatureContainer) -> None:
    """Backward-compatible name for saving DER signature containers."""
    save_signature_container(path, container)


def load_signature(path: Path) -> SignatureContainer:
    """Backward-compatible name for loading DER signature containers."""
    return load_signature_container(path)

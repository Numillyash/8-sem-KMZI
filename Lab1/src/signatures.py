"""Учебные RSA-подписи для SHA-256 и CRC32."""

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
    # SHA-256 дает 32-байтный digest, который интерпретируется как большое число.
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, byteorder="big") % modulus


def crc32_hash_int(data: bytes, modulus: int) -> int:
    # CRC32 оставлен только для демонстрации уязвимости из дополнительного задания.
    # Это не криптографический hash.
    return (binascii.crc32(data) & 0xFFFFFFFF) % modulus


def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def crc32_digest(data: bytes) -> bytes:
    return (binascii.crc32(data) & 0xFFFFFFFF).to_bytes(4, byteorder="big")


def sign_sha256(data: bytes, private_key: PrivateKey) -> int:
    # Формула подписи RSA: s = h^d mod n.
    h = sha256_hash_int(data, private_key.n)
    return pow(h, private_key.d, private_key.n)


def verify_sha256(data: bytes, signature: int, public_key: PublicKey) -> bool:
    # Проверка RSA: s^e mod n должно совпасть с h(file) mod n.
    h = sha256_hash_int(data, public_key.n)
    return pow(signature, public_key.e, public_key.n) == h


def sign_crc32(data: bytes, private_key: PrivateKey) -> int:
    # Та же RSA-формула применяется к CRC32-значению для учебной атаки.
    h = crc32_hash_int(data, private_key.n)
    return pow(h, private_key.d, private_key.n)


def verify_crc32(data: bytes, signature: int, public_key: PublicKey) -> bool:
    h = crc32_hash_int(data, public_key.n)
    return pow(signature, public_key.e, public_key.n) == h


def create_sha256_container(data: bytes, private_key: PrivateKey) -> SignatureContainer:
    # В контейнер записываем и исходный digest, и digest после приведения по модулю n.
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
    # hashValue и hashModN из файла подписи не доверяются сами по себе:
    # проверка заново считает digest по данным файла и сравнивает все поля.
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
    # Для CRC32 также заново считаем значение по файлу, иначе контейнер можно было бы
    # подменить согласованными hashValue/hashModN без связи с проверяемыми данными.
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

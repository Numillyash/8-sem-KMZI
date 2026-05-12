"""Hybrid file encryption: AES-256-CBC data encryption and RSA key wrapping."""

from __future__ import annotations

import secrets
from pathlib import Path

from src.aes import BLOCK_SIZE, decrypt_cbc, encrypt_cbc
from src.der import EncryptedFileContainer, decode_container, encode_container
from src.rsa import (
    PrivateKey,
    PublicKey,
    decrypt_integer,
    encrypt_integer,
    int_from_bytes,
    int_to_fixed_bytes,
)


AES_KEY_SIZE = 32
CONTAINER_VERSION = 1


def encrypt_file(input_path: Path, public_key: PublicKey, output_path: Path) -> None:
    plaintext = input_path.read_bytes()
    aes_key = secrets.token_bytes(AES_KEY_SIZE)
    iv = secrets.token_bytes(BLOCK_SIZE)

    encrypted_key_int = encrypt_integer(int_from_bytes(aes_key), public_key)
    rsa_size = (public_key.n.bit_length() + 7) // 8
    container = EncryptedFileContainer(
        version=CONTAINER_VERSION,
        encrypted_key=int_to_fixed_bytes(encrypted_key_int, rsa_size),
        iv=iv,
        ciphertext=encrypt_cbc(plaintext, aes_key, iv),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encode_container(container))


def decrypt_file(input_path: Path, private_key: PrivateKey, output_path: Path) -> None:
    container = decode_container(input_path.read_bytes())
    if container.version != CONTAINER_VERSION:
        raise ValueError(f"unsupported container version: {container.version}")
    if len(container.iv) != BLOCK_SIZE:
        raise ValueError("invalid IV length in container")

    encrypted_key_int = int_from_bytes(container.encrypted_key)
    aes_key_int = decrypt_integer(encrypted_key_int, private_key)
    aes_key = int_to_fixed_bytes(aes_key_int, AES_KEY_SIZE)
    plaintext = decrypt_cbc(container.ciphertext, aes_key, container.iv)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)


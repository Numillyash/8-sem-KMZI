"""Hybrid file encryption: AES-256-CBC data encryption and RSA key wrapping."""

from __future__ import annotations

import json
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


def encrypt_file(
    input_path: Path,
    public_key: PublicKey,
    output_path: Path,
    debug_json_path: Path | None = None,
) -> None:
    plaintext = input_path.read_bytes()
    aes_key = secrets.token_bytes(AES_KEY_SIZE)
    iv = secrets.token_bytes(BLOCK_SIZE)

    encrypted_key_int = encrypt_integer(int_from_bytes(aes_key), public_key)
    rsa_size = (public_key.n.bit_length() + 7) // 8
    encrypted_key = int_to_fixed_bytes(encrypted_key_int, rsa_size)
    ciphertext = encrypt_cbc(plaintext, aes_key, iv)
    container = EncryptedFileContainer(
        version=CONTAINER_VERSION,
        encrypted_key=encrypted_key,
        iv=iv,
        ciphertext=ciphertext,
    )
    container_der = encode_container(container)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(container_der)

    if debug_json_path is not None:
        debug_json_path.parent.mkdir(parents=True, exist_ok=True)
        debug_json_path.write_text(
            json.dumps(
                {
                    "aes_key_hex": aes_key.hex(),
                    "iv_hex": iv.hex(),
                    "encrypted_key_hex": encrypted_key.hex(),
                    "ciphertext_first_100_hex": ciphertext[:100].hex(),
                    "container_first_100_hex": container_der[:100].hex(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )


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

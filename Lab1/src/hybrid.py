"""Гибридное шифрование файла: AES-256-CBC плюс RSA-обертка ключа."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from src.aes import BLOCK_SIZE, decrypt_cbc, encrypt_cbc
from src.der import (
    AES_CBC_ALGORITHM_ID,
    DEFAULT_KEY_LABEL,
    RSA_ALGORITHM_ID,
    EncryptedFileContainer,
    decode_container,
    encode_container,
)
from src.rsa import (
    PrivateKey,
    PublicKey,
    decrypt_integer,
    encrypt_integer,
    int_from_bytes,
    int_to_fixed_bytes,
)


AES_KEY_SIZE = 32


def encrypt_file(
    input_path: Path,
    public_key: PublicKey,
    output_path: Path,
    debug_json_path: Path | None = None,
) -> None:
    plaintext = input_path.read_bytes()
    aes_key = secrets.token_bytes(AES_KEY_SIZE)
    iv = secrets.token_bytes(BLOCK_SIZE)

    encrypted_key_c = encrypt_integer(int_from_bytes(aes_key), public_key)
    ciphertext = encrypt_cbc(plaintext, aes_key, iv)

    header = EncryptedFileContainer(
        rsa_algorithm_id=RSA_ALGORITHM_ID,
        key_label=DEFAULT_KEY_LABEL,
        rsa_n=public_key.n,
        rsa_e=public_key.e,
        encrypted_key_c=encrypted_key_c,
        symmetric_algorithm_id=AES_CBC_ALGORITHM_ID,
        original_file_length=len(plaintext),
        iv=iv,
    )
    header_der = encode_container(header)
    container_bytes = header_der + ciphertext

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(container_bytes)

    if debug_json_path is not None:
        debug_json_path.parent.mkdir(parents=True, exist_ok=True)
        rsa_size = (public_key.n.bit_length() + 7) // 8
        debug_json_path.write_text(
            json.dumps(
                {
                    "header_length": len(header_der),
                    "ciphertext_length": len(ciphertext),
                    "original_file_length": len(plaintext),
                    "iv_hex": iv.hex(),
                    "encrypted_key_hex": int_to_fixed_bytes(encrypted_key_c, rsa_size).hex(),
                    "header_first_100_hex": header_der[:100].hex(),
                    "ciphertext_first_100_hex": ciphertext[:100].hex(),
                    "container_first_100_hex": container_bytes[:100].hex(),
                    "aes_key_hex": aes_key.hex(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def decrypt_file(input_path: Path, private_key: PrivateKey, output_path: Path) -> None:
    parsed = decode_container(input_path.read_bytes())
    header = parsed.header
    if len(header.iv) != BLOCK_SIZE:
        raise ValueError("invalid IV length in container")

    aes_key_int = decrypt_integer(header.encrypted_key_c, private_key)
    aes_key = int_to_fixed_bytes(aes_key_int, AES_KEY_SIZE)
    plaintext = decrypt_cbc(parsed.ciphertext, aes_key, header.iv)
    plaintext = plaintext[: header.original_file_length]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)

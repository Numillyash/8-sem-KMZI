"""Гибридное шифрование файла: AES-256-CBC плюс RSA-обертка ключа."""

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
    # Для каждого шифрования создаются новый AES-256 ключ и новый IV.
    aes_key = secrets.token_bytes(AES_KEY_SIZE)
    iv = secrets.token_bytes(BLOCK_SIZE)

    # RSA шифрует только короткий AES-ключ, а не весь файл.
    encrypted_key_int = encrypt_integer(int_from_bytes(aes_key), public_key)
    rsa_size = (public_key.n.bit_length() + 7) // 8
    encrypted_key = int_to_fixed_bytes(encrypted_key_int, rsa_size)
    # Содержимое файла шифруется блочным режимом AES-CBC с PKCS#7 padding.
    ciphertext = encrypt_cbc(plaintext, aes_key, iv)
    container = EncryptedFileContainer(
        version=CONTAINER_VERSION,
        encrypted_key=encrypted_key,
        iv=iv,
        ciphertext=ciphertext,
    )
    # Все поля складываются в структурированный ASN.1 DER-контейнер.
    container_der = encode_container(container)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(container_der)

    if debug_json_path is not None:
        # Debug JSON нужен только для отчета: он показывает ключевые промежуточные
        # значения в hex и не должен использоваться как защищенный формат хранения.
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
    # Расшифрование начинается с разбора DER-контейнера и проверки версии.
    container = decode_container(input_path.read_bytes())
    if container.version != CONTAINER_VERSION:
        raise ValueError(f"unsupported container version: {container.version}")
    if len(container.iv) != BLOCK_SIZE:
        raise ValueError("invalid IV length in container")

    encrypted_key_int = int_from_bytes(container.encrypted_key)
    # Закрытый RSA-ключ восстанавливает AES-ключ, после чего AES-CBC возвращает plaintext.
    aes_key_int = decrypt_integer(encrypted_key_int, private_key)
    aes_key = int_to_fixed_bytes(aes_key_int, AES_KEY_SIZE)
    plaintext = decrypt_cbc(container.ciphertext, aes_key, container.iv)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)

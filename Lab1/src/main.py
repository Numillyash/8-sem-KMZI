"""CLI-интерфейс для команд KMZI Lab1."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.crcforge import forge_crc32_file
from src.hybrid import decrypt_file, encrypt_file
from src.rsa import generate_keypair, load_private_key, load_public_key, save_private_key, save_public_key
from src.signatures import (
    create_crc32_container,
    create_sha256_container,
    load_signature,
    save_signature,
    verify_crc32_container,
    verify_sha256_container,
)


def build_parser() -> argparse.ArgumentParser:
    # Все лабораторные действия оформлены как subcommands, чтобы имена команд
    # оставались стабильными для демонстрации и отчета.
    parser = argparse.ArgumentParser(prog="python -m src.main", description="KMZI Lab1 RSA/AES tools")
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate RSA key pair")
    keygen.add_argument("--bits", type=int, default=1024)
    keygen.add_argument("--out", type=Path, required=True)

    encrypt = subparsers.add_parser("encrypt", help="Encrypt file into ASN.1 DER container")
    encrypt.add_argument("--file", type=Path, required=True)
    encrypt.add_argument("--public-key", type=Path, required=True)
    encrypt.add_argument("--out", type=Path, required=True)
    encrypt.add_argument("--debug-json", type=Path, help="Write educational encryption debug report")

    decrypt = subparsers.add_parser("decrypt", help="Decrypt ASN.1 DER container")
    decrypt.add_argument("--file", type=Path, required=True)
    decrypt.add_argument("--private-key", type=Path, required=True)
    decrypt.add_argument("--out", type=Path, required=True)

    sign_sha = subparsers.add_parser("sign-sha256", help="Sign file with RSA/SHA-256")
    sign_sha.add_argument("--file", type=Path, required=True)
    sign_sha.add_argument("--private-key", type=Path, required=True)
    sign_sha.add_argument("--signature", type=Path, required=True)

    verify_sha = subparsers.add_parser("verify-sha256", help="Verify RSA/SHA-256 signature")
    verify_sha.add_argument("--file", type=Path, required=True)
    verify_sha.add_argument("--public-key", type=Path, help="Optional external public key for consistency check")
    verify_sha.add_argument("--signature", type=Path, required=True)

    sign_crc = subparsers.add_parser("sign-crc32", help="Sign file with RSA/CRC32")
    sign_crc.add_argument("--file", type=Path, required=True)
    sign_crc.add_argument("--private-key", type=Path, required=True)
    sign_crc.add_argument("--signature", type=Path, required=True)

    verify_crc = subparsers.add_parser("verify-crc32", help="Verify RSA/CRC32 signature")
    verify_crc.add_argument("--file", type=Path, required=True)
    verify_crc.add_argument("--public-key", type=Path, help="Optional external public key for consistency check")
    verify_crc.add_argument("--signature", type=Path, required=True)

    forge = subparsers.add_parser("forge-crc32", help="Create D3 = D2 || patch with CRC32(D3)=CRC32(D1)")
    forge.add_argument("--original", type=Path, required=True)
    forge.add_argument("--modified", type=Path, required=True)
    forge.add_argument("--out", type=Path, required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "keygen":
            # keygen создает пару RSA-ключей и сохраняет их в JSON для отчета.
            private, public = generate_keypair(args.bits)
            save_private_key(args.out / "private.json", private)
            save_public_key(args.out / "public.json", public)
            print(f"Keys saved to: {args.out}")
            return 0

        if args.command == "encrypt":
            # encrypt формирует ASN.1 DER-контейнер с RSA-wrapped AES key и ciphertext.
            encrypt_file(args.file, load_public_key(args.public_key), args.out, args.debug_json)
            print(f"Encrypted file saved to: {args.out}")
            if args.debug_json:
                print(f"Debug JSON saved to: {args.debug_json}")
            return 0

        if args.command == "decrypt":
            # decrypt разбирает DER-контейнер и восстанавливает исходный файл.
            decrypt_file(args.file, load_private_key(args.private_key), args.out)
            print(f"Decrypted file saved to: {args.out}")
            return 0

        if args.command == "sign-sha256":
            # Подпись сохраняется не как текстовое число, а как DER SignatureFile.
            container = create_sha256_container(args.file.read_bytes(), load_private_key(args.private_key))
            save_signature(args.signature, container)
            print(f"Signature saved to: {args.signature}")
            return 0

        if args.command == "verify-sha256":
            # INVALID возвращает код 1, чтобы CLI можно было использовать в скриптах.
            external_public_key = load_public_key(args.public_key) if args.public_key else None
            ok = verify_sha256_container(
                args.file.read_bytes(),
                load_signature(args.signature),
                external_public_key,
            )
            print("VALID" if ok else "INVALID")
            return 0 if ok else 1

        if args.command == "sign-crc32":
            # CRC32-подпись нужна для демонстрации дополнительного задания.
            container = create_crc32_container(args.file.read_bytes(), load_private_key(args.private_key))
            save_signature(args.signature, container)
            print(f"Signature saved to: {args.signature}")
            return 0

        if args.command == "verify-crc32":
            # Проверка CRC32 использует тот же DER-контейнер, но другой algorithm id.
            external_public_key = load_public_key(args.public_key) if args.public_key else None
            ok = verify_crc32_container(
                args.file.read_bytes(),
                load_signature(args.signature),
                external_public_key,
            )
            print("VALID" if ok else "INVALID")
            return 0 if ok else 1

        if args.command == "forge-crc32":
            # forge-crc32 строит D3 = D2 || patch для совпадения CRC32 с D1.
            forge_crc32_file(args.original, args.modified, args.out)
            print(f"Forged file saved to: {args.out}")
            return 0

    except (OSError, ValueError) as exc:
        # Верхний уровень CLI превращает ошибки файлов/формата в понятный код 1.
        print(f"ERROR: {exc}")
        return 1

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

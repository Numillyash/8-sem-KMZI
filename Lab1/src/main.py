"""Command-line interface for KMZI Lab1."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.crcforge import forge_crc32_file
from src.hybrid import decrypt_file, encrypt_file
from src.rsa import generate_keypair, load_private_key, load_public_key, save_private_key, save_public_key
from src.signatures import (
    load_signature,
    save_signature,
    sign_crc32,
    sign_sha256,
    verify_crc32,
    verify_sha256,
)


def build_parser() -> argparse.ArgumentParser:
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
    verify_sha.add_argument("--public-key", type=Path, required=True)
    verify_sha.add_argument("--signature", type=Path, required=True)

    sign_crc = subparsers.add_parser("sign-crc32", help="Sign file with RSA/CRC32")
    sign_crc.add_argument("--file", type=Path, required=True)
    sign_crc.add_argument("--private-key", type=Path, required=True)
    sign_crc.add_argument("--signature", type=Path, required=True)

    verify_crc = subparsers.add_parser("verify-crc32", help="Verify RSA/CRC32 signature")
    verify_crc.add_argument("--file", type=Path, required=True)
    verify_crc.add_argument("--public-key", type=Path, required=True)
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
            private, public = generate_keypair(args.bits)
            save_private_key(args.out / "private.json", private)
            save_public_key(args.out / "public.json", public)
            print(f"Keys saved to: {args.out}")
            return 0

        if args.command == "encrypt":
            encrypt_file(args.file, load_public_key(args.public_key), args.out, args.debug_json)
            print(f"Encrypted file saved to: {args.out}")
            if args.debug_json:
                print(f"Debug JSON saved to: {args.debug_json}")
            return 0

        if args.command == "decrypt":
            decrypt_file(args.file, load_private_key(args.private_key), args.out)
            print(f"Decrypted file saved to: {args.out}")
            return 0

        if args.command == "sign-sha256":
            signature = sign_sha256(args.file.read_bytes(), load_private_key(args.private_key))
            save_signature(args.signature, signature)
            print(f"Signature saved to: {args.signature}")
            return 0

        if args.command == "verify-sha256":
            ok = verify_sha256(args.file.read_bytes(), load_signature(args.signature), load_public_key(args.public_key))
            print("VALID" if ok else "INVALID")
            return 0 if ok else 1

        if args.command == "sign-crc32":
            signature = sign_crc32(args.file.read_bytes(), load_private_key(args.private_key))
            save_signature(args.signature, signature)
            print(f"Signature saved to: {args.signature}")
            return 0

        if args.command == "verify-crc32":
            ok = verify_crc32(args.file.read_bytes(), load_signature(args.signature), load_public_key(args.public_key))
            print("VALID" if ok else "INVALID")
            return 0 if ok else 1

        if args.command == "forge-crc32":
            forge_crc32_file(args.original, args.modified, args.out)
            print(f"Forged file saved to: {args.out}")
            return 0

    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 1

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""CLI entry point for file signing and signature verification."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.config import APP_CONFIG
from src.sign import sign_file, verify_file


def build_parser() -> argparse.ArgumentParser:
    """Create CLI parser with sign and verify commands."""
    parser = argparse.ArgumentParser(
        prog="gost-sign-cli",
        description="Educational signer/verifier for GOST R 34.10-2018",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="Sign file")
    sign_parser.add_argument("--file", required=True, type=Path, help="Input file path")
    sign_parser.add_argument(
        "--private-key", required=True, type=Path, help="Path to private key JSON"
    )
    sign_parser.add_argument(
        "--signature", required=True, type=Path, help="Output signature file path"
    )
    sign_parser.add_argument(
        "--hash-alg",
        default=APP_CONFIG.default_hash_alg,
        choices=["streebog256", "streebog512"],
        help="Hash algorithm",
    )

    verify_parser = subparsers.add_parser("verify", help="Verify file signature")
    verify_parser.add_argument("--file", required=True, type=Path, help="Input file path")
    verify_parser.add_argument(
        "--signature", required=True, type=Path, help="Path to signature file"
    )
    verify_parser.add_argument(
        "--public-key", required=True, type=Path, help="Path to public key JSON"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run CLI command and return process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "sign":
        try:
            sign_file(
                file_path=args.file,
                private_key_path=args.private_key,
                signature_path=args.signature,
                hash_alg=args.hash_alg,
            )
        except (ValueError, OSError) as exc:
            print(f"SIGN ERROR: {exc}")
            return 1
        print(f"Signature saved to: {args.signature}")
        return 0

    if args.command == "verify":
        is_valid = verify_file(
            file_path=args.file,
            signature_path=args.signature,
            public_key_path=args.public_key,
        )
        print("VALID" if is_valid else "INVALID")
        return 0 if is_valid else 1

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

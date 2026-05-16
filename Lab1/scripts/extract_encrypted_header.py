"""Extract DER header from Lab1 encrypted file (.enc = DER header || raw ciphertext)."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.der import decode_container


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract DER header from encrypted Lab1 file")
    parser.add_argument("--file", type=Path, required=True, help="Input .enc file")
    parser.add_argument("--out", type=Path, required=True, help="Output .header.der file")
    args = parser.parse_args()

    data = args.file.read_bytes()
    parsed = decode_container(data)
    header = data[: parsed.header_length]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(header)
    print(f"Header length: {parsed.header_length} bytes")
    print(f"Ciphertext length: {len(parsed.ciphertext)} bytes")
    print(f"Header written to: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

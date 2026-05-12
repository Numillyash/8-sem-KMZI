"""CRC32 four-byte append patch.

CRC32 is linear over GF(2). Instead of searching all 2^32 suffixes, we build a
32-column linear system that describes how each patch bit changes the final CRC.
"""

from __future__ import annotations

import binascii
from pathlib import Path


def crc32_bytes(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def _solve_gf2(columns: list[int], target: int) -> int:
    # Rows store equation coefficients in low 32 bits and the target bit in bit 32.
    rows = []
    for bit in range(32):
        coeffs = 0
        for column_index, column in enumerate(columns):
            if (column >> bit) & 1:
                coeffs |= 1 << column_index
        rows.append(coeffs | (((target >> bit) & 1) << 32))

    pivot_row = 0
    for col in range(32):
        selected = next((r for r in range(pivot_row, 32) if (rows[r] >> col) & 1), None)
        if selected is None:
            continue
        rows[pivot_row], rows[selected] = rows[selected], rows[pivot_row]
        for r in range(32):
            if r != pivot_row and ((rows[r] >> col) & 1):
                rows[r] ^= rows[pivot_row]
        pivot_row += 1

    for row in rows:
        if (row & 0xFFFFFFFF) == 0 and ((row >> 32) & 1):
            raise ValueError("CRC32 patch system has no solution")

    solution = 0
    for row in rows:
        coeffs = row & 0xFFFFFFFF
        if coeffs and coeffs & (coeffs - 1) == 0 and ((row >> 32) & 1):
            solution |= coeffs
    return solution


def crc32_patch_for_append(prefix: bytes, target_crc: int) -> bytes:
    zero_patch = b"\x00\x00\x00\x00"
    base_crc = crc32_bytes(prefix + zero_patch)
    columns = []
    for bit in range(32):
        patch_value = 1 << bit
        patch = patch_value.to_bytes(4, byteorder="little")
        columns.append(crc32_bytes(prefix + patch) ^ base_crc)

    solution = _solve_gf2(columns, target_crc ^ base_crc)
    patch = solution.to_bytes(4, byteorder="little")
    if crc32_bytes(prefix + patch) != target_crc:
        raise ValueError("internal CRC32 patch verification failed")
    return patch


def forge_crc32_file(original_path: Path, modified_path: Path, output_path: Path) -> None:
    original = original_path.read_bytes()
    modified = modified_path.read_bytes()
    patch = crc32_patch_for_append(modified, crc32_bytes(original))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(modified + patch)


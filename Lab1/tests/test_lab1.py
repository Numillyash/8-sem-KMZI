"""Smoke tests for KMZI Lab1."""

from __future__ import annotations

from pathlib import Path

from src.aes import decrypt_block, encrypt_block
from src.crcforge import crc32_bytes, forge_crc32_file
from src.hybrid import decrypt_file, encrypt_file
from src.rsa import generate_keypair
from src.signatures import sign_crc32, sign_sha256, verify_crc32, verify_sha256


def test_aes256_known_block_vector() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")

    assert encrypt_block(plaintext, key) == ciphertext
    assert decrypt_block(ciphertext, key) == plaintext


def test_encrypt_decrypt_restores_original_file(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair(512)
    source = tmp_path / "message.txt"
    encrypted = tmp_path / "message.enc"
    decrypted = tmp_path / "message.dec"
    source.write_bytes(b"KMZI Lab1 hybrid encryption test\nSecond line.\x00\x01")

    encrypt_file(source, public_key, encrypted)
    decrypt_file(encrypted, private_key, decrypted)

    assert decrypted.read_bytes() == source.read_bytes()
    assert encrypted.read_bytes().startswith(b"\x30")


def test_sha256_signature_verifies_original_and_fails_modified() -> None:
    private_key, public_key = generate_keypair(512)
    original = b"original message"
    modified = b"modified message"

    signature = sign_sha256(original, private_key)

    assert verify_sha256(original, signature, public_key) is True
    assert verify_sha256(modified, signature, public_key) is False


def test_crc32_signature_verifies_original() -> None:
    private_key, public_key = generate_keypair(512)
    data = b"D1 document for CRC32 signature"

    signature = sign_crc32(data, private_key)

    assert verify_crc32(data, signature, public_key) is True


def test_forge_crc32_preserves_d2_and_matches_d1_crc(tmp_path: Path) -> None:
    d1 = tmp_path / "d1.txt"
    d2 = tmp_path / "d2.txt"
    d3 = tmp_path / "d3.txt"
    d1.write_bytes(b"Original D1 content signed with CRC32.")
    d2_bytes = b"Modified D2 content that must be preserved."
    d2.write_bytes(d2_bytes)

    forge_crc32_file(d1, d2, d3)
    forged = d3.read_bytes()

    assert forged.startswith(d2_bytes)
    assert len(forged) == len(d2_bytes) + 4
    assert crc32_bytes(forged) == crc32_bytes(d1.read_bytes())


def test_forged_d3_passes_old_crc32_signature() -> None:
    private_key, public_key = generate_keypair(512)
    d1 = b"Signed D1 content"
    d2 = b"Attacker-selected D2 content"
    signature = sign_crc32(d1, private_key)

    from src.crcforge import crc32_patch_for_append

    d3 = d2 + crc32_patch_for_append(d2, crc32_bytes(d1))

    assert verify_crc32(d3, signature, public_key) is True


"""Smoke tests for KMZI Lab1."""

from __future__ import annotations

import json
import importlib.util
from pathlib import Path

from src.aes import decrypt_block, encrypt_block
from src.crcforge import crc32_bytes, forge_crc32_file
from src.hybrid import decrypt_file, encrypt_file
from src.rsa import generate_keypair
from src.sigder import SignatureContainer
from src.signatures import (
    create_crc32_container,
    create_sha256_container,
    load_signature,
    save_signature,
    sign_crc32,
    sign_sha256,
    verify_crc32,
    verify_crc32_container,
    verify_sha256,
    verify_sha256_container,
)


LAB_ROOT = Path(__file__).resolve().parents[1]


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


def test_encrypt_debug_json_contains_key_and_iv(tmp_path: Path) -> None:
    _, public_key = generate_keypair(512)
    source = tmp_path / "message.txt"
    encrypted = tmp_path / "message.enc"
    debug_json = tmp_path / "encrypt_debug.json"
    source.write_bytes(b"debug report test")

    encrypt_file(source, public_key, encrypted, debug_json)
    debug = json.loads(debug_json.read_text(encoding="utf-8"))

    assert bytes.fromhex(debug["aes_key_hex"])
    assert len(bytes.fromhex(debug["aes_key_hex"])) == 32
    assert len(bytes.fromhex(debug["iv_hex"])) == 16
    assert set(debug) == {
        "aes_key_hex",
        "iv_hex",
        "encrypted_key_hex",
        "ciphertext_first_100_hex",
        "container_first_100_hex",
    }


def test_sha256_signature_verifies_original_and_fails_modified() -> None:
    private_key, public_key = generate_keypair(512)
    original = b"original message"
    modified = b"modified message"

    signature = sign_sha256(original, private_key)

    assert verify_sha256(original, signature, public_key) is True
    assert verify_sha256(modified, signature, public_key) is False


def test_sha256_der_signature_file_verifies_original_and_fails_modified(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair(512)
    original = b"original message"
    modified = b"modified message"
    signature_path = tmp_path / "message.sha256.sig"

    save_signature(signature_path, create_sha256_container(original, private_key))
    container = load_signature(signature_path)

    assert signature_path.read_bytes().startswith(b"\x30")
    assert verify_sha256_container(original, container, public_key) is True
    assert verify_sha256_container(modified, container, public_key) is False


def test_crc32_signature_verifies_original() -> None:
    private_key, public_key = generate_keypair(512)
    data = b"D1 document for CRC32 signature"

    signature = sign_crc32(data, private_key)

    assert verify_crc32(data, signature, public_key) is True


def test_crc32_der_signature_file_verifies_d1(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair(512)
    data = b"D1 document for CRC32 signature"
    signature_path = tmp_path / "d1.crc32.sig"

    save_signature(signature_path, create_crc32_container(data, private_key))
    container = load_signature(signature_path)

    assert signature_path.read_bytes().startswith(b"\x30")
    assert verify_crc32_container(data, container, public_key) is True


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


def test_forged_d3_passes_old_crc32_der_signature(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair(512)
    d1 = b"Signed D1 content"
    d2 = b"Attacker-selected D2 content"
    signature_path = tmp_path / "d1.crc32.sig"

    from src.crcforge import crc32_patch_for_append

    save_signature(signature_path, create_crc32_container(d1, private_key))
    d3 = d2 + crc32_patch_for_append(d2, crc32_bytes(d1))

    assert verify_crc32_container(d3, load_signature(signature_path), public_key) is True


def test_der_signature_corruption_fails_verification(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair(512)
    data = b"message"
    signature_path = tmp_path / "message.sha256.sig"
    save_signature(signature_path, create_sha256_container(data, private_key))
    container = load_signature(signature_path)

    bad_algorithm = SignatureContainer(
        version=container.version,
        algorithm="rsa-crc32",
        hash_value=container.hash_value,
        hash_mod_n=container.hash_mod_n,
        signature=container.signature,
    )
    assert verify_sha256_container(data, bad_algorithm, public_key) is False

    bad_signature = SignatureContainer(
        version=container.version,
        algorithm=container.algorithm,
        hash_value=container.hash_value,
        hash_mod_n=container.hash_mod_n,
        signature=(container.signature + 1) % public_key.n,
    )
    assert verify_sha256_container(data, bad_signature, public_key) is False


def test_report_generator_creates_expected_files(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "message.txt").write_text("Report generator message", encoding="utf-8")
    (data_dir / "d1.txt").write_text("CRC32 original D1", encoding="utf-8")
    (data_dir / "d2.txt").write_text("CRC32 modified D2", encoding="utf-8")

    script_path = LAB_ROOT / "scripts" / "generate_report_materials.py"
    spec = importlib.util.spec_from_file_location("generate_report_materials", script_path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    data = module.generate_report_materials(tmp_path, bits=512)
    generated_dir = tmp_path / "report" / "generated"

    assert (generated_dir / "report_data.md").exists()
    assert (generated_dir / "report_data.json").exists()
    assert (generated_dir / "verification_log.txt").exists()
    assert (generated_dir / "hex_dump.md").exists()
    assert (generated_dir / "crc32_demo.md").exists()
    assert (generated_dir / "theory.md").exists()
    assert (generated_dir / "control_questions.md").exists()
    assert (generated_dir / "stand_commands.md").exists()
    full_report = generated_dir / "full_report_draft.md"
    assert full_report.exists()
    assert data["files"]["decrypted_equals_original"] is True
    assert data["sha256_signature"]["original_verification"] == "VALID"
    assert data["sha256_signature"]["modified_verification"] == "INVALID"
    assert data["sha256_signature"]["signature_der_first_100_hex"].startswith("30")
    assert data["crc32_signature"]["d3_crc32_equals_d1"] is True
    assert data["crc32_signature"]["signature_der_first_100_hex"].startswith("30")

    full_report_text = full_report.read_text(encoding="utf-8")
    assert "Лабораторная работа №1" in full_report_text
    assert "RSA" in full_report_text
    assert "AES-256-CBC" in full_report_text
    assert "ASN.1 DER" in full_report_text
    assert "Электронная подпись RSA/SHA-256" in full_report_text
    assert "CRC32" in full_report_text
    assert "Контрольные вопросы" in full_report_text
    assert "Вывод" in full_report_text

    forbidden_markers = ("Рџ", "Рґ", "СЊ", "С…", "TODO", "not_performed", "placeholder")
    for path in generated_dir.glob("*.md"):
        text = path.read_text(encoding="utf-8")
        for marker in forbidden_markers:
            assert marker not in text

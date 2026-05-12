"""Minimal DER encoder/decoder for the hybrid-encryption container."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EncryptedFileContainer:
    version: int
    encrypted_key: bytes
    iv: bytes
    ciphertext: bytes


def _encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative DER length")
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("only non-negative integers are supported")
    raw = b"\x00" if value == 0 else value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _encode_tlv(0x02, raw)


def _encode_octet_string(value: bytes) -> bytes:
    return _encode_tlv(0x04, value)


def encode_container(container: EncryptedFileContainer) -> bytes:
    body = b"".join(
        (
            _encode_integer(container.version),
            _encode_octet_string(container.encrypted_key),
            _encode_octet_string(container.iv),
            _encode_octet_string(container.ciphertext),
        )
    )
    return _encode_tlv(0x30, body)


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("unexpected end of DER data")
    first = data[offset]
    offset += 1
    if first < 128:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite DER lengths are not allowed")
    if offset + count > len(data):
        raise ValueError("truncated DER length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 128:
        raise ValueError("non-minimal DER length")
    return length, offset + count


def _read_tlv(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise ValueError(f"expected DER tag 0x{expected_tag:02x}")
    length, value_offset = _read_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return data[value_offset:end], end


def _decode_integer(value: bytes) -> int:
    if not value:
        raise ValueError("empty DER integer")
    return int.from_bytes(value, "big")


def decode_container(data: bytes) -> EncryptedFileContainer:
    body, offset = _read_tlv(data, 0, 0x30)
    if offset != len(data):
        raise ValueError("trailing data after DER sequence")

    inner = 0
    version_raw, inner = _read_tlv(body, inner, 0x02)
    encrypted_key, inner = _read_tlv(body, inner, 0x04)
    iv, inner = _read_tlv(body, inner, 0x04)
    ciphertext, inner = _read_tlv(body, inner, 0x04)
    if inner != len(body):
        raise ValueError("trailing data inside DER sequence")

    return EncryptedFileContainer(
        version=_decode_integer(version_raw),
        encrypted_key=encrypted_key,
        iv=iv,
        ciphertext=ciphertext,
    )


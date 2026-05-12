"""ASN.1 DER containers for RSA signature files."""

from __future__ import annotations

from dataclasses import dataclass


SIGNATURE_VERSION = 1


@dataclass(frozen=True)
class SignatureContainer:
    version: int
    algorithm: str
    hash_value: bytes
    hash_mod_n: int
    signature: int


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


def _encode_utf8_string(value: str) -> bytes:
    return _encode_tlv(0x0C, value.encode("utf-8"))


def _encode_octet_string(value: bytes) -> bytes:
    return _encode_tlv(0x04, value)


def encode_signature_container(container: SignatureContainer) -> bytes:
    body = b"".join(
        (
            _encode_integer(container.version),
            _encode_utf8_string(container.algorithm),
            _encode_octet_string(container.hash_value),
            _encode_integer(container.hash_mod_n),
            _encode_integer(container.signature),
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
    if len(value) > 1 and value[0] == 0 and not (value[1] & 0x80):
        raise ValueError("non-minimal DER integer")
    if value[0] & 0x80:
        raise ValueError("negative DER integer is not supported")
    return int.from_bytes(value, "big")


def decode_signature_container(data: bytes) -> SignatureContainer:
    body, offset = _read_tlv(data, 0, 0x30)
    if offset != len(data):
        raise ValueError("trailing data after DER sequence")

    inner = 0
    version_raw, inner = _read_tlv(body, inner, 0x02)
    algorithm_raw, inner = _read_tlv(body, inner, 0x0C)
    hash_value, inner = _read_tlv(body, inner, 0x04)
    hash_mod_n_raw, inner = _read_tlv(body, inner, 0x02)
    signature_raw, inner = _read_tlv(body, inner, 0x02)
    if inner != len(body):
        raise ValueError("trailing data inside DER sequence")

    return SignatureContainer(
        version=_decode_integer(version_raw),
        algorithm=algorithm_raw.decode("utf-8"),
        hash_value=hash_value,
        hash_mod_n=_decode_integer(hash_mod_n_raw),
        signature=_decode_integer(signature_raw),
    )


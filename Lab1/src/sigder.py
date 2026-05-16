"""ASN.1 DER containers for methodical RSA signatures (Appendix A)."""

from __future__ import annotations

from dataclasses import dataclass


SIGNATURE_VERSION = 1
RSA_SHA256_ALGORITHM_ID = b"\x00\x40"
RSA_CRC32_ALGORITHM_ID = b"\x00\x41"
RSA_SHA256_KEY_LABEL = "rsaSha256Sign"
RSA_CRC32_KEY_LABEL = "rsaCrc32Sign"


@dataclass(frozen=True)
class SignatureContainer:
    """Methodical signature structure with embedded public key and signature."""

    version: int
    algorithm_id: bytes
    key_label: str
    rsa_n: int
    rsa_e: int
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


def _encode_octet_string(value: bytes) -> bytes:
    return _encode_tlv(0x04, value)


def _encode_utf8_string(value: str) -> bytes:
    return _encode_tlv(0x0C, value.encode("utf-8"))


def _encode_sequence(value: bytes) -> bytes:
    return _encode_tlv(0x30, value)


def _encode_set(value: bytes) -> bytes:
    return _encode_tlv(0x31, value)


def encode_signature_container(container: SignatureContainer) -> bytes:
    public_key = _encode_sequence(_encode_integer(container.rsa_n) + _encode_integer(container.rsa_e))
    params = _encode_sequence(b"")
    signature = _encode_sequence(_encode_integer(container.signature))

    algorithm_info = _encode_sequence(
        b"".join(
            (
                _encode_octet_string(container.algorithm_id),
                _encode_utf8_string(container.key_label),
                public_key,
                params,
                signature,
            )
        )
    )

    body = _encode_set(algorithm_info) + _encode_sequence(b"")
    return _encode_sequence(body)


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
    set_body, inner = _read_tlv(body, inner, 0x31)
    additional_data, inner = _read_tlv(body, inner, 0x30)
    if inner != len(body):
        raise ValueError("trailing data inside DER sequence")
    if additional_data:
        raise ValueError("signature additional data sequence must be empty")

    set_inner = 0
    algorithm_sequence, set_inner = _read_tlv(set_body, set_inner, 0x30)
    if set_inner != len(set_body):
        raise ValueError("unexpected data inside outer SET")

    alg_inner = 0
    algorithm_id, alg_inner = _read_tlv(algorithm_sequence, alg_inner, 0x04)
    key_label_raw, alg_inner = _read_tlv(algorithm_sequence, alg_inner, 0x0C)
    public_key_sequence, alg_inner = _read_tlv(algorithm_sequence, alg_inner, 0x30)
    params_sequence, alg_inner = _read_tlv(algorithm_sequence, alg_inner, 0x30)
    signature_sequence, alg_inner = _read_tlv(algorithm_sequence, alg_inner, 0x30)
    if alg_inner != len(algorithm_sequence):
        raise ValueError("trailing data inside algorithm sequence")

    if params_sequence:
        raise ValueError("signature params sequence must be empty")

    pk_inner = 0
    n_raw, pk_inner = _read_tlv(public_key_sequence, pk_inner, 0x02)
    e_raw, pk_inner = _read_tlv(public_key_sequence, pk_inner, 0x02)
    if pk_inner != len(public_key_sequence):
        raise ValueError("trailing data inside RSA public key sequence")

    sig_inner = 0
    s_raw, sig_inner = _read_tlv(signature_sequence, sig_inner, 0x02)
    if sig_inner != len(signature_sequence):
        raise ValueError("trailing data inside signature sequence")

    return SignatureContainer(
        version=SIGNATURE_VERSION,
        algorithm_id=algorithm_id,
        key_label=key_label_raw.decode("utf-8"),
        rsa_n=_decode_integer(n_raw),
        rsa_e=_decode_integer(e_raw),
        signature=_decode_integer(s_raw),
    )

"""ASN.1 DER encoding tests for signature container."""

from __future__ import annotations

import asn1

from src.config import VARIANT_8
from src.sigfile import SignaturePayload, decode_signature, encode_signature


def _read_primitive(decoder: asn1.Decoder, nr: int):
    tag, value = decoder.read()
    assert tag is not None
    assert tag.nr == nr
    assert tag.typ == asn1.Types.Primitive
    return value


def _enter(decoder: asn1.Decoder, nr: int) -> None:
    tag = decoder.peek()
    assert tag is not None
    assert tag.nr == nr
    assert tag.typ == asn1.Types.Constructed
    decoder.enter()


def _encoded_curve_a(blob: bytes) -> int:
    decoder = asn1.Decoder()
    decoder.start(blob)

    _enter(decoder, asn1.Numbers.Sequence)
    _enter(decoder, asn1.Numbers.Set)
    _enter(decoder, asn1.Numbers.Sequence)

    _read_primitive(decoder, asn1.Numbers.OctetString)
    _read_primitive(decoder, asn1.Numbers.UTF8String)

    _enter(decoder, asn1.Numbers.Sequence)
    _read_primitive(decoder, asn1.Numbers.Integer)
    _read_primitive(decoder, asn1.Numbers.Integer)
    decoder.leave()

    _enter(decoder, asn1.Numbers.Sequence)
    _enter(decoder, asn1.Numbers.Sequence)
    _read_primitive(decoder, asn1.Numbers.Integer)
    decoder.leave()

    _enter(decoder, asn1.Numbers.Sequence)
    return int(_read_primitive(decoder, asn1.Numbers.Integer))


def _variant_payload() -> SignaturePayload:
    return SignaturePayload(
        hash_alg="streebog256",
        curve_id=VARIANT_8.curve_id,
        qx=1,
        qy=2,
        p=VARIANT_8.p,
        a=VARIANT_8.a,
        b=VARIANT_8.b,
        px=VARIANT_8.px,
        py=VARIANT_8.py,
        q=VARIANT_8.q,
        r=3,
        s=4,
    )


def test_variant8_a_is_encoded_as_non_negative_field_representative() -> None:
    """Internal a = -1 must be encoded as p - 1, not negative INTEGER -1."""
    encoded_a = _encoded_curve_a(encode_signature(_variant_payload()))

    assert encoded_a >= 0
    assert encoded_a == VARIANT_8.a % VARIANT_8.p
    assert encoded_a == VARIANT_8.p - 1


def test_variant8_decoded_payload_keeps_internal_a_value() -> None:
    """Decoded payload remains compatible with internal curve config."""
    payload = decode_signature(encode_signature(_variant_payload()))

    assert payload.a == VARIANT_8.a

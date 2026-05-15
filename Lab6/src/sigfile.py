"""ASN.1 DER signature container for GOST R 34.10-2018 lab work.

Format from Appendix G:

SEQUENCE {
    SET {
        SEQUENCE {
            OCTET STRING      -- algorithm identifier bytes: 80 06 07 00
            UTF8String        -- 'gostSignKey'
            SEQUENCE {        -- public key Q
                INTEGER qx
                INTEGER qy
            }
            SEQUENCE {        -- curve parameters
                SEQUENCE {    -- field params
                    INTEGER p
                }
                SEQUENCE {    -- curve params
                    INTEGER a
                    INTEGER b
                }
                SEQUENCE {    -- base point P
                    INTEGER px
                    INTEGER py
                }
                INTEGER q
            }
            SEQUENCE {        -- signature
                INTEGER r
                INTEGER s
            }
        }
    }
    SEQUENCE {}              -- file params, unused
}
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import asn1

from src.config import APP_CONFIG


@dataclass(frozen=True)
class SignaturePayload:
    """Signature payload stored inside ASN.1 container."""

    hash_alg: str
    curve_id: str
    qx: int
    qy: int
    p: int
    a: int
    b: int
    px: int
    py: int
    q: int
    r: int
    s: int


def encode_signature(payload: SignaturePayload) -> bytes:
    """Encode signature payload to ASN.1 DER bytes."""
    encoder = asn1.Encoder()
    encoder.start()

    encoder.enter(asn1.Numbers.Sequence)

    encoder.enter(asn1.Numbers.Set)
    encoder.enter(asn1.Numbers.Sequence)

    encoder.write(APP_CONFIG.gost_algorithm_id, asn1.Numbers.OctetString)
    encoder.write(APP_CONFIG.signature_key_label, asn1.Numbers.UTF8String)

    # Public key Q
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(payload.qx, asn1.Numbers.Integer)
    encoder.write(payload.qy, asn1.Numbers.Integer)
    encoder.leave()

    # Curve parameters
    encoder.enter(asn1.Numbers.Sequence)

    # Field parameters
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(payload.p, asn1.Numbers.Integer)
    encoder.leave()

    # Curve coefficients. ASN.1 stores finite-field parameters as non-negative
    # INTEGER values, so internal a = -1 is encoded as p - 1.
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(payload.a % payload.p, asn1.Numbers.Integer)
    encoder.write(payload.b, asn1.Numbers.Integer)
    encoder.leave()

    # Base point P
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(payload.px, asn1.Numbers.Integer)
    encoder.write(payload.py, asn1.Numbers.Integer)
    encoder.leave()

    # Subgroup order q
    encoder.write(payload.q, asn1.Numbers.Integer)
    encoder.leave()

    # Signature (r, s)
    encoder.enter(asn1.Numbers.Sequence)
    encoder.write(payload.r, asn1.Numbers.Integer)
    encoder.write(payload.s, asn1.Numbers.Integer)
    encoder.leave()

    encoder.leave()
    encoder.leave()

    # Unused file params
    encoder.enter(asn1.Numbers.Sequence)
    encoder.leave()

    encoder.leave()

    return encoder.output()


def _expect_constructed(decoder: asn1.Decoder, nr: int) -> None:
    """Enter a constructed ASN.1 object of the expected type."""
    tag = decoder.peek()
    if tag is None:
        raise ValueError("Unexpected end of ASN.1 data")
    if tag.nr != nr or tag.typ != asn1.Types.Constructed:
        raise ValueError(f"Expected constructed ASN.1 tag {nr}, got {tag}")
    decoder.enter()


def _read_primitive(decoder: asn1.Decoder, nr: int):
    """Read a primitive ASN.1 value of the expected type."""
    tag, value = decoder.read()
    if tag is None:
        raise ValueError("Unexpected end of ASN.1 data")
    if tag.nr != nr or tag.typ != asn1.Types.Primitive:
        raise ValueError(f"Expected primitive ASN.1 tag {nr}, got {tag}")
    return value


def decode_signature(blob: bytes) -> SignaturePayload:
    """Decode ASN.1 DER signature container."""
    decoder = asn1.Decoder()
    decoder.start(blob)

    _expect_constructed(decoder, asn1.Numbers.Sequence)

    _expect_constructed(decoder, asn1.Numbers.Set)
    _expect_constructed(decoder, asn1.Numbers.Sequence)

    algorithm_id = bytes(_read_primitive(decoder, asn1.Numbers.OctetString))
    if algorithm_id != APP_CONFIG.gost_algorithm_id:
        raise ValueError("Unexpected algorithm identifier")

    key_label = _read_primitive(decoder, asn1.Numbers.UTF8String)
    if not isinstance(key_label, str):
        raise ValueError("Invalid key label type")

    _expect_constructed(decoder, asn1.Numbers.Sequence)
    qx = int(_read_primitive(decoder, asn1.Numbers.Integer))
    qy = int(_read_primitive(decoder, asn1.Numbers.Integer))
    decoder.leave()

    _expect_constructed(decoder, asn1.Numbers.Sequence)

    _expect_constructed(decoder, asn1.Numbers.Sequence)
    p = int(_read_primitive(decoder, asn1.Numbers.Integer))
    decoder.leave()

    _expect_constructed(decoder, asn1.Numbers.Sequence)
    a_encoded = int(_read_primitive(decoder, asn1.Numbers.Integer))
    a = -1 if a_encoded == p - 1 else a_encoded
    b = int(_read_primitive(decoder, asn1.Numbers.Integer))
    decoder.leave()

    _expect_constructed(decoder, asn1.Numbers.Sequence)
    px = int(_read_primitive(decoder, asn1.Numbers.Integer))
    py = int(_read_primitive(decoder, asn1.Numbers.Integer))
    decoder.leave()

    q = int(_read_primitive(decoder, asn1.Numbers.Integer))
    decoder.leave()

    _expect_constructed(decoder, asn1.Numbers.Sequence)
    r = int(_read_primitive(decoder, asn1.Numbers.Integer))
    s = int(_read_primitive(decoder, asn1.Numbers.Integer))
    decoder.leave()

    decoder.leave()
    decoder.leave()

    _expect_constructed(decoder, asn1.Numbers.Sequence)
    if not decoder.eof():
        raise ValueError("File params sequence must be empty")
    decoder.leave()

    decoder.leave()

    if not decoder.eof():
        raise ValueError("Unexpected trailing bytes after ASN.1 container")

    return SignaturePayload(
        hash_alg=APP_CONFIG.default_hash_alg,
        curve_id=APP_CONFIG.default_curve_id,
        qx=qx,
        qy=qy,
        p=p,
        a=a,
        b=b,
        px=px,
        py=py,
        q=q,
        r=r,
        s=s,
    )


def save_signature(path: Path, payload: SignaturePayload) -> None:
    """Write signature payload to file."""
    path.write_bytes(encode_signature(payload))


def load_signature(path: Path) -> SignaturePayload:
    """Read and parse signature payload from file."""
    return decode_signature(path.read_bytes())

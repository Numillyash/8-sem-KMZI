"""Tests for generated Lab6 report materials."""

from __future__ import annotations

import json
from pathlib import Path

import asn1

from scripts.generate_report_materials import REPORT_FILES, generate
from src.config import VARIANT_8
from src.sigfile import load_signature


BAD_TEXT_MARKERS = ("TODO", "placeholder", "Рџ", "Рґ", "СЊ", "С…")


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


def _encoded_curve_a(signature_path: Path) -> int:
    decoder = asn1.Decoder()
    decoder.start(signature_path.read_bytes())

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


def test_generate_report_materials_outputs_expected_files(tmp_path: Path) -> None:
    """Report generator must create complete UTF-8 materials with verification results."""
    generate(tmp_path)

    report_dir = tmp_path / "report" / "generated"
    generated_names = sorted(path.name for path in report_dir.iterdir())
    assert generated_names == sorted(REPORT_FILES)

    report_data = json.loads(
        (report_dir / "report_data.json").read_text(encoding="utf-8")
    )
    assert report_data["curve_variant"] == "variant 8"
    assert report_data["verify_original"] == "VALID"
    assert report_data["verify_modified"] == "INVALID"
    assert report_data["verify_corrupted"] == "INVALID"
    assert report_data["a_der_encoded"] == VARIANT_8.a % VARIANT_8.p

    verification_log = (report_dir / "verification_log.txt").read_text(
        encoding="utf-8"
    )
    assert "original message: VALID" in verification_log
    assert "modified message: INVALID" in verification_log
    assert "corrupted signature: INVALID" in verification_log

    for markdown_path in report_dir.glob("*.md"):
        text = markdown_path.read_text(encoding="utf-8")
        assert not any(marker in text for marker in BAD_TEXT_MARKERS), markdown_path.name

    signature_path = tmp_path / "artifacts" / "report_run" / "message.sig"
    assert _encoded_curve_a(signature_path) == VARIANT_8.a % VARIANT_8.p
    assert load_signature(signature_path).a == VARIANT_8.a

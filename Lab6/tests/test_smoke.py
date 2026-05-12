"""Smoke tests for sign/verify flow."""

from __future__ import annotations

import json
from pathlib import Path
from src.sign import sign_file, verify_file
from src.ecc import ECPoint, EllipticCurve
from src.sigfile import load_signature, save_signature, SignaturePayload


def _write_test_keys(tmp_path: Path) -> tuple[Path, Path]:
    # Маленькая учебная кривая для smoke-тестов.
    # Оставляем её отдельной от реального варианта 8, чтобы тесты были быстрыми.
    p = 17
    a = 2
    b = 2
    q = 19
    px = 5
    py = 1
    d = 7

    curve = EllipticCurve(
        p=p,
        a=a,
        b=b,
        q=q,
        base_point=ECPoint(px, py),
        curve_id="edu-tiny-v1",
    )

    q_point = curve.scalar_mul(d, curve.base_point)

    private_key = {
        "curve_id": "edu-tiny-v1",
        "p": p,
        "a": a,
        "b": b,
        "q": q,
        "P": {"x": px, "y": py},
        "d": d,
    }

    public_key = {
        "curve_id": "edu-tiny-v1",
        "p": p,
        "a": a,
        "b": b,
        "q": q,
        "P": {"x": px, "y": py},
        "Q": {"x": q_point.x, "y": q_point.y},
    }

    private_key_path = tmp_path / "private.json"
    public_key_path = tmp_path / "public.json"

    private_key_path.write_text(json.dumps(
        private_key, indent=2), encoding="utf-8")
    public_key_path.write_text(json.dumps(
        public_key, indent=2), encoding="utf-8")

    return private_key_path, public_key_path


def test_sign_and_verify_success(tmp_path: Path) -> None:
    """Smoke: generated signature must verify for original file."""
    private_key_path, public_key_path = _write_test_keys(tmp_path)
    message_path = tmp_path / "message.txt"
    signature_path = tmp_path / "message.sig"
    message_path.write_text("KMZI Lab 6 test message", encoding="utf-8")

    sign_file(message_path, private_key_path, signature_path)
    assert verify_file(message_path, signature_path, public_key_path) is True


def test_verify_fails_for_modified_message(tmp_path: Path) -> None:
    """Smoke: verification must fail after message modification."""
    private_key_path, public_key_path = _write_test_keys(tmp_path)
    message_path = tmp_path / "message.txt"
    signature_path = tmp_path / "message.sig"
    message_path.write_text("original", encoding="utf-8")

    sign_file(message_path, private_key_path, signature_path)
    message_path.write_text("tampered", encoding="utf-8")

    assert verify_file(message_path, signature_path, public_key_path) is False


def test_verify_fails_for_corrupted_signature(tmp_path: Path) -> None:
    """Smoke: verification must fail for corrupted signature values."""
    private_key_path, public_key_path = _write_test_keys(tmp_path)
    message_path = tmp_path / "message.txt"
    signature_path = tmp_path / "message.sig"
    message_path.write_text("message", encoding="utf-8")

    sign_file(message_path, private_key_path, signature_path)

    payload = load_signature(signature_path)

    # Портим именно значение подписи, а не случайный байт ASN.1-контейнера.
    bad_s = payload.s + 1
    if bad_s == payload.q:
        bad_s = 1

    corrupted_payload = SignaturePayload(
        hash_alg=payload.hash_alg,
        curve_id=payload.curve_id,
        qx=payload.qx,
        qy=payload.qy,
        p=payload.p,
        a=payload.a,
        b=payload.b,
        px=payload.px,
        py=payload.py,
        q=payload.q,
        r=payload.r,
        s=bad_s,
    )
    save_signature(signature_path, corrupted_payload)

    assert verify_file(message_path, signature_path, public_key_path) is False

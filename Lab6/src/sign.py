"""Signing and verification logic for GOST R 34.10-2018 (educational build)."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from src.config import APP_CONFIG, CurveParams
from src.ecc import ECPoint, EllipticCurve, mod_inv
from src.hashing import HashAlg, hash_to_alpha
from src.sigfile import SignaturePayload, load_signature, save_signature


@dataclass(frozen=True)
class PrivateKey:
    """Private key with curve parameters."""

    curve: EllipticCurve
    d: int


@dataclass(frozen=True)
class PublicKey:
    """Public key with curve parameters."""

    curve: EllipticCurve
    q_point: ECPoint


def _parse_point(raw: Any, field_name: str) -> ECPoint:
    """Parse point from JSON as {'x': int, 'y': int} or [x, y]."""
    if isinstance(raw, dict):
        return ECPoint(int(raw["x"]), int(raw["y"]))
    if isinstance(raw, list) and len(raw) == 2:
        return ECPoint(int(raw[0]), int(raw[1]))
    raise ValueError(f"Field '{field_name}' must be point object or [x, y]")


def _curve_from_key_json(key_data: dict[str, Any]) -> EllipticCurve:
    """Build curve object from key JSON fields."""
    base_point = _parse_point(key_data["P"], "P")
    curve_params = CurveParams(
        curve_id=str(key_data.get("curve_id", APP_CONFIG.default_curve_id)),
        p=int(key_data["p"]),
        a=int(key_data["a"]),
        b=int(key_data["b"]),
        q=int(key_data["q"]),
        px=base_point.x,
        py=base_point.y,
    )
    curve = EllipticCurve(
        p=curve_params.p,
        a=curve_params.a,
        b=curve_params.b,
        q=curve_params.q,
        base_point=base_point,
        curve_id=curve_params.curve_id,
    )
    if not curve.is_on_curve(curve.base_point):
        raise ValueError("Base point P is not on the curve")
    if curve.base_point.is_infinity:
        raise ValueError("Base point P must not be infinity")
    if not curve.scalar_mul(curve.q, curve.base_point).is_infinity:
        raise ValueError("Base point P must have order q")
    return curve


def load_private_key(path: Path) -> PrivateKey:
    """Load private key from JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    curve = _curve_from_key_json(data)
    d = int(data["d"])
    if not (0 < d < curve.q):
        raise ValueError("Private key d must satisfy 0 < d < q")
    return PrivateKey(curve=curve, d=d)


def load_public_key(path: Path) -> PublicKey:
    """Load public key from JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    curve = _curve_from_key_json(data)
    q_point = _parse_point(data["Q"], "Q")
    if not curve.is_on_curve(q_point):
        raise ValueError("Public key point Q is not on the curve")
    if q_point.is_infinity:
        raise ValueError("Public key point Q must not be infinity")
    if not curve.scalar_mul(curve.q, q_point).is_infinity:
        raise ValueError(
            "Public key point Q must belong to subgroup of order q")
    return PublicKey(curve=curve, q_point=q_point)


def _compute_e(file_path: Path, hash_alg: HashAlg, q: int) -> int:
    """Compute e = alpha mod q, where alpha = h(M)."""
    alpha = hash_to_alpha(file_path, hash_alg)
    e = alpha % q
    return 1 if e == 0 else e


def sign_file(
    file_path: Path,
    private_key_path: Path,
    signature_path: Path,
    hash_alg: HashAlg = cast(HashAlg, APP_CONFIG.default_hash_alg),
) -> SignaturePayload:
    """Create signature and save it in temporary binary container."""
    private_key = load_private_key(private_key_path)
    curve = private_key.curve
    e = _compute_e(file_path=file_path, hash_alg=hash_alg, q=curve.q)

    # Signature generation repeats until both r and s are non-zero.
    while True:
        k = secrets.randbelow(curve.q - 1) + 1  # random k in (0, q)
        c_point = curve.scalar_mul(k, curve.base_point)
        if c_point.is_infinity:
            continue

        r = c_point.x % curve.q
        if r == 0:
            continue

        s = (r * private_key.d + k * e) % curve.q
        if s == 0:
            continue
        break
    q_point = curve.scalar_mul(private_key.d, curve.base_point)
    if q_point.is_infinity:
        raise ValueError("Derived public key Q is infinity")
    payload = SignaturePayload(
        hash_alg=hash_alg,
        curve_id=curve.curve_id,
        qx=q_point.x,
        qy=q_point.y,
        p=curve.p,
        a=curve.a,
        b=curve.b,
        px=curve.base_point.x,
        py=curve.base_point.y,
        q=curve.q,
        r=r,
        s=s,
    )
    save_signature(signature_path, payload)
    return payload


def verify_file(
    file_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> bool:
    """Verify signature according to educational GOST R 34.10-2018 steps."""
    try:
        public_key = load_public_key(public_key_path)
        payload = load_signature(signature_path)
    except (ValueError, json.JSONDecodeError, OSError):
        return False

    curve = public_key.curve

    if payload.qx != public_key.q_point.x or payload.qy != public_key.q_point.y:
        return False

    if (
        payload.p != curve.p
        or payload.a != curve.a
        or payload.b != curve.b
        or payload.px != curve.base_point.x
        or payload.py != curve.base_point.y
        or payload.q != curve.q
    ):
        return False

    if payload.hash_alg not in ("streebog256", "streebog512"):
        return False
    hash_alg = cast(HashAlg, payload.hash_alg)

    r = payload.r
    s = payload.s
    if not (0 < r < curve.q and 0 < s < curve.q):
        return False

    try:
        e = _compute_e(file_path=file_path, hash_alg=hash_alg, q=curve.q)
        v = mod_inv(e, curve.q)
    except (ValueError, OSError):
        return False

    z1 = (s * v) % curve.q
    z2 = (-r * v) % curve.q

    c_point = curve.add(
        curve.scalar_mul(z1, curve.base_point),
        curve.scalar_mul(z2, public_key.q_point),
    )
    if c_point.is_infinity:
        return False

    r_check = c_point.x % curve.q
    return r_check == r

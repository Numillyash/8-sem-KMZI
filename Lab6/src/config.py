from dataclasses import dataclass


@dataclass(frozen=True)
class CurveParams:
    """Elliptic curve parameters in short Weierstrass form."""

    curve_id: str
    p: int
    a: int
    b: int
    q: int
    px: int
    py: int


@dataclass(frozen=True)
class AppConfig:
    """Global configuration for signing and verification."""

    default_curve_id: str
    default_hash_alg: str
    gost_algorithm_id: bytes
    signature_key_label: str


# Вариант 8 из Приложения Д.
# В методичке порядок группы обозначен как r, а в коде мы используем поле q.
# Это один и тот же параметр порядка подгруппы.
VARIANT_8 = CurveParams(
    curve_id="gost3410-2018-var8",
    p=57896044628958718631213028275518411328476149599789770738757218840632915517411,
    a=-1,
    b=44516423948019661825420813927965592341675839270849860441861020678502941837466,
    q=28948022314479359315606514137759205664236832023231628035871193493020981068937,
    px=2323576058601956664720966708045726308916627824741707729836708887517232685058,
    py=20772302011053991390127435262297715010367018383131467831609444907978987653753,
)

CURVE_VARIANTS: dict[str, CurveParams] = {
    VARIANT_8.curve_id: VARIANT_8,
}

APP_CONFIG = AppConfig(
    default_curve_id=VARIANT_8.curve_id,
    default_hash_alg="streebog256",
    gost_algorithm_id=bytes.fromhex("80060700"),
    signature_key_label="gostSignKey",
)

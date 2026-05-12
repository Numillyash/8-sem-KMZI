"""Manual elliptic curve arithmetic for educational purposes.

Implements operations on curves in short Weierstrass form:
    y^2 = x^3 + a*x + b (mod p)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ECPoint:
    """Point on an elliptic curve."""

    x: int = 0
    y: int = 0
    is_infinity: bool = False

    @staticmethod
    def infinity() -> "ECPoint":
        """Return the point at infinity."""
        return ECPoint(is_infinity=True)


def mod_inv(value: int, modulus: int) -> int:
    """Compute modular inverse using the extended Euclidean algorithm."""
    if modulus <= 0:
        raise ValueError("Modulus must be positive")

    value %= modulus
    if value == 0:
        raise ValueError("Inverse does not exist for zero")

    t, new_t = 0, 1
    r, new_r = modulus, value

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r != 1:
        raise ValueError("Inverse does not exist")
    if t < 0:
        t += modulus
    return t


@dataclass(frozen=True)
class EllipticCurve:
    """Elliptic curve with base point and subgroup order."""

    p: int
    a: int
    b: int
    q: int
    base_point: ECPoint
    curve_id: str

    def is_on_curve(self, point: ECPoint) -> bool:
        """Check if point belongs to the curve."""
        if point.is_infinity:
            return True
        left = (point.y * point.y) % self.p
        right = (point.x * point.x * point.x + self.a * point.x + self.b) % self.p
        return left == right

    def negate(self, point: ECPoint) -> ECPoint:
        """Return additive inverse of a point."""
        if point.is_infinity:
            return point
        return ECPoint(point.x, (-point.y) % self.p)

    def add(self, p1: ECPoint, p2: ECPoint) -> ECPoint:
        """Add two points on the curve."""
        if p1.is_infinity:
            return p2
        if p2.is_infinity:
            return p1

        if p1.x == p2.x and (p1.y + p2.y) % self.p == 0:
            return ECPoint.infinity()

        if p1 == p2:
            return self.double(p1)

        numerator = (p2.y - p1.y) % self.p
        denominator = (p2.x - p1.x) % self.p
        lam = (numerator * mod_inv(denominator, self.p)) % self.p

        x3 = (lam * lam - p1.x - p2.x) % self.p
        y3 = (lam * (p1.x - x3) - p1.y) % self.p
        return ECPoint(x3, y3)

    def double(self, point: ECPoint) -> ECPoint:
        """Double a point on the curve."""
        if point.is_infinity:
            return point
        if point.y % self.p == 0:
            return ECPoint.infinity()

        numerator = (3 * point.x * point.x + self.a) % self.p
        denominator = (2 * point.y) % self.p
        lam = (numerator * mod_inv(denominator, self.p)) % self.p

        x3 = (lam * lam - 2 * point.x) % self.p
        y3 = (lam * (point.x - x3) - point.y) % self.p
        return ECPoint(x3, y3)

    def scalar_mul(self, scalar: int, point: ECPoint) -> ECPoint:
        """Multiply point by integer using binary method (double-and-add)."""
        if scalar == 0 or point.is_infinity:
            return ECPoint.infinity()
        if scalar < 0:
            return self.scalar_mul(-scalar, self.negate(point))

        result = ECPoint.infinity()
        addend = point
        k = scalar

        while k > 0:
            if k & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            k >>= 1

        return result

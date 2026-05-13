"""Атака Винера на RSA с малым закрытым показателем."""

from __future__ import annotations

import secrets

from .math_utils import continued_fraction, convergents, gcd, generate_prime, integer_nth_root, mod_inverse
from .rsa_core import PrivateKey, PublicKey


def wiener_attack(n: int, e: int) -> tuple[int, int, int] | None:
    """Вернуть d, p, q, если атака Винера применима, иначе None."""
    # Атака перебирает подходящие дроби цепной дроби e/n. При малом d
    # настоящая дробь k/d появляется среди этих приближений.
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue
        ed_minus_1 = e * d - 1
        if ed_minus_1 % k != 0:
            continue
        # Из e*d - 1 = k*phi(n) получаем кандидата на phi(n).
        phi_candidate = ed_minus_1 // k
        s = n - phi_candidate + 1
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        # p и q являются корнями уравнения x^2 - (p+q)x + n = 0. Поэтому
        # дискриминант должен быть точным квадратом.
        root, exact = integer_nth_root(discriminant, 2)
        if not exact or (s + root) % 2 != 0:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p > 1 and q > 1 and p * q == n:
            return d, min(p, q), max(p, q)
    return None


def generate_wiener_vulnerable_key(bits: int = 512) -> tuple[PrivateKey, PublicKey]:
    """Сгенерировать учебный RSA-ключ с d < n^(1/4)/3."""
    if bits < 64:
        raise ValueError("bits must be at least 64")
    half = bits // 2
    # Ключ специально делается уязвимым для отчета и тестов. Это не безопасная
    # генерация, а контролируемый пример применения атаки Винера.
    while True:
        q = generate_prime(half)
        p = generate_prime(bits - half)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        if not q < p < 2 * q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        bound, _ = integer_nth_root(n, 4)
        # Условие Винера: d должен быть меньше примерно n^(1/4)/3.
        max_d = max(3, bound // 3)
        for _ in range(256):
            d = secrets.randbelow(max_d - 2) + 2
            if gcd(d, phi) != 1:
                continue
            e = mod_inverse(d, phi)
            if e >= n:
                continue
            private = PrivateKey(n=n, e=e, d=d, p=p, q=q)
            public = PublicKey(n=n, e=e)
            if wiener_attack(n, e) is not None:
                return private, public

"""Восстановление закрытого показателя RSA при общем модуле."""

from __future__ import annotations

import secrets

from .math_utils import gcd, mod_inverse


def recover_from_known_private_exponent(
    n: int,
    e_b: int,
    d_b: int,
    e_a: int,
    max_attempts: int = 128,
) -> tuple[int, int, int]:
    """Восстановить p, q и d_a по n, e_b, d_b и другому e_a."""
    # Так как e_b*d_b == 1 mod phi(n), число k = e_b*d_b - 1 кратно phi(n).
    # Это позволяет использовать k как замену неизвестного порядка группы.
    k = e_b * d_b - 1
    if k <= 0:
        raise ValueError("invalid exponent data")

    # Выделяем степень двойки: k = 2^f * s, где s нечетно. Далее возведение
    # случайных оснований в степень s помогает найти квадратный корень из 1.
    f = 0
    s = k
    while s % 2 == 0:
        f += 1
        s //= 2
    if f == 0:
        raise ValueError("e_b*d_b - 1 must be even")

    # Ищем нетривиальный квадратный корень из единицы по модулю n. Для RSA
    # такой корень раскрывает факторизацию n.
    for _ in range(max_attempts):
        a = secrets.randbelow(n - 3) + 2
        b = pow(a, s, n)
        if b in (1, n - 1):
            continue
        t = b
        for _ in range(f):
            next_t = pow(t, 2, n)
            if next_t == 1 and t not in (1, n - 1):
                # Если t^2 == 1 mod n, но t не равен +-1, то gcd(t-1, n) и
                # gcd(t+1, n) дают разные простые множители p и q.
                p = gcd(t + 1, n)
                q = gcd(t - 1, n)
                if p in (1, n) or q in (1, n):
                    break
                if p * q != n:
                    p, q = q, p
                if p * q != n:
                    break
                phi = (p - 1) * (q - 1)
                # После факторизации общего n закрытый показатель для e_a
                # вычисляется обычным обратным элементом по модулю phi(n).
                d_a = mod_inverse(e_a, phi)
                if (e_a * d_a) % phi != 1:
                    raise ValueError("failed to verify recovered d_a")
                return min(p, q), max(p, q), d_a
            t = next_t
            if t == n - 1:
                break

    raise ValueError("failed to factor n within max_attempts")

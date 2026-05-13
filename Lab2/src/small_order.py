"""Демонстрация атаки при малом порядке открытого показателя."""

from __future__ import annotations

from .math_utils import mod_inverse
from .rsa_core import PublicKey, encrypt_int


def recover_small_order_message(
    n: int,
    e: int,
    c: int,
    max_iterations: int = 100_000,
) -> tuple[int, int]:
    """Восстановить m, когда повторное возведение в степень возвращает шифртекст."""
    # Если e имеет малый порядок по модулю phi(n), повторное применение
    # операции RSA-шифрования образует короткий цикл.
    c0 = c
    previous = c0
    current = c0
    for iteration in range(1, max_iterations + 1):
        current = pow(previous, e, n)
        if current == c0:
            # Когда цикл вернулся к исходному шифртексту c0, предыдущий элемент
            # цикла является открытым текстом для учебного примера.
            return previous, iteration
        previous = current
    raise ValueError("cycle was not found within max_iterations")


def generate_small_order_demo() -> dict[str, int]:
    """Вернуть детерминированный малый учебный RSA-пример."""
    # Малые p и q выбраны только для наглядной лабораторной демонстрации.
    # Такие параметры не имеют промышленной криптографической стойкости.
    p = 23
    q = 47
    n = p * q
    phi = (p - 1) * (q - 1)
    # Для выбранного phi показатель e имеет малый порядок, поэтому цикл
    # повторного шифрования быстро раскрывает сообщение.
    e = 45
    d = mod_inverse(e, phi)
    order = 2
    assert pow(e, order, phi) == 1
    message = 123
    public = PublicKey(n=n, e=e)
    c = encrypt_int(message, public)
    recovered, iterations = recover_small_order_message(n, e, c)
    return {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d,
        "m": message,
        "c": c,
        "recovered_m": recovered,
        "iterations": iterations,
        "order": order,
    }

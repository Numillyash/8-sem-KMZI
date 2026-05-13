"""Вспомогательные функции теории чисел для учебных атак на RSA."""

from __future__ import annotations

import math
import secrets
from collections.abc import Iterable, Iterator, Sequence

gcd = math.gcd


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Вернуть gcd(a, b) и коэффициенты Безу x, y."""
    # Расширенный алгоритм Евклида одновременно находит НОД и коэффициенты
    # x, y такие, что a*x + b*y = gcd(a, b). Эти коэффициенты нужны для
    # вычисления обратного элемента по модулю.
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    if old_r < 0:
        return -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Вернуть обратный элемент к a по модулю m."""
    # Обратный элемент существует только при gcd(a, m) = 1. В RSA это условие
    # используется для вычисления закрытого показателя d из e.
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def integer_nth_root(value: int, n: int) -> tuple[int, bool]:
    """Вернуть floor(value ** (1/n)) и признак точного корня."""
    if value < 0:
        raise ValueError("value must be non-negative")
    if n <= 0:
        raise ValueError("n must be positive")
    if value in (0, 1) or n == 1:
        return value, True

    # Двоичный поиск работает только с целыми числами, поэтому не возникает
    # ошибок округления, которые опасны для больших RSA-параметров.
    low, high = 0, 1 << ((value.bit_length() + n - 1) // n)
    while low <= high:
        mid = (low + high) // 2
        power = mid**n
        if power == value:
            return mid, True
        if power < value:
            low = mid + 1
        else:
            high = mid - 1
    return high, False


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    """Вернуть простую цепную дробь для numerator / denominator."""
    # Цепные дроби используются в атаке Винера: малый d проявляется среди
    # знаменателей подходящих дробей разложения e/n.
    if denominator == 0:
        raise ZeroDivisionError("denominator must be non-zero")
    terms: list[int] = []
    while denominator:
        q = numerator // denominator
        terms.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return terms


def convergents(cf: Sequence[int]) -> Iterator[tuple[int, int]]:
    """Порождать числитель и знаменатель подходящих дробей."""
    # Подходящие дроби строятся рекуррентно и дают лучшие рациональные
    # приближения исходной дроби на каждом шаге.
    p_nm2, p_nm1 = 0, 1
    q_nm2, q_nm1 = 1, 0
    for a in cf:
        p = a * p_nm1 + p_nm2
        q = a * q_nm1 + q_nm2
        yield p, q
        p_nm2, p_nm1 = p_nm1, p
        q_nm2, q_nm1 = q_nm1, q


def crt(residues: Sequence[int], moduli: Sequence[int]) -> int:
    """Решить систему x == residue_i (mod modulus_i) для взаимно простых модулей."""
    # Китайская теорема об остатках объединяет несколько сравнений в одно.
    # В широковещательной атаке она восстанавливает целое значение m^e.
    if len(residues) != len(moduli) or not residues:
        raise ValueError("residues and moduli must have equal non-zero length")
    total_modulus = 1
    for modulus in moduli:
        if modulus <= 1:
            raise ValueError("moduli must be greater than one")
        total_modulus *= modulus

    result = 0
    for residue, modulus in zip(residues, moduli):
        partial = total_modulus // modulus
        result += residue * partial * mod_inverse(partial % modulus, modulus)
    return result % total_modulus


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Вероятностный тест Миллера-Рабина с предварительной проверкой малых простых."""
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    # Представляем n-1 как 2^r * d, где d нечетно. Это стандартная форма для
    # раундов Миллера-Рабина.
    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2

    # Тест вероятностный: несколько независимых оснований резко снижают шанс
    # принять составное число за простое. Для лабораторной этого достаточно.
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Сгенерировать вероятно простое число ровно bits бит."""
    if bits < 2:
        raise ValueError("bits must be at least 2")
    # Кандидат принудительно делается нечетным и с установленным старшим битом,
    # чтобы получить число нужной длины.
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

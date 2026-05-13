"""Широковещательная атака Хостада для малого общего RSA-показателя."""

from __future__ import annotations

from collections.abc import Sequence

from .math_utils import crt, gcd, integer_nth_root
from .rsa_core import PublicKey, encrypt_int, generate_keypair


def recover_broadcast_message(e: int, pairs: Sequence[tuple[int, int]]) -> int:
    # Атака требует как минимум e получателей, которым отправлено одно и то же
    # сообщение без padding с одинаковым малым открытым показателем e.
    if len(pairs) < e:
        raise ValueError("at least e ciphertexts are required")
    moduli = [n for n, _ in pairs]
    ciphertexts = [c for _, c in pairs]
    # Модули должны быть попарно взаимно простыми, иначе CRT в этой форме не
    # применима и общий делитель уже сам по себе раскрывает факторизацию.
    for i, n_i in enumerate(moduli):
        for n_j in moduli[i + 1 :]:
            if gcd(n_i, n_j) != 1:
                raise ValueError("moduli must be pairwise coprime")
    # CRT восстанавливает x, сравнимый с m^e по каждому модулю n_i. При
    # условии m^e < product(n_i) это не просто остаток, а само целое m^e.
    x = crt(ciphertexts, moduli)
    # Последний шаг - точное извлечение корня степени e. Если корень не точный,
    # входные данные не соответствуют классической атаке Хостада.
    root, exact = integer_nth_root(x, e)
    if not exact:
        raise ValueError("combined ciphertext is not an exact e-th power")
    return root


def generate_broadcast_demo(
    e: int = 3,
    recipients: int = 3,
    bits: int = 256,
    message_int: int | None = None,
) -> dict[str, object]:
    # Генератор создает учебный набор получателей для отчета: одно сообщение,
    # одинаковый e и разные взаимно простые RSA-модули.
    if recipients < e:
        raise ValueError("recipients must be at least e")
    message = message_int if message_int is not None else int.from_bytes(b"KMZI Lab2", "big")
    public_keys: list[PublicKey] = []
    pairs: list[tuple[int, int]] = []
    product = 1
    seen_moduli: set[int] = set()
    while len(pairs) < recipients:
        private, public = generate_keypair(bits, e)
        if public.n in seen_moduli or message >= public.n:
            continue
        seen_moduli.add(public.n)
        public_keys.append(public)
        pairs.append((public.n, encrypt_int(message, public)))
        product *= public.n
    if message**e >= product:
        raise ValueError("message^e must be smaller than product of moduli")
    return {
        "e": e,
        "message_int": message,
        "pairs": pairs,
        "public_keys": public_keys,
        "recovered_message": recover_broadcast_message(e, pairs),
    }

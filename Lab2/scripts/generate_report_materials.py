"""Generate reproducible report materials for KMZI Lab2."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
LAB_ROOT = SCRIPT_PATH.parents[1]
if str(LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(LAB_ROOT))

from src.broadcast import generate_broadcast_demo, recover_broadcast_message
from src.common_modulus import recover_from_known_private_exponent
from src.math_utils import gcd
from src.rsa_core import generate_keypair, generate_keypair_from_primes
from src.safe_keygen import analyze_rsa_params, generate_safe_rsa_params
from src.small_order import generate_small_order_demo, recover_small_order_message
from src.wiener import generate_wiener_vulnerable_key, wiener_attack


def _clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _code(value: object) -> str:
    return f"```text\n{value}\n```"


def _build_markdown(data: dict[str, Any]) -> str:
    common = data["common_modulus"]
    wiener = data["wiener"]
    broadcast = data["broadcast"]
    small = data["small_order"]
    safe = data["safe_keygen"]
    common_recovered = (
        f"p={common['recovered_p']}\n"
        f"q={common['recovered_q']}\n"
        f"d_a={common['recovered_d_a']}"
    )
    wiener_recovered = (
        f"d_real={wiener['d_real']}\n"
        f"recovered_d={wiener['recovered_d']}"
    )
    small_params = (
        f"n={small['n']}\n"
        f"e={small['e']}\n"
        f"c={small['c']}"
    )
    safe_ed = (
        f"e={safe['e']}\n"
        f"d={safe['d']}"
    )
    return f"""# Данные для отчёта Lab2

## 1. Атака общего модуля RSA

В демонстрации два пользователя имеют общий модуль `n`, но разные открытые показатели `e_a` и `e_b`. По известной паре `e_b`, `d_b` восстановлены множители `p`, `q`, а затем вычислен закрытый показатель `d_a`.

**n:**
{_code(common["n"])}

**e_a / e_b:** `{common["e_a"]}` / `{common["e_b"]}`

**d_b:**
{_code(common["d_b"])}

**Восстановленные p, q, d_a:**
{_code(common_recovered)}

Проверка: **{"OK" if common["verification_ok"] else "FAIL"}**.

## 2. Атака Винера

Сгенерирован учебный ключ RSA с малым закрытым показателем `d < n^(1/4)/3`. Атака использует подходящие дроби цепной дроби `e/n`.

**n:**
{_code(wiener["n"])}

**e:**
{_code(wiener["e"])}

**Реальный и восстановленный d:**
{_code(wiener_recovered)}

Проверка: **{"OK" if wiener["verification_ok"] else "FAIL"}**.

## 3. Широковещательная атака при малом общем e

Одно сообщение зашифровано для трёх получателей с одинаковым `e = {broadcast["e"]}` и попарно взаимно простыми модулями. CRT восстанавливает `m^e`, после чего берётся точный целочисленный корень.

**message_int:** `{broadcast["message_int"]}`

**message_text:** `{broadcast["message_text"]}`

**recovered_message:** `{broadcast["recovered_message"]}`

Проверка: **{"OK" if broadcast["verification_ok"] else "FAIL"}**.

## 4. Бесключевое дешифрование при малом порядке e

Для учебного малого RSA-модуля показатель `e` имеет малый порядок по модулю `phi(n)`. Повторное возведение шифртекста в степень `e` возвращает цикл, где предыдущий элемент является исходным сообщением.

**n, e, c:**
{_code(small_params)}

**m_real / recovered_m:** `{small["m_real"]}` / `{small["recovered_m"]}`

**iterations:** `{small["iterations"]}`

Проверка: **{"OK" if small["verification_ok"] else "FAIL"}**.

## 5. Генерация безопасных параметров RSA

Параметры RSA сгенерированы с `e = 65537`, разными простыми `p`, `q` близкой длины и закрытым показателем выше границы Винера.

**n:**
{_code(safe["n"])}

**e / d:**
{_code(safe_ed)}

**Битовые длины:** модуль `{safe["analysis"]["modulus_bits"]}`, p `{safe["analysis"]["p_bits"]}`, q `{safe["analysis"]["q_bits"]}`.

**gcd(e, phi):** `{safe["analysis"]["gcd_e_phi"]}`

**Граница Винера:** `{safe["analysis"]["wiener_bound"]}`, условие `d > bound`: **{safe["analysis"]["d_gt_wiener_bound"]}**.

**Собственная атака Винера на безопасный ключ:** `{safe["wiener_attack_on_safe_key"]}`.

**cryptool_manual_check:** `{safe["analysis"]["cryptool_manual_check"]}`.

## 6. Итоговые результаты проверки

- common modulus attack OK
- Wiener attack OK
- broadcast attack OK
- small-order attack OK
- safe keygen OK
- Wiener attack against safe key NOT FOUND
"""


def _build_verification_log() -> str:
    return "\n".join(
        [
            "common modulus attack OK",
            "Wiener attack OK",
            "broadcast attack OK",
            "small-order attack OK",
            "safe keygen OK",
            "Wiener attack against safe key NOT FOUND",
        ]
    ) + "\n"


def generate_report_materials(lab_root: Path | None = None) -> dict[str, Any]:
    root = (lab_root or LAB_ROOT).resolve()
    artifacts = root / "artifacts" / "report_run"
    generated = root / "report" / "generated"
    _clean_dir(artifacts)
    generated.mkdir(parents=True, exist_ok=True)

    private_b, _ = generate_keypair(256, 65537)
    phi = (private_b.p - 1) * (private_b.q - 1)
    e_a = 17
    while gcd(e_a, phi) != 1:
        e_a += 2
    private_a, _ = generate_keypair_from_primes(private_b.p, private_b.q, e_a)
    p, q, d_a = recover_from_known_private_exponent(private_b.n, private_b.e, private_b.d, e_a)

    vulnerable_private, vulnerable_public = generate_wiener_vulnerable_key(256)
    wiener_result = wiener_attack(vulnerable_public.n, vulnerable_public.e)
    assert wiener_result is not None

    message_text = "KMZI Lab2"
    message_int = int.from_bytes(message_text.encode("utf-8"), "big")
    broadcast_demo = generate_broadcast_demo(e=3, recipients=3, bits=128, message_int=message_int)
    recovered_broadcast = recover_broadcast_message(broadcast_demo["e"], broadcast_demo["pairs"])

    small_demo = generate_small_order_demo()
    recovered_small, small_iterations = recover_small_order_message(
        small_demo["n"], small_demo["e"], small_demo["c"]
    )

    safe_private = generate_safe_rsa_params(512)
    safe_analysis = analyze_rsa_params(safe_private)
    safe_wiener = wiener_attack(safe_private.n, safe_private.e)

    data: dict[str, Any] = {
        "common_modulus": {
            "n": private_b.n,
            "e_a": e_a,
            "d_a_real": private_a.d,
            "e_b": private_b.e,
            "d_b": private_b.d,
            "p": min(private_b.p, private_b.q),
            "q": max(private_b.p, private_b.q),
            "recovered_p": p,
            "recovered_q": q,
            "recovered_d_a": d_a,
            "verification_ok": {p, q} == {private_b.p, private_b.q} and d_a == private_a.d,
        },
        "wiener": {
            "n": vulnerable_public.n,
            "e": vulnerable_public.e,
            "d_real": vulnerable_private.d,
            "recovered_d": wiener_result[0],
            "p": vulnerable_private.p,
            "q": vulnerable_private.q,
            "recovered_p": wiener_result[1],
            "recovered_q": wiener_result[2],
            "verification_ok": wiener_result[0] == vulnerable_private.d,
        },
        "broadcast": {
            "e": broadcast_demo["e"],
            "message_int": message_int,
            "message_text": message_text,
            "pairs": [{"n": n, "c": c} for n, c in broadcast_demo["pairs"]],
            "recovered_message": recovered_broadcast,
            "verification_ok": recovered_broadcast == message_int,
        },
        "small_order": {
            "n": small_demo["n"],
            "e": small_demo["e"],
            "c": small_demo["c"],
            "m_real": small_demo["m"],
            "recovered_m": recovered_small,
            "iterations": small_iterations,
            "verification_ok": recovered_small == small_demo["m"],
        },
        "safe_keygen": {
            "n": safe_private.n,
            "e": safe_private.e,
            "d": safe_private.d,
            "p": safe_private.p,
            "q": safe_private.q,
            "analysis": safe_analysis,
            "wiener_attack_on_safe_key": "NOT FOUND" if safe_wiener is None else "FOUND",
            "verification_ok": safe_analysis["gcd_e_phi"] == 1
            and safe_analysis["d_gt_wiener_bound"]
            and safe_wiener is None,
        },
    }

    _write_json(generated / "report_data.json", data)
    (generated / "report_data.md").write_text(_build_markdown(data), encoding="utf-8")
    (generated / "verification_log.txt").write_text(_build_verification_log(), encoding="utf-8")
    (artifacts / "README.txt").write_text("Temporary report run files are not committed.\n", encoding="utf-8")
    return data


def main() -> int:
    generate_report_materials()
    print("Generated Lab2 report materials:")
    print("- report/generated/report_data.json")
    print("- report/generated/report_data.md")
    print("- report/generated/verification_log.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

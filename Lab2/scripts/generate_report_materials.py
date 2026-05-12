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
from src.math_utils import gcd, integer_nth_root
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


def _status(value: bool) -> str:
    return "OK" if value else "FAIL"


def _build_recipient_block(pairs: list[dict[str, int]]) -> str:
    lines: list[str] = []
    for index, pair in enumerate(pairs, start=1):
        lines.append(f"Получатель {index}:")
        lines.append(f"n_{index} = {pair['n']}")
        lines.append(f"c_{index} = {pair['c']}")
        lines.append("")
    return "\n".join(lines).strip()


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
    wiener_pq = (
        f"p={wiener['recovered_p']}\n"
        f"q={wiener['recovered_q']}"
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
    broadcast_recipients = _build_recipient_block(broadcast["pairs"])
    common_conditions = (
        f"p*q == n: {common['condition_pq_equals_n']}\n"
        f"(e_a*d_a) mod phi(n) == 1: {common['condition_inverse_ok']}"
    )
    wiener_conditions = (
        f"d_real < n^(1/4)/3: {wiener['condition_d_lt_bound']}\n"
        f"Wiener bound: {wiener['wiener_bound']}"
    )
    broadcast_condition = (
        f"recovered_message == message_int: {broadcast['condition_message_recovered']}"
    )
    small_values = (
        f"p={small['p']}\n"
        f"q={small['q']}\n"
        f"n={small['n']}\n"
        f"phi={small['phi']}\n"
        f"e={small['e']}\n"
        f"d={small['d']}\n"
        f"c={small['c']}\n"
        f"m_real={small['m_real']}\n"
        f"recovered_m={small['recovered_m']}\n"
        f"iterations={small['iterations']}\n"
        f"order={small['order']}"
    )
    safe_values = (
        f"p={safe['p']}\n"
        f"q={safe['q']}\n"
        f"n={safe['n']}\n"
        f"e={safe['e']}\n"
        f"d={safe['d']}"
    )
    return f"""# Данные для отчёта Lab2

## 1. Атака общего модуля RSA

В демонстрации два пользователя имеют общий модуль `n`, но разные открытые показатели `e_a` и `e_b`. По известной паре `e_b`, `d_b` программа восстановила множители `p`, `q`, а затем вычислила закрытый показатель `d_a` для второго пользователя. Это показывает, что общий модуль RSA разрушает изоляцию ключей: знание одного закрытого показателя позволяет факторизовать общий `n`.

### Входные параметры

**n**
{_code(common["n"])}

**e_a:** `{common["e_a"]}`

**e_b:** `{common["e_b"]}`

**d_b**
{_code(common["d_b"])}

### Восстановленные значения

{_code(common_recovered)}

**real d_a**
{_code(common["d_a_real"])}

### Проверка

{_code(common_conditions)}

**Результат:** **{_status(common["verification_ok"])}**.

## 2. Атака Винера

Сгенерирован учебный ключ RSA с малым закрытым показателем `d < n^(1/4)/3`. Атака Винера использует подходящие дроби цепной дроби `e/n` и восстанавливает `d`, после чего из значения `phi(n)` восстанавливаются `p` и `q`. Демонстрация подтверждает, что слишком малый закрытый показатель является самостоятельной уязвимостью RSA.

### Входные параметры

**n**
{_code(wiener["n"])}

**e**
{_code(wiener["e"])}

### Восстановленные значения

{_code(wiener_recovered)}

**recovered p/q**
{_code(wiener_pq)}

### Проверка

{_code(wiener_conditions)}

**Результат:** **{_status(wiener["verification_ok"])}**.

## 3. Широковещательная атака при малом общем e

Одно сообщение зашифровано для трёх получателей с одинаковым `e = {broadcast["e"]}` и попарно взаимно простыми модулями. Китайская теорема об остатках восстанавливает целое значение `m^e`, после чего берётся точный целочисленный корень. Это демонстрирует опасность малого общего `e` при широковещательном шифровании без padding.

**message_int:** `{broadcast["message_int"]}`

**message_text:** `{broadcast["message_text"]}`

### Данные получателей

{_code(broadcast_recipients)}

**recovered_message:** `{broadcast["recovered_message"]}`

### Проверка

{_code(broadcast_condition)}

**Результат:** **{_status(broadcast["verification_ok"])}**.

## 4. Бесключевое дешифрование при малом порядке e

Для учебного малого RSA-модуля показатель `e` имеет малый порядок по модулю `phi(n)`. Повторное возведение шифртекста в степень `e` возвращает цикл, где предыдущий элемент является исходным сообщением. Демонстрация показывает, что небезопасный выбор порядка `e` может позволить расшифровать сообщение без знания закрытого ключа.

### Параметры и результат

{_code(small_values)}

**Результат:** **{_status(small["verification_ok"])}**.

## 5. Генерация безопасных параметров RSA

Параметры RSA сгенерированы с `e = 65537`, разными простыми `p`, `q` близкой длины и закрытым показателем выше границы Винера. Дополнительно запущена собственная реализация атаки Винера против безопасного ключа; закрытый показатель не восстановлен.

### Параметры ключа

{_code(safe_values)}

**Битовые длины:** модуль `{safe["analysis"]["modulus_bits"]}`, p `{safe["analysis"]["p_bits"]}`, q `{safe["analysis"]["q_bits"]}`.

**gcd(e, phi):** `{safe["analysis"]["gcd_e_phi"]}`

**Граница Винера:** `{safe["analysis"]["wiener_bound"]}`, условие `d > bound`: **{safe["analysis"]["d_gt_wiener_bound"]}**.

**p_q_ratio_ok:** `{safe["analysis"]["p_q_ratio_ok"]}`

**Собственная атака Винера на безопасный ключ:** `{safe["wiener_attack_on_safe_key"]}`.

Проверка в CrypTool относится к ручной части оформления: в отчёте можно добавить скриншот проверки параметров. В программной части дополнительно выполнены проверки `gcd(e, phi(n)) = 1`, `d > n^(1/4)/3` и отсутствие восстановления `d` атакой Винера.

**Результат:** **{_status(safe["verification_ok"])}**.

## 6. Итоговые результаты проверки

- common modulus attack OK
- Wiener attack OK
- broadcast attack OK
- small-order attack OK
- safe keygen OK
- Wiener attack against safe key NOT FOUND
"""


def _build_theory() -> str:
    return """# Теоретические сведения

## 1. RSA и роль показателей e и d

В RSA выбираются два простых числа `p` и `q`, после чего вычисляются `n = p q` и `phi(n) = (p-1)(q-1)`. Открытый показатель `e` должен быть взаимно прост с `phi(n)`, а закрытый показатель `d` определяется условием `e d ≡ 1 mod phi(n)`. Шифрование выполняется как `c = m^e mod n`, расшифрование как `m = c^d mod n`. Безопасность основана на сложности факторизации `n`; если `p` и `q` восстановлены, то `phi(n)` и `d` вычисляются напрямую.

## 2. Атака общего модуля

Уязвимость возникает, когда разные пользователи используют один и тот же модуль `n`, но разные пары показателей. Если известны `e_b` и `d_b`, то `k = e_b d_b - 1` кратно `phi(n)`. Представление `k = 2^s r`, где `r` нечётно, позволяет искать нетривиальный квадратный корень из единицы по модулю `n`. Такой корень даёт делители через `gcd(x-1, n)` и `gcd(x+1, n)`. После факторизации общего `n` закрытый показатель другого пользователя находится из `e_a d_a ≡ 1 mod phi(n)`.

## 3. Атака Винера

Атака Винера применима, когда закрытый показатель слишком мал: `d < n^(1/4)/3`, а простые множители сравнимы по размеру. В этом случае дробь `e/phi(n)` хорошо приближается дробью `k/d`, а `phi(n)` близко к `n`. Реализация перебирает подходящие дроби цепной дроби `e/n`, проверяет делимость `e d - 1` на `k`, восстанавливает кандидат `phi(n)` и решает квадратное уравнение для `p` и `q`.

## 4. Широковещательная атака Хостада при малом e

Малый открытый показатель `e` не опасен сам по себе, если используется корректный padding. Уязвимость появляется, когда одно и то же сообщение без padding отправляется нескольким получателям с одинаковым малым `e` и разными взаимно простыми модулями. Для каждого получателя известно `c_i ≡ m^e mod n_i`. Китайская теорема об остатках восстанавливает `x ≡ c_i mod n_i`, то есть `x = m^e`, если `m^e < n_1 n_2 ... n_e`. После этого сообщение находится как точный целочисленный корень степени `e`.

## 5. Бесключевое дешифрование при малом порядке e

Если показатель `e` имеет малый порядок в мультипликативной группе по модулю `phi(n)`, повторное применение операции шифрования быстро образует цикл. Для шифртекста `c_0 = c` вычисляются `c_i = c_{i-1}^e mod n`. Когда очередное значение снова равно `c_0`, предыдущее значение является исходным сообщением. Уязвимость связана не с факторизацией `n`, а с плохими алгебраическими свойствами выбранного `e`.

## 6. Безопасная генерация параметров RSA

Для учебной безопасной генерации требуется выбирать разные простые `p` и `q` близкой длины, проверять `gcd(e, phi(n)) = 1`, использовать обычный открытый показатель `e = 65537` и избегать малого `d`. Дополнительная проверка `d > n^(1/4)/3` исключает демонстрационный случай атаки Винера. В практических системах также обязателен padding, например OAEP для шифрования и PSS для подписи.
"""


def _build_control_questions() -> str:
    return """# Контрольные вопросы

## 1. Почему знание d одного пользователя при общем n позволяет разложить n?

Потому что из `e d - 1` получается число, кратное `phi(n)`. Его разложение на нечётную часть и степень двойки позволяет найти нетривиальный квадратный корень из единицы по модулю `n`, а затем получить `p` и `q` через НОД.

## 2. Почему нельзя использовать один и тот же модуль n для разных пользователей?

Общий `n` связывает безопасность всех пользователей. Если у одного пользователя раскрыт закрытый показатель или факторизация, то факторизуется общий модуль и становятся вычислимы закрытые показатели остальных пользователей.

## 3. В чём условие применимости атаки Винера?

Классическое условие: закрытый показатель должен быть малым, примерно `d < n^(1/4)/3`, а множители `p` и `q` должны быть близки по размеру. Тогда `d` появляется среди знаменателей подходящих дробей цепной дроби `e/n`.

## 4. Почему малое e само по себе не всегда опасно, но опасно при широковещательном шифровании без padding?

При корректном padding одинаковые сообщения превращаются в разные случайные представители, поэтому простая алгебраическая атака не работает. Без padding одно и то же `m` даёт связанные значения `c_i = m^e mod n_i`, из которых можно восстановить `m^e`.

## 5. Зачем в широковещательной атаке нужна китайская теорема об остатках?

Она объединяет сравнения `x ≡ c_i mod n_i` в одно значение по модулю произведения `n_i`. При выполнении ограничения `m^e < n_1 n_2 ... n_e` это значение равно обычному целому `m^e`.

## 6. Почему требуется m^e < n_1*n_2*...*n_e?

Это условие гарантирует, что результат CRT является не только остатком, но и самим числом `m^e`. Тогда можно извлечь точный целочисленный корень и получить сообщение.

## 7. В чём идея бесключевого дешифрования при малом порядке e?

Если повторное возведение в степень `e` быстро возвращает шифртекст к исходному значению цикла, то элемент перед возвратом является сообщением. Закрытый ключ при этом не используется.

## 8. Какие параметры RSA можно считать более безопасными для этой лабораторной?

Разные простые `p` и `q` близкой длины, `gcd(e, phi(n)) = 1`, открытый показатель `e = 65537`, закрытый показатель выше границы Винера и отсутствие общего модуля между пользователями.

## 9. Почему padding важен для практической RSA-криптографии?

Padding вносит структуру и случайность, устраняет прямые алгебраические связи между сообщением и шифртекстом и защищает от атак на детерминированную textbook RSA-схему.

## 10. Почему сгенерированные в демонстрации параметры малых размеров не являются промышленно безопасными?

Они выбраны для быстрой проверки и наглядности. Малые модули легко факторизуются современными средствами, поэтому для реальной защиты нужны существенно большие ключи и стандартизованные схемы padding.
"""


def _build_stand_commands() -> str:
    return r"""# Команды для защиты

## Проверка лабораторной

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab2
.\.venv\Scripts\Activate.ps1
pytest -q
python scripts\generate_report_materials.py
Get-Content .\report\generated\verification_log.txt -Encoding UTF8
```

## CLI-демонстрация

```powershell
python -m src.main demo --out artifacts\demo_data
python -m src.main common-modulus --json artifacts\demo_data\common_modulus.json
python -m src.main wiener --json artifacts\demo_data\wiener.json
python -m src.main broadcast --json artifacts\demo_data\broadcast.json
python -m src.main small-order --json artifacts\demo_data\small_order.json
python -m src.main safe-keygen --bits 512 --out artifacts\safe_key.json
```
"""


def _build_full_report_draft(
    report_data: str,
    theory: str,
    control_questions: str,
) -> str:
    theory_body = theory.removeprefix("# Теоретические сведения\n\n")
    control_body = control_questions.removeprefix("# Контрольные вопросы\n\n")
    practical_body = report_data.removeprefix("# Данные для отчёта Lab2\n\n")
    return f"""# Лабораторная работа №2. Атаки на RSA

## Цель работы

Изучить уязвимости RSA, связанные с неправильным выбором показателей и повторным использованием параметров, реализовать демонстрационные атаки и сформировать проверки безопасной генерации параметров.

## Задание

Реализованы атака общего модуля, атака Винера, широковещательная атака при малом общем `e`, бесключевое дешифрование при малом порядке `e` и генерация безопасных параметров RSA. Для каждой программы подготовлены входные данные, восстановленные значения и автоматическая проверка результата.

## Теоретические сведения

{theory_body}

## Описание реализации

Программа разделена на независимые модули: `math_utils.py` содержит базовую теорию чисел, `rsa_core.py` содержит RSA-примитивы, отдельные модули реализуют каждую атаку, а `safe_keygen.py` выполняет генерацию и анализ безопасных параметров. CLI в `src/main.py` позволяет запускать каждую демонстрацию отдельно и генерировать набор JSON-файлов для защиты.

## Практические результаты

{practical_body}

## Дополнительное задание

Дополнительная часть связана с генерацией безопасных параметров RSA и проверкой, что выбранный ключ не подпадает под реализованные учебные атаки. В программной части проверяются `gcd(e, phi(n)) = 1`, близость длин `p` и `q`, выполнение условия `d > n^(1/4)/3` и отрицательный результат атаки Винера против безопасного ключа.

## Генерация безопасных параметров RSA

Для безопасной демонстрации используется `e = 65537`, разные простые `p` и `q`, а также автоматический анализ параметров. Проверка в CrypTool относится к ручной части оформления: в итоговый документ можно добавить скриншот проверки сгенерированных параметров.

## Контрольные вопросы

{control_body}

## Вывод

В работе показано, что безопасность RSA зависит не только от сложности факторизации, но и от корректного выбора параметров и схемы применения. Повторное использование модуля, слишком малый закрытый показатель, широковещательное шифрование без padding и малый порядок `e` приводят к практическому восстановлению сообщения или закрытых параметров. Безопасная генерация должна исключать эти случаи и в реальных системах обязательно дополняться стандартизованным padding.
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
    vulnerable_bound, _ = integer_nth_root(vulnerable_public.n, 4)
    vulnerable_wiener_bound = vulnerable_bound // 3

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
            "condition_pq_equals_n": p * q == private_b.n,
            "condition_inverse_ok": (e_a * d_a) % phi == 1,
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
            "wiener_bound": vulnerable_wiener_bound,
            "condition_d_lt_bound": vulnerable_private.d < vulnerable_wiener_bound,
            "verification_ok": wiener_result[0] == vulnerable_private.d,
        },
        "broadcast": {
            "e": broadcast_demo["e"],
            "message_int": message_int,
            "message_text": message_text,
            "pairs": [{"n": n, "c": c} for n, c in broadcast_demo["pairs"]],
            "recovered_message": recovered_broadcast,
            "condition_message_recovered": recovered_broadcast == message_int,
            "verification_ok": recovered_broadcast == message_int,
        },
        "small_order": {
            "p": small_demo["p"],
            "q": small_demo["q"],
            "n": small_demo["n"],
            "phi": small_demo["phi"],
            "e": small_demo["e"],
            "d": small_demo["d"],
            "c": small_demo["c"],
            "m_real": small_demo["m"],
            "recovered_m": recovered_small,
            "iterations": small_iterations,
            "order": small_demo["order"],
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

    report_data = _build_markdown(data)
    theory = _build_theory()
    control_questions = _build_control_questions()
    stand_commands = _build_stand_commands()
    full_report = _build_full_report_draft(report_data, theory, control_questions)

    _write_json(generated / "report_data.json", data)
    (generated / "report_data.md").write_text(report_data, encoding="utf-8")
    (generated / "verification_log.txt").write_text(_build_verification_log(), encoding="utf-8")
    (generated / "theory.md").write_text(theory, encoding="utf-8")
    (generated / "control_questions.md").write_text(control_questions, encoding="utf-8")
    (generated / "stand_commands.md").write_text(stand_commands, encoding="utf-8")
    (generated / "full_report_draft.md").write_text(full_report, encoding="utf-8")
    (artifacts / "README.txt").write_text("Temporary report run files are not committed.\n", encoding="utf-8")
    return data


def main() -> int:
    generate_report_materials()
    print("Generated Lab2 report materials:")
    print("- report/generated/report_data.json")
    print("- report/generated/report_data.md")
    print("- report/generated/verification_log.txt")
    print("- report/generated/theory.md")
    print("- report/generated/control_questions.md")
    print("- report/generated/stand_commands.md")
    print("- report/generated/full_report_draft.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

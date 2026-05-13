"""Generate report materials for Lab6.

Run from Lab6:
    python scripts/generate_report_materials.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

LAB6_DIR = Path(__file__).resolve().parents[1]
if str(LAB6_DIR) not in sys.path:
    sys.path.insert(0, str(LAB6_DIR))

from src.config import APP_CONFIG, VARIANT_8
from src.ecc import ECPoint, EllipticCurve
from src.hashing import hash_file, hash_to_alpha
from src.sigfile import SignaturePayload, load_signature, save_signature
from src.sign import sign_file, verify_file

REPORT_FILES = [
    "report_data.md",
    "report_data.json",
    "verification_log.txt",
    "hex_dump.md",
    "theory.md",
    "control_questions.md",
    "stand_commands.md",
    "full_report_draft.md",
]

DEMO_PRIVATE_D = 123456789
DEMO_K = 987654321
DEMO_MESSAGE = (
    "Лабораторная работа 6. ГОСТ Р 34.10-2018.\n"
    "Демонстрационное сообщение для подписи, вариант 8.\n"
)


def _curve() -> EllipticCurve:
    return EllipticCurve(
        p=VARIANT_8.p,
        a=VARIANT_8.a,
        b=VARIANT_8.b,
        q=VARIANT_8.q,
        base_point=ECPoint(VARIANT_8.px, VARIANT_8.py),
        curve_id=VARIANT_8.curve_id,
    )


def _write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _hex_preview(data: bytes, length: int = 96) -> str:
    return data[:length].hex(" ")


def _hex_lines(data: bytes, width: int = 16, limit: int | None = None) -> str:
    blob = data if limit is None else data[:limit]
    lines = []
    for offset in range(0, len(blob), width):
        chunk = blob[offset : offset + width]
        lines.append(f"{offset:04x}: {chunk.hex(' ')}")
    return "\n".join(lines)


def _signature_fields(payload: SignaturePayload) -> dict[str, object]:
    return {
        "algorithm_id_hex": APP_CONFIG.gost_algorithm_id.hex(" "),
        "key_label": APP_CONFIG.signature_key_label,
        "hash_alg": payload.hash_alg,
        "curve_id": payload.curve_id,
        "Q.x": payload.qx,
        "Q.y": payload.qy,
        "p": payload.p,
        "a": payload.a,
        "b": payload.b,
        "P.x": payload.px,
        "P.y": payload.py,
        "q": payload.q,
        "r": payload.r,
        "s": payload.s,
        "file_params": "empty SEQUENCE",
    }


def _make_keys(run_dir: Path) -> tuple[Path, Path, dict[str, object], dict[str, object]]:
    curve = _curve()
    q_point = curve.scalar_mul(DEMO_PRIVATE_D, curve.base_point)
    if q_point.is_infinity:
        raise ValueError("Derived public key Q is infinity")

    private_key = {
        "curve_id": VARIANT_8.curve_id,
        "p": VARIANT_8.p,
        "a": VARIANT_8.a,
        "b": VARIANT_8.b,
        "q": VARIANT_8.q,
        "P": {"x": VARIANT_8.px, "y": VARIANT_8.py},
        "d": DEMO_PRIVATE_D,
    }
    public_key = {
        "curve_id": VARIANT_8.curve_id,
        "p": VARIANT_8.p,
        "a": VARIANT_8.a,
        "b": VARIANT_8.b,
        "q": VARIANT_8.q,
        "P": {"x": VARIANT_8.px, "y": VARIANT_8.py},
        "Q": {"x": q_point.x, "y": q_point.y},
    }

    private_key_path = run_dir / "private_demo.json"
    public_key_path = run_dir / "public_demo.json"
    _write_json(private_key_path, private_key)
    _write_json(public_key_path, public_key)
    return private_key_path, public_key_path, private_key, public_key


def _write_report_data_md(path: Path, data: dict[str, object]) -> None:
    fields = data["asn1_fields"]
    assert isinstance(fields, dict)
    content = f"""# ЛР6. ГОСТ Р 34.10-2018: электронная цифровая подпись

## Используемые параметры

- Вариант кривой: variant 8 ({data["curve_id"]})
- p = {data["p"]}
- a = {data["a"]}
- b = {data["b"]}
- q = {data["q"]}
- P.x = {data["px"]}
- P.y = {data["py"]}

## Ключи

- Закрытый ключ d = {data["private_d"]}
- Открытый ключ Q = dP
- Q.x = {data["qx"]}
- Q.y = {data["qy"]}

## Сообщение и хэш

Текст сообщения:

```text
{data["message_text"]}
```

Первые байты исходного файла:

```text
{data["message_first_bytes_hex"]}
```

- Streebog-256 digest hex = {data["digest_hex"]}
- alpha = int(hash) = {data["alpha"]}
- e = alpha mod q = {data["e"]}

## Подпись

- r = {data["r"]}
- s = {data["s"]}

Первые 96 байт файла подписи:

```text
{data["signature_first_bytes_hex"]}
```

## Поля ASN.1 DER контейнера

| Поле | Значение |
| --- | --- |
"""
    for key, value in fields.items():
        content += f"| {key} | {value} |\n"

    content += f"""
## Результаты проверки

- Исходное сообщение: {data["verify_original"]}
- Изменённое сообщение: {data["verify_modified"]}
- Испорченная подпись: {data["verify_corrupted"]}
"""
    path.write_text(content, encoding="utf-8")


def _write_theory(path: Path) -> None:
    path.write_text(
        """# Теоретические сведения

Эллиптическая кривая над конечным полем F_p задаётся уравнением y^2 = x^3 + ax + b (mod p). Все вычисления координат выполняются по модулю простого числа p, поэтому множество точек конечно.

Точка на бесконечности является нейтральным элементом группы точек кривой. При сложении любой точки P с точкой на бесконечности получается P.

Сложение двух разных точек выполняется через наклон прямой, проходящей через эти точки. Удвоение точки использует касательную к кривой. После вычисления наклона координаты результата приводятся по модулю p.

Скалярное умножение kP означает многократное сложение точки P самой с собой. На практике используется двоичный метод double-and-add: скаляр разбирается по битам, а точка последовательно удваивается.

Закрытый ключ d выбирается как число 0 < d < q. Открытый ключ вычисляется как Q = dP, где P - базовая точка подгруппы порядка q.

Перед подписью сообщение хэшируется алгоритмом Стрибог. В данной работе используется Streebog-256, а значение хэша интерпретируется как целое число alpha.

Формирование подписи ГОСТ Р 34.10-2018:

1. alpha = H(M).
2. e = alpha mod q; если e = 0, то e = 1.
3. Выбирается случайное число k, 0 < k < q.
4. C = kP.
5. r = x_C mod q.
6. s = (r*d + k*e) mod q.

Если r или s равны нулю, выбирается новое k.

Проверка подписи:

1. v = e^-1 mod q.
2. z1 = s*v mod q.
3. z2 = -r*v mod q.
4. C = z1*P + z2*Q.
5. R = x_C mod q.
6. Подпись считается верной тогда и только тогда, когда R == r.

ASN.1 DER контейнер подписи построен по структуре из приложения Г: внешний SEQUENCE содержит SET с параметрами алгоритма, меткой ключа, открытым ключом Q, параметрами кривой, парой подписи r и s, а также пустой SEQUENCE параметров файла.

Ограничения учебной реализации: код предназначен для демонстрации алгоритма, использует ручную арифметику эллиптических кривых, не реализует промышленную защиту от побочных каналов, не выполняет сертифицированное управление ключами и не должен использоваться для реальной криптографической защиты.
""",
        encoding="utf-8",
    )


def _write_control_questions(path: Path) -> None:
    path.write_text(
        """# Контрольные вопросы

## 1. Преимущества криптосистем на эллиптических кривых по сравнению с другими криптосистемами

Эллиптические кривые дают сопоставимый уровень стойкости при меньшей длине ключа. Это уменьшает объём хранимых и передаваемых данных, ускоряет операции и удобно для систем с ограниченными ресурсами.

## 2. Почему в ГОСТ Р 34.10-2018 требуется #E(F_p) != p

Если число точек кривой равно характеристике поля p, кривая является аномальной. Для таких кривых существуют специальные атаки, сводящие задачу дискретного логарифмирования на кривой к более простой задаче в поле. Поэтому стандарт исключает этот небезопасный случай.

## 3. Как злоумышленник мог бы подделать сообщение и подпись, если умеет обращать хэш-функцию

Если можно подобрать сообщение с заданным значением хэша, злоумышленник может взять уже подписанный хэш или сконструировать нужное значение alpha, а затем найти другое сообщение с тем же или требуемым хэшем. Проверка подписи работает с H(M), поэтому такое сообщение будет принято как подписанное.

## 4. Почему случайное k не должно повторяться в течение срока жизни ключа подписи

При повторном использовании k в двух подписях появляется связь между значениями s, r, хэшами сообщений и закрытым ключом d. Из этой системы сравнений можно восстановить k, а затем вычислить d. Поэтому k должно быть уникальным и непредсказуемым для каждой подписи.
""",
        encoding="utf-8",
    )


def _write_stand_commands(path: Path) -> None:
    path.write_text(
        r"""# Команды для защиты

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab6
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q

python scripts\generate_report_materials.py

python -m src.main sign `
  --file artifacts\report_run\message.txt `
  --private-key artifacts\report_run\private_demo.json `
  --signature artifacts\report_run\message.sig `
  --hash-alg streebog256

python -m src.main verify `
  --file artifacts\report_run\message.txt `
  --signature artifacts\report_run\message.sig `
  --public-key artifacts\report_run\public_demo.json

Set-Content artifacts\report_run\message_modified.txt `
  -Value "Лабораторная работа 6. Изменённое сообщение." `
  -Encoding UTF8

python -m src.main verify `
  --file artifacts\report_run\message_modified.txt `
  --signature artifacts\report_run\message.sig `
  --public-key artifacts\report_run\public_demo.json

python -m src.main verify `
  --file artifacts\report_run\message.txt `
  --signature artifacts\report_run\message_corrupted.sig `
  --public-key artifacts\report_run\public_demo.json

Format-Hex artifacts\report_run\message.sig -Count 96
```
""",
        encoding="utf-8",
    )


def _write_full_report(path: Path, data: dict[str, object], verification_log: str) -> None:
    path.write_text(
        f"""# Лабораторная работа 6. ГОСТ Р 34.10-2018

## Цель

Изучить формирование и проверку электронной цифровой подписи ГОСТ Р 34.10-2018 на эллиптических кривых и подготовить ASN.1 DER контейнер подписи.

## Задачи

1. Реализовать работу с параметрами кривой варианта 8.
2. Сформировать закрытый и открытый ключи.
3. Подписать сообщение с использованием Streebog-256.
4. Проверить корректную подпись и показать отказ при изменении сообщения или подписи.
5. Разобрать поля ASN.1 DER контейнера.

## Теория

См. файл `theory.md`.

## Описание реализации

Реализация разделена на модули: `config.py` хранит параметры варианта 8, `ecc.py` выполняет арифметику точек, `hashing.py` вычисляет Стрибог, `sigfile.py` кодирует и декодирует ASN.1 DER контейнер, `sign.py` реализует подпись и проверку, `main.py` предоставляет CLI.

## Практические результаты

- Закрытый ключ d = {data["private_d"]}
- Открытый ключ Q.x = {data["qx"]}
- Открытый ключ Q.y = {data["qy"]}
- Хэш Streebog-256 = {data["digest_hex"]}
- r = {data["r"]}
- s = {data["s"]}
- Исходное сообщение: {data["verify_original"]}
- Изменённое сообщение: {data["verify_modified"]}
- Испорченная подпись: {data["verify_corrupted"]}

## ASN.1 контейнер подписи

Контейнер содержит идентификатор алгоритма, метку ключа, открытый ключ Q, параметры кривой p, a, b, P.x, P.y, q и значения подписи r, s.

Первые байты:

```text
{data["signature_first_bytes_hex"]}
```

## Журнал проверки

```text
{verification_log}
```

## Контрольные вопросы

См. файл `control_questions.md`.

## Выводы

В ходе работы получена подпись ГОСТ Р 34.10-2018 для сообщения, подтверждена корректность проверки исходного файла и отказ проверки при изменении сообщения или значения подписи. ASN.1 DER контейнер разобран на поля, необходимые для отчёта.

## Приложения

- `report_data.md`
- `report_data.json`
- `verification_log.txt`
- `hex_dump.md`
- `theory.md`
- `control_questions.md`
- `stand_commands.md`
""",
        encoding="utf-8",
    )


def generate(lab6_dir: Path = LAB6_DIR) -> dict[str, object]:
    report_dir = lab6_dir / "report" / "generated"
    run_dir = lab6_dir / "artifacts" / "report_run"
    report_dir.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)

    message_path = run_dir / "message.txt"
    modified_message_path = run_dir / "message_modified.txt"
    signature_path = run_dir / "message.sig"
    corrupted_signature_path = run_dir / "message_corrupted.sig"

    message_path.write_text(DEMO_MESSAGE, encoding="utf-8")
    modified_message_path.write_text(DEMO_MESSAGE + "Изменение.\n", encoding="utf-8")

    private_key_path, public_key_path, private_key, public_key = _make_keys(run_dir)
    with patch("src.sign.secrets.randbelow", return_value=DEMO_K - 1):
        payload = sign_file(
            file_path=message_path,
            private_key_path=private_key_path,
            signature_path=signature_path,
            hash_alg="streebog256",
        )

    parsed_payload = load_signature(signature_path)
    bad_s = parsed_payload.s + 1
    if bad_s >= parsed_payload.q:
        bad_s = 1
    save_signature(
        corrupted_signature_path,
        SignaturePayload(
            hash_alg=parsed_payload.hash_alg,
            curve_id=parsed_payload.curve_id,
            qx=parsed_payload.qx,
            qy=parsed_payload.qy,
            p=parsed_payload.p,
            a=parsed_payload.a,
            b=parsed_payload.b,
            px=parsed_payload.px,
            py=parsed_payload.py,
            q=parsed_payload.q,
            r=parsed_payload.r,
            s=bad_s,
        ),
    )

    original_valid = verify_file(message_path, signature_path, public_key_path)
    modified_valid = verify_file(modified_message_path, signature_path, public_key_path)
    corrupted_valid = verify_file(message_path, corrupted_signature_path, public_key_path)

    digest = hash_file(message_path, "streebog256")
    alpha = hash_to_alpha(message_path, "streebog256")
    e = alpha % VARIANT_8.q
    if e == 0:
        e = 1
    signature_bytes = signature_path.read_bytes()
    message_bytes = message_path.read_bytes()

    q_raw = public_key["Q"]
    assert isinstance(q_raw, dict)
    data: dict[str, object] = {
        "lab_title": "ЛР6. ГОСТ Р 34.10-2018: электронная цифровая подпись",
        "curve_variant": "variant 8",
        "curve_id": VARIANT_8.curve_id,
        "p": VARIANT_8.p,
        "a": VARIANT_8.a,
        "b": VARIANT_8.b,
        "q": VARIANT_8.q,
        "px": VARIANT_8.px,
        "py": VARIANT_8.py,
        "private_d": private_key["d"],
        "qx": q_raw["x"],
        "qy": q_raw["y"],
        "message_text": DEMO_MESSAGE,
        "message_first_bytes_hex": _hex_preview(message_bytes, 64),
        "digest_hex": digest.hex(),
        "alpha": alpha,
        "e": e,
        "r": payload.r,
        "s": payload.s,
        "signature_first_bytes_hex": _hex_preview(signature_bytes, 96),
        "asn1_fields": _signature_fields(parsed_payload),
        "verify_original": "VALID" if original_valid else "INVALID",
        "verify_modified": "VALID" if modified_valid else "INVALID",
        "verify_corrupted": "VALID" if corrupted_valid else "INVALID",
        "paths": {
            "message": str(message_path),
            "modified_message": str(modified_message_path),
            "private_key": str(private_key_path),
            "public_key": str(public_key_path),
            "signature": str(signature_path),
            "corrupted_signature": str(corrupted_signature_path),
        },
    }

    verification_log = "\n".join(
        [
            "Verification log",
            f"original message: {'VALID' if original_valid else 'INVALID'}",
            f"modified message: {'VALID' if modified_valid else 'INVALID'}",
            f"corrupted signature: {'VALID' if corrupted_valid else 'INVALID'}",
            "",
        ]
    )

    _write_report_data_md(report_dir / "report_data.md", data)
    _write_json(report_dir / "report_data.json", data)
    (report_dir / "verification_log.txt").write_text(verification_log, encoding="utf-8")
    (report_dir / "hex_dump.md").write_text(
        "# Hex dump подписи\n\n"
        "Первые 96 байт ASN.1 DER контейнера:\n\n"
        "```text\n"
        f"{_hex_lines(signature_bytes, limit=96)}\n"
        "```\n",
        encoding="utf-8",
    )
    _write_theory(report_dir / "theory.md")
    _write_control_questions(report_dir / "control_questions.md")
    _write_stand_commands(report_dir / "stand_commands.md")
    _write_full_report(report_dir / "full_report_draft.md", data, verification_log)
    return data


def main() -> int:
    generate()
    print("Generated Lab6 report materials:")
    for name in REPORT_FILES:
        print(f"  report/generated/{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

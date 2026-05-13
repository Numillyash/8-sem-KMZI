"""Генерация воспроизводимых материалов для отчета по KMZI Lab1.

Скрипт использует только существующую реализацию Lab1 и стандартную библиотеку.
Случайные RSA/AES значения могут меняться при каждом запуске, но структура
выходных Markdown/JSON/TXT файлов остается одинаковой.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
DEFAULT_LAB_ROOT = SCRIPT_PATH.parents[1]
if str(DEFAULT_LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(DEFAULT_LAB_ROOT))

from src.crcforge import crc32_bytes, forge_crc32_file
from src.hybrid import decrypt_file, encrypt_file
from src.rsa import generate_keypair, save_private_key, save_public_key
from src.signatures import (
    create_crc32_container,
    create_sha256_container,
    load_signature_container,
    save_signature,
    verify_crc32_container,
    verify_sha256_container,
)


REPORT_FILES = (
    "report_data.md",
    "report_data.json",
    "verification_log.txt",
    "hex_dump.md",
    "crc32_demo.md",
    "theory.md",
    "control_questions.md",
    "stand_commands.md",
    "full_report_draft.md",
)


def _clean_dir(path: Path) -> None:
    # artifacts/report_run хранит временные ключи, подписи и шифртексты одного запуска.
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def _hex_block(value: str, width: int = 64) -> str:
    return "\n".join(value[i : i + width] for i in range(0, len(value), width))


def _code_block(value: int | str) -> str:
    return f"```text\n{value}\n```"


def _status(value: bool) -> str:
    return "VALID" if value else "INVALID"


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _build_report_markdown(data: dict[str, Any]) -> str:
    rsa = data["rsa"]
    aes = data["aes"]
    files = data["files"]
    sha = data["sha256_signature"]
    crc = data["crc32_signature"]

    return f"""# Данные для отчета по Lab1

## 1. Параметры RSA

Размер модуля RSA: **{rsa["modulus_bit_length"]} бит**.

**p:**
{_code_block(rsa["p"])}

**q:**
{_code_block(rsa["q"])}

**n = p * q:**
{_code_block(rsa["n"])}

**e:**
{_code_block(rsa["e"])}

**d:**
{_code_block(rsa["d"])}

## 2. Гибридное шифрование RSA + AES-256-CBC

Исходный файл `data/message.txt` был зашифрован по гибридной схеме: содержимое файла шифруется AES-256-CBC, а 32-байтный AES-ключ шифруется RSA.

**AES-256 ключ, hex:**
```text
{_hex_block(aes["aes_key_hex"])}
```

**IV, hex:**
```text
{aes["iv_hex"]}
```

**Зашифрованный AES-ключ, hex:**
```text
{_hex_block(aes["encrypted_key_hex"])}
```

Размер исходного файла: **{files["original_message_size"]} байт**.
Размер DER-контейнера: **{files["encrypted_container_size"]} байт**.

**Первые 100 байт DER-контейнера, hex:**
```text
{_hex_block(files["container_first_100_hex"])}
```

**Первые 100 байт AES ciphertext, hex:**
```text
{_hex_block(files["ciphertext_first_100_hex"])}
```

## 3. Расшифрование

- DER-контейнер разобран: **OK**
- AES-ключ расшифрован закрытым RSA-ключом: **OK**
- Содержимое файла восстановлено AES-256-CBC: **OK**

Результат сравнения расшифрованного файла с исходным: **{"OK" if files["decrypted_equals_original"] else "FAIL"}**.

## 4. Электронная подпись RSA/SHA-256

Подпись вычислялась по формуле `s = h(file)^d mod n`, где `h(file)` - SHA-256 как целое число, приведенное по модулю `n`.

**SHA-256 digest, hex:**
```text
{sha["digest_hex"]}
```

**h_sha256_mod_n:**
{_code_block(sha["h_sha256_mod_n"])}

**Подпись RSA/SHA-256:**
{_code_block(sha["signature_integer"])}

Подпись хранится в ASN.1 DER-контейнере `SignatureFile`.

**DER RSA/SHA-256, first 100 bytes, hex:**
```text
{_hex_block(sha["signature_der_first_100_hex"])}
```

Проверка исходного файла: **{sha["original_verification"]}**.
Проверка измененного файла: **{sha["modified_verification"]}**.

При проверке подписи хэш файла вычисляется заново, затем проверяется равенство `signature^e mod n == SHA-256(file) mod n`. Значение `hashValue` в контейнере используется как сохраненная диагностическая информация, но корректность подписи определяется пересчетом данных.

## 5. Дополнительное задание: RSA/CRC32

Для дополнительного задания вместо SHA-256 используется CRC32, после чего значение CRC32 подписывается RSA.

CRC32(D1): **{crc["d1_crc32_hex"]}** / **{crc["d1_crc32_decimal"]}**.
CRC32(D2): **{crc["d2_crc32_hex"]}** / **{crc["d2_crc32_decimal"]}**.
CRC32(D3): **{crc["d3_crc32_hex"]}** / **{crc["d3_crc32_decimal"]}**.

**Подпись RSA/CRC32 для D1:**
{_code_block(crc["signature_integer"])}

Подпись RSA/CRC32 хранится в ASN.1 DER-контейнере `SignatureFile`.

**DER RSA/CRC32, first 100 bytes, hex:**
```text
{_hex_block(crc["signature_der_first_100_hex"])}
```

Проверка подписи D1: **{crc["d1_verification"]}**.

## 6. Демонстрация подбора D3

Файл D3 строится как `D3 = D2 || patch`, где `patch` - четыре байта, рассчитанные по линейности CRC32 над GF(2), без перебора `2^32` значений.

Размер D2: **{crc["d2_size"]} байт**.
Размер D3: **{crc["d3_size"]} байт**.
Четырехбайтный patch, hex: **{crc["patch_hex"]}**.

D3 начинается с полного содержимого D2: **{"OK" if crc["d3_starts_with_d2"] else "FAIL"}**.
Равенство CRC32(D3) и CRC32(D1): **{"OK" if crc["d3_crc32_equals_d1"] else "FAIL"}**.
Проверка D3 старой подписью D1: **{crc["d3_old_signature_verification"]}**.

## 7. Итоговые результаты проверки

- Генерация ключей RSA: **OK**
- Шифрование файла: **OK**
- Расшифрование файла: **OK**
- Расшифрованный файл совпадает с исходным: **{"OK" if files["decrypted_equals_original"] else "FAIL"}**
- RSA/SHA-256 для исходного файла: **{sha["original_verification"]}**
- RSA/SHA-256 для измененного файла: **{sha["modified_verification"]}**
- RSA/CRC32 для D1: **{crc["d1_verification"]}**
- CRC32(D3) == CRC32(D1): **{"OK" if crc["d3_crc32_equals_d1"] else "FAIL"}**
- D3 проходит проверку старой CRC32-подписью D1: **{crc["d3_old_signature_verification"]}**
"""


def _build_verification_log(data: dict[str, Any]) -> str:
    # Краткий журнал нужен для приложения к отчету и быстрой проверки результатов.
    files = data["files"]
    sha = data["sha256_signature"]
    crc = data["crc32_signature"]
    lines = [
        "key generation OK",
        "encryption OK",
        "decryption OK",
        f"decrypted equals original {'OK' if files['decrypted_equals_original'] else 'FAIL'}",
        f"SHA-256 signature original {sha['original_verification']}",
        f"SHA-256 signature modified {sha['modified_verification']}",
        f"CRC32 D1 signature {crc['d1_verification']}",
        f"CRC32(D3) == CRC32(D1) {'OK' if crc['d3_crc32_equals_d1'] else 'FAIL'}",
        f"CRC32 D3 with old signature {crc['d3_old_signature_verification']}",
    ]
    return "\n".join(lines) + "\n"


def _build_hex_dump(data: dict[str, Any]) -> str:
    aes = data["aes"]
    files = data["files"]
    return f"""# Hex dump для Lab1

## Первые 100 байт DER-контейнера

```text
{_hex_block(files["container_first_100_hex"])}
```

## DER RSA/SHA-256 signature container, first 100 bytes

```text
{_hex_block(data["sha256_signature"]["signature_der_first_100_hex"])}
```

## DER RSA/CRC32 signature container, first 100 bytes

```text
{_hex_block(data["crc32_signature"]["signature_der_first_100_hex"])}
```

## Первые 100 байт AES ciphertext

```text
{_hex_block(files["ciphertext_first_100_hex"])}
```

## AES-256 ключ

```text
{_hex_block(aes["aes_key_hex"])}
```

## IV

```text
{aes["iv_hex"]}
```

## Зашифрованный AES-ключ

```text
{_hex_block(aes["encrypted_key_hex"])}
```
"""


def _build_crc32_demo(data: dict[str, Any]) -> str:
    crc = data["crc32_signature"]
    return f"""# Демонстрация дополнительного задания RSA/CRC32

CRC32(D1): **{crc["d1_crc32_hex"]}** / **{crc["d1_crc32_decimal"]}**.

CRC32(D2): **{crc["d2_crc32_hex"]}** / **{crc["d2_crc32_decimal"]}**.

Четырехбайтный patch, hex: **{crc["patch_hex"]}**.

CRC32(D3): **{crc["d3_crc32_hex"]}** / **{crc["d3_crc32_decimal"]}**.

D3 построен как `D3 = D2 || patch`.

D3 сохраняет все содержимое D2: **{"OK" if crc["d3_starts_with_d2"] else "FAIL"}**.

D3 проходит проверку со старой CRC32-подписью D1: **{crc["d3_old_signature_verification"]}**.
"""


def _build_theory() -> str:
    return """# Теоретические сведения

## 1. RSA

В RSA выбираются два простых числа `p` и `q`, после чего вычисляется модуль `n = p q`. Функция Эйлера для такого модуля равна `phi(n) = (p-1)(q-1)`. Открытый показатель `e` выбирается взаимно простым с `phi(n)`, а закрытый показатель `d` удовлетворяет сравнению `e d ≡ 1 mod phi(n)`.

Шифрование целого представителя сообщения выполняется как `c = m^e mod n`, расшифрование как `m = c^d mod n`. В лабораторной используется учебная реализация RSA для демонстрации принципов. В реальных системах textbook RSA без padding не применяют: для шифрования нужен OAEP, для подписи - PSS или другой стандартизованный padding.

## 2. Гибридное шифрование RSA + AES

RSA не используют для шифрования больших файлов напрямую: операция медленная, размер блока ограничен модулем, а без padding схема детерминирована. Поэтому применяется гибридная схема: данные файла шифруются симметричным алгоритмом AES, а RSA шифрует только случайный AES-ключ.

В данной работе файл шифруется AES-256-CBC. Случайный 32-байтный ключ AES помещается в контейнер в RSA-зашифрованном виде. IV нужен для режима CBC, чтобы одинаковые первые блоки открытого текста не давали одинаковые первые блоки шифртекста при одном и том же ключе.

## 3. AES-256-CBC

AES-256 использует ключ длиной 256 бит и размер блока 128 бит. Режим CBC связывает каждый блок открытого текста с предыдущим блоком шифртекста через XOR перед шифрованием. Для первого блока используется IV длиной 16 байт.

Так как AES работает с блоками фиксированного размера, перед шифрованием применяется PKCS#7 padding. При расшифровании padding проверяется и удаляется, после чего восстанавливается исходный файл.

## 4. ASN.1 DER-контейнер

Структурированный бинарный контейнер нужен, чтобы хранить вместе версию формата, RSA-зашифрованный ключ, IV, шифртекст и параметры подписи без неоднозначного разбора. DER является однозначным бинарным кодированием ASN.1.

Зашифрованный файл хранится как:

```text
EncryptedFile ::= SEQUENCE {
  version INTEGER,
  encryptedKey OCTET STRING,
  iv OCTET STRING,
  ciphertext OCTET STRING
}
```

Файл подписи хранится как:

```text
SignatureFile ::= SEQUENCE {
  version INTEGER,
  algorithm UTF8String,
  hashValue OCTET STRING,
  hashModN INTEGER,
  signature INTEGER
}
```

## 5. Электронная подпись RSA/SHA-256

Для подписи вычисляется `h = SHA-256(file) mod n`, затем `s = h^d mod n`. Проверка выполняет обратную операцию с открытым ключом: `s^e mod n == h`. SHA-256 подходит для лабораторной как криптографическая хэш-функция с большим выходом и практической устойчивостью к подбору коллизий.

## 6. CRC32 и почему он не подходит для электронной подписи

CRC32 является линейной контрольной суммой для обнаружения случайных ошибок, а не криптографическим хэшем. Выход имеет всего 32 бита, коллизии легко находятся, а линейность позволяет конструктивно изменять данные при сохранении заданного CRC32.

В дополнительном задании строится файл `D3 = D2 || patch`, где четыре байта `patch` подбираются так, чтобы `CRC32(D3) == CRC32(D1)`. Если подпись строится по CRC32, то D3 проходит проверку старой подписью D1, хотя содержимое файла другое.
"""


def _build_control_questions() -> str:
    return """# Контрольные вопросы

## 1. Почему RSA не шифрует весь файл напрямую?

RSA медленнее симметричных алгоритмов и может обрабатывать только данные меньше модуля `n`. Кроме того, textbook RSA без padding небезопасен. Поэтому RSA шифрует только ключ, а файл шифруется AES.

## 2. Зачем используется AES-256-CBC в гибридной схеме?

AES быстро шифрует данные произвольного размера, а ключ длиной 256 бит дает достаточный запас стойкости для учебной реализации. RSA защищает только AES-ключ.

## 3. Зачем нужен IV в CBC?

IV задает начальное значение цепочки CBC. Он делает шифрование первого блока зависимым от случайного значения, поэтому одинаковые сообщения при одном ключе не начинаются одинаковым шифртекстом.

## 4. Что хранится в ASN.1 DER-контейнере зашифрованного файла?

Версия формата, RSA-зашифрованный AES-ключ, IV и AES-шифртекст файла.

## 5. Что хранится в ASN.1 DER-контейнере подписи?

Версия, имя алгоритма, сохраненное значение хэша, хэш как число по модулю `n` и целое значение RSA-подписи.

## 6. Как формируется RSA/SHA-256 подпись?

Сначала вычисляется SHA-256 от файла, затем хэш переводится в целое число и приводится по модулю `n`. Подпись равна `s = h^d mod n`.

## 7. Как проверяется RSA/SHA-256 подпись?

Проверяющая сторона заново вычисляет SHA-256 файла, получает `h`, затем проверяет, что `s^e mod n == h`.

## 8. Почему при проверке нельзя доверять hashValue из контейнера без пересчёта?

Контейнер может быть изменен вместе с файлом. Если не пересчитывать хэш по реальным данным, проверка подтвердит не содержимое файла, а только сохраненное в контейнере значение.

## 9. Чем CRC32 отличается от SHA-256?

CRC32 - короткая линейная контрольная сумма для ошибок передачи. SHA-256 - криптографическая хэш-функция с 256-битным выходом, рассчитанная на сопротивление коллизиям и подделке.

## 10. Почему CRC32 нельзя использовать как криптографический хэш для ЭП?

Из-за 32-битного размера и линейности CRC32 легко построить другое сообщение с тем же значением. Такая подпись не защищает целостность от намеренной подделки.

## 11. Как работает подбор D3 = D2 || patch?

К выбранному содержимому D2 добавляются четыре специально рассчитанных байта. Из-за линейных свойств CRC32 эти байты переводят итоговый CRC32 в заранее заданное значение CRC32(D1).

## 12. Почему D3 проходит проверку старой подписью D1?

Потому что подпись RSA/CRC32 проверяет только значение CRC32. Если `CRC32(D3) == CRC32(D1)`, то старая подпись от D1 подтверждает и D3.

## 13. Почему в реальных системах RSA-подпись должна использовать padding, например PSS?

Padding устраняет опасные алгебраические свойства textbook RSA, добавляет случайность и структуру проверки. PSS является стандартизованной схемой RSA-подписи с доказуемыми свойствами безопасности.
"""


def _build_stand_commands() -> str:
    return r"""# Команды для защиты

## Проверка лабораторной

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab1
.\.venv\Scripts\Activate.ps1
pytest -q
python scripts\generate_report_materials.py
Get-Content .\report\generated\verification_log.txt -Encoding UTF8
```

## Основная CLI-демонстрация

```powershell
python -m src.main keygen --bits 1024 --out artifacts
python -m src.main encrypt --file data\message.txt --public-key artifacts\public.json --out artifacts\message.enc --debug-json artifacts\encrypt_debug.json
python -m src.main decrypt --file artifacts\message.enc --private-key artifacts\private.json --out artifacts\message.dec
python -m src.main sign-sha256 --file data\message.txt --private-key artifacts\private.json --signature artifacts\message.sha256.sig
python -m src.main verify-sha256 --file data\message.txt --public-key artifacts\public.json --signature artifacts\message.sha256.sig
python -m src.main sign-crc32 --file data\d1.txt --private-key artifacts\private.json --signature artifacts\d1.crc32.sig
python -m src.main verify-crc32 --file data\d1.txt --public-key artifacts\public.json --signature artifacts\d1.crc32.sig
python -m src.main forge-crc32 --original data\d1.txt --modified data\d2.txt --out artifacts\d3.txt
python -m src.main verify-crc32 --file artifacts\d3.txt --public-key artifacts\public.json --signature artifacts\d1.crc32.sig
```

## Проверка первого байта DER

```powershell
Format-Hex .\artifacts\message.enc | Select-Object -First 1
Format-Hex .\artifacts\message.sha256.sig | Select-Object -First 1
Format-Hex .\artifacts\d1.crc32.sig | Select-Object -First 1
```

Ожидаемый первый байт: `30`, что соответствует ASN.1 DER `SEQUENCE`.
"""


def _build_full_report_draft(report_data: str, theory: str, control_questions: str) -> str:
    theory_body = theory.removeprefix("# Теоретические сведения\n\n")
    practical_body = report_data.removeprefix("# Данные для отчета по Lab1\n\n")
    control_body = control_questions.removeprefix("# Контрольные вопросы\n\n")
    return f"""# Лабораторная работа №1. Основы RSA

## Цель работы

Изучить принципы RSA, гибридного шифрования RSA + AES-256-CBC, ASN.1 DER-контейнеров и электронной подписи RSA/SHA-256, а также показать непригодность CRC32 для криптографической подписи.

## Задание

Реализованы генерация ключей RSA, шифрование и расшифрование файла по гибридной схеме, сохранение данных в DER-контейнере, создание и проверка подписи RSA/SHA-256, подпись RSA/CRC32 и демонстрация подбора файла D3 с тем же CRC32, что и у D1.

## Теоретические сведения

{theory_body}

## Описание реализации

Код разделен на модули: `rsa.py` реализует RSA, `aes.py` - AES-256-CBC и padding, `der.py` и `sigder.py` - DER-контейнеры, `hybrid.py` - файловое гибридное шифрование, `signatures.py` - подписи, `crcforge.py` - подбор четырехбайтного CRC32-патча. CLI в `src/main.py` запускает основные операции лабораторной.

## Практические результаты

{practical_body}

## Дополнительное задание

Дополнительное задание демонстрирует слабость подписи по CRC32. Файл D3 строится как `D3 = D2 || patch`, где `patch` рассчитан так, чтобы `CRC32(D3) == CRC32(D1)`. Поэтому подпись, созданная для D1, проходит проверку для D3, хотя содержимое D3 начинается с выбранного D2.

## Контрольные вопросы

{control_body}

## Вывод

В работе реализована полная учебная схема защиты файла: RSA используется для ключей и подписи, AES-256-CBC - для данных, DER - для структурированного хранения. Проверка RSA/SHA-256 корректно отвергает измененный файл. Демонстрация CRC32 показывает, что контрольные суммы нельзя использовать как криптографические хэши для электронной подписи.
"""


def generate_report_materials(lab_root: Path | None = None, bits: int = 1024) -> dict[str, Any]:
    """Сформировать материалы отчета и вернуть собранные данные."""
    root = (lab_root or DEFAULT_LAB_ROOT).resolve()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    data_dir = root / "data"
    artifacts_dir = root / "artifacts" / "report_run"
    generated_dir = root / "report" / "generated"
    # Временные артефакты очищаются, а report/generated остается папкой
    # с готовыми для вставки в отчет материалами.
    _clean_dir(artifacts_dir)
    generated_dir.mkdir(parents=True, exist_ok=True)

    message_path = data_dir / "message.txt"
    d1_path = data_dir / "d1.txt"
    d2_path = data_dir / "d2.txt"

    # 1. Генерация RSA-ключей и сохранение параметров p, q, n, e, d.
    private_key, public_key = generate_keypair(bits)
    private_key_path = artifacts_dir / "private.json"
    public_key_path = artifacts_dir / "public.json"
    save_private_key(private_key_path, private_key)
    save_public_key(public_key_path, public_key)

    encrypted_path = artifacts_dir / "message.enc"
    decrypted_path = artifacts_dir / "message.dec"
    debug_json_path = artifacts_dir / "encrypt_debug.json"
    # 2. Гибридное шифрование файла и debug JSON с AES/DER значениями.
    encrypt_file(message_path, public_key, encrypted_path, debug_json_path)
    # 3. Расшифрование и байтовое сравнение с исходным файлом.
    decrypt_file(encrypted_path, private_key, decrypted_path)

    message = message_path.read_bytes()
    decrypted_equals_original = decrypted_path.read_bytes() == message
    debug = json.loads(debug_json_path.read_text(encoding="utf-8"))
    container_bytes = encrypted_path.read_bytes()

    sha_signature_path = artifacts_dir / "message.sha256.sig"
    # 4. RSA/SHA-256 подпись: проверяем исходный файл и отрицательный пример.
    sha_container = create_sha256_container(message, private_key)
    save_signature(sha_signature_path, sha_container)
    sha_loaded = load_signature_container(sha_signature_path)
    sha_original_valid = verify_sha256_container(message, sha_loaded, public_key)
    modified_path = artifacts_dir / "message.modified.txt"
    modified_message = message + b"\nmodified for negative signature check\n"
    modified_path.write_bytes(modified_message)
    sha_modified_valid = verify_sha256_container(modified_message, sha_loaded, public_key)
    sha_digest = hashlib.sha256(message).digest()
    sha_signature_der = sha_signature_path.read_bytes()

    crc_signature_path = artifacts_dir / "d1.crc32.sig"
    d1_bytes = d1_path.read_bytes()
    d2_bytes = d2_path.read_bytes()
    # 5. RSA/CRC32 подпись для D1 как часть дополнительного задания.
    crc_container = create_crc32_container(d1_bytes, private_key)
    save_signature(crc_signature_path, crc_container)
    crc_loaded = load_signature_container(crc_signature_path)
    crc_d1_valid = verify_crc32_container(d1_bytes, crc_loaded, public_key)
    crc_signature_der = crc_signature_path.read_bytes()

    d3_path = artifacts_dir / "d3.txt"
    # 6. Построение D3 = D2 || patch без перебора 2^32 вариантов.
    forge_crc32_file(d1_path, d2_path, d3_path)
    d3_bytes = d3_path.read_bytes()
    patch = d3_bytes[len(d2_bytes) :]
    crc_d3_old_signature_valid = verify_crc32_container(d3_bytes, crc_loaded, public_key)

    d1_crc = crc32_bytes(d1_bytes)
    d2_crc = crc32_bytes(d2_bytes)
    d3_crc = crc32_bytes(d3_bytes)

    data: dict[str, Any] = {
        "rsa": {
            "p": str(private_key.p),
            "q": str(private_key.q),
            "n": str(private_key.n),
            "e": str(private_key.e),
            "d": str(private_key.d),
            "modulus_bit_length": private_key.n.bit_length(),
        },
        "aes": {
            "aes_key_hex": debug["aes_key_hex"],
            "iv_hex": debug["iv_hex"],
            "encrypted_key_hex": debug["encrypted_key_hex"],
        },
        "files": {
            "original_message_size": len(message),
            "encrypted_container_size": len(container_bytes),
            "decrypted_equals_original": decrypted_equals_original,
            "container_first_100_hex": debug["container_first_100_hex"],
            "ciphertext_first_100_hex": debug["ciphertext_first_100_hex"],
        },
        "sha256_signature": {
            "digest_hex": sha_digest.hex(),
            "h_sha256_mod_n": str(sha_loaded.hash_mod_n),
            "signature_integer": str(sha_loaded.signature),
            "signature_der_first_100_hex": sha_signature_der[:100].hex(),
            "original_verification": _status(sha_original_valid),
            "modified_verification": _status(sha_modified_valid),
        },
        "crc32_signature": {
            "d1_crc32_hex": f"{d1_crc:08x}",
            "d1_crc32_decimal": d1_crc,
            "d2_crc32_hex": f"{d2_crc:08x}",
            "d2_crc32_decimal": d2_crc,
            "d3_crc32_hex": f"{d3_crc:08x}",
            "d3_crc32_decimal": d3_crc,
            "patch_hex": patch.hex(),
            "d2_size": len(d2_bytes),
            "d3_size": len(d3_bytes),
            "d3_starts_with_d2": d3_bytes.startswith(d2_bytes),
            "d3_crc32_equals_d1": d3_crc == d1_crc,
            "signature_integer": str(crc_loaded.signature),
            "signature_der_first_100_hex": crc_signature_der[:100].hex(),
            "d1_verification": _status(crc_d1_valid),
            "d3_old_signature_verification": _status(crc_d3_old_signature_valid),
        },
    }

    report_data = _build_report_markdown(data)
    theory = _build_theory()
    control_questions = _build_control_questions()
    stand_commands = _build_stand_commands()
    full_report = _build_full_report_draft(report_data, theory, control_questions)

    # 7. Запись машинно-читаемых и человеко-читаемых файлов отчета.
    _write_json(generated_dir / "report_data.json", data)
    (generated_dir / "report_data.md").write_text(report_data, encoding="utf-8")
    (generated_dir / "verification_log.txt").write_text(_build_verification_log(data), encoding="utf-8")
    (generated_dir / "hex_dump.md").write_text(_build_hex_dump(data), encoding="utf-8")
    (generated_dir / "crc32_demo.md").write_text(_build_crc32_demo(data), encoding="utf-8")
    (generated_dir / "theory.md").write_text(theory, encoding="utf-8")
    (generated_dir / "control_questions.md").write_text(control_questions, encoding="utf-8")
    (generated_dir / "stand_commands.md").write_text(stand_commands, encoding="utf-8")
    (generated_dir / "full_report_draft.md").write_text(full_report, encoding="utf-8")

    return data


def main() -> int:
    generate_report_materials()
    print("Generated report materials:")
    for filename in REPORT_FILES:
        print(f"- report/generated/{filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

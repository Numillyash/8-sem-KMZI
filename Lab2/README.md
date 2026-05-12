# Lab2: RSA attacks with exponent-related weaknesses

Clean educational implementation for KMZI Lab2. This folder is independent from `Lab1`, `Lab6`, and the old `КМЗИ/2 лаба/kmzi_2` reference folder.

## Setup on Windows PowerShell

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The implementation uses the Python standard library for RSA arithmetic and attack demos. `pytest` is required only for tests.

## CLI commands

```powershell
python -m src.main common-modulus --json data/common_modulus.json
python -m src.main wiener --json data/wiener.json
python -m src.main broadcast --json data/broadcast.json
python -m src.main small-order --json data/small_order.json
python -m src.main safe-keygen --bits 1024 --out artifacts/safe_key.json
python -m src.main demo --out artifacts/demo_data
```

JSON formats:

```json
{"n": 0, "e_b": 65537, "d_b": 0, "e_a": 17}
```

```json
{"n": 0, "e": 0}
```

```json
{"e": 3, "pairs": [{"n": 0, "c": 0}, {"n": 0, "c": 0}, {"n": 0, "c": 0}]}
```

```json
{"n": 0, "e": 0, "c": 0}
```

## Команды для демонстрации

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab2
python -m src.main demo --out data
python -m src.main common-modulus --json data/common_modulus.json
python -m src.main wiener --json data/wiener.json
python -m src.main broadcast --json data/broadcast.json
python -m src.main small-order --json data/small_order.json
python -m src.main safe-keygen --bits 1024 --out artifacts/safe_key.json
```

## Генерация данных для отчёта

```powershell
python scripts\generate_report_materials.py
```

The script cleans `artifacts\report_run` and writes report-ready materials to `report\generated`.

## Генерация материалов для отчёта

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab2
python scripts\generate_report_materials.py
```

Скрипт обновляет практические результаты, теоретические сведения, ответы на контрольные вопросы и черновик полного отчёта. Временные файлы запуска создаются в `artifacts\report_run` и не добавляются в Git.

## Файлы отчёта

- `report/generated/report_data.md` - практические результаты атак и проверок.
- `report/generated/report_data.json` - те же данные в машинно-читаемом виде.
- `report/generated/theory.md` - краткая теория по уязвимостям RSA.
- `report/generated/control_questions.md` - ответы на контрольные вопросы.
- `report/generated/stand_commands.md` - команды для демонстрации на защите.
- `report/generated/full_report_draft.md` - собранный черновик отчёта.
- `report/generated/verification_log.txt` - короткий лог успешных проверок.

## Команды для защиты

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab2
.\.venv\Scripts\Activate.ps1
pytest -q
python scripts\generate_report_materials.py
Get-Content .\report\generated\verification_log.txt -Encoding UTF8

python -m src.main demo --out artifacts\demo_data
python -m src.main common-modulus --json artifacts\demo_data\common_modulus.json
python -m src.main wiener --json artifacts\demo_data\wiener.json
python -m src.main broadcast --json artifacts\demo_data\broadcast.json
python -m src.main small-order --json artifacts\demo_data\small_order.json
python -m src.main safe-keygen --bits 512 --out artifacts\safe_key.json
```

## Tests

```powershell
pytest -q
```

## Покрытие программ П-1..П-5

- П-1: атака общего модуля RSA по известному закрытому показателю другого пользователя.
- П-2: атака Винера на RSA с малым `d`.
- П-3: широковещательная атака при малом общем `e`.
- П-4: генерация и анализ безопасных параметров RSA.
- П-5: бесключевое дешифрование при малом порядке `e`.

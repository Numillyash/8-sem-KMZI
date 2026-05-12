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

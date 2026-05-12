# Команды для защиты

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

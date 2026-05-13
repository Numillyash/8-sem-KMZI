# Команды для защиты

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

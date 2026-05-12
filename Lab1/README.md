# Lab1: RSA, Hybrid Encryption, and RSA Signatures

Clean educational implementation for KMZI Lab1. The project is intentionally separate from `Lab6` and from the old `КМЗИ/1 лаба/kmzi_1` folder.

## Setup on Windows PowerShell

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab1
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The implementation uses only the Python standard library for RSA, AES-256-CBC, ASN.1 DER encoding, SHA-256, and CRC32. `pytest` is required only for tests.

## CLI

```powershell
python -m src.main keygen --bits 1024 --out artifacts
python -m src.main encrypt --file data/message.txt --public-key artifacts/public.json --out artifacts/message.enc --debug-json artifacts/encrypt_debug.json
python -m src.main decrypt --file artifacts/message.enc --private-key artifacts/private.json --out artifacts/message.dec
python -m src.main sign-sha256 --file data/message.txt --private-key artifacts/private.json --signature artifacts/message.sha256.sig
python -m src.main verify-sha256 --file data/message.txt --public-key artifacts/public.json --signature artifacts/message.sha256.sig
python -m src.main sign-crc32 --file data/d1.txt --private-key artifacts/private.json --signature artifacts/d1.crc32.sig
python -m src.main verify-crc32 --file data/d1.txt --public-key artifacts/public.json --signature artifacts/d1.crc32.sig
python -m src.main forge-crc32 --original data/d1.txt --modified data/d2.txt --out artifacts/d3.txt
python -m src.main verify-crc32 --file artifacts/d3.txt --public-key artifacts/public.json --signature artifacts/d1.crc32.sig
```

## Команды для демонстрации

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab1

# 1. Сгенерировать пару RSA-ключей.
python -m src.main keygen --bits 1024 --out artifacts

# 2. Зашифровать файл: AES-256-CBC шифрует данные, RSA шифрует AES-ключ.
#    Отчет encrypt_debug.json содержит AES-ключ, IV и первые байты контейнера в hex.
python -m src.main encrypt --file data/message.txt --public-key artifacts/public.json --out artifacts/message.enc --debug-json artifacts/encrypt_debug.json

# 3. Расшифровать DER-контейнер и восстановить исходный файл.
python -m src.main decrypt --file artifacts/message.enc --private-key artifacts/private.json --out artifacts/message.dec

# 4. Подписать и проверить файл через RSA/SHA-256.
python -m src.main sign-sha256 --file data/message.txt --private-key artifacts/private.json --signature artifacts/message.sha256.sig
python -m src.main verify-sha256 --file data/message.txt --public-key artifacts/public.json --signature artifacts/message.sha256.sig

# 5. Подписать D1 через RSA/CRC32 и проверить подпись.
python -m src.main sign-crc32 --file data/d1.txt --private-key artifacts/private.json --signature artifacts/d1.crc32.sig
python -m src.main verify-crc32 --file data/d1.txt --public-key artifacts/public.json --signature artifacts/d1.crc32.sig

# 6. Сформировать D3 = D2 || patch так, чтобы CRC32(D3) == CRC32(D1).
python -m src.main forge-crc32 --original data/d1.txt --modified data/d2.txt --out artifacts/d3.txt
python -m src.main verify-crc32 --file artifacts/d3.txt --public-key artifacts/public.json --signature artifacts/d1.crc32.sig
```

Папка `artifacts` предназначена для сгенерированных ключей, подписей, зашифрованных файлов, восстановленных файлов и debug-отчетов. Эти файлы не добавляются в Git.

## Tests

```powershell
pytest -q
```

The tests check hybrid encryption/decryption, RSA/SHA-256 signatures, RSA/CRC32 signatures, and the deterministic CRC32 four-byte append forgery.

## Генерация данных для отчёта

```powershell
python scripts\generate_report_materials.py
```

Скрипт создает временные файлы запуска в `artifacts\report_run` и готовые материалы для отчета в:

```text
report\generated
```

Файлы из `report\generated` можно использовать для вставки в итоговый отчет.

## ASN.1 DER Container

Encrypted files are stored as a DER `SEQUENCE`:

```text
EncryptedFile ::= SEQUENCE {
  version       INTEGER,
  encryptedKey  OCTET STRING,
  iv            OCTET STRING,
  ciphertext    OCTET STRING
}
```

`encryptedKey` is the RSA encryption of the 32-byte AES key. `ciphertext` is AES-256-CBC with PKCS#7 padding.

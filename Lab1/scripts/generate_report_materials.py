"""Generate reproducible report materials for KMZI Lab1.

The script uses only the existing Lab1 implementation and the Python standard
library. It writes transient cryptographic artifacts into artifacts/report_run
and report-ready files into report/generated.
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
)


def _clean_dir(path: Path) -> None:
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

## 3. Расшифрование

DER-контейнер был разобран, AES-ключ расшифрован закрытым RSA-ключом, затем содержимое файла восстановлено AES-CBC.

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


def generate_report_materials(lab_root: Path | None = None, bits: int = 1024) -> dict[str, Any]:
    """Generate report materials and return collected machine-readable data."""
    root = (lab_root or DEFAULT_LAB_ROOT).resolve()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    data_dir = root / "data"
    artifacts_dir = root / "artifacts" / "report_run"
    generated_dir = root / "report" / "generated"
    _clean_dir(artifacts_dir)
    generated_dir.mkdir(parents=True, exist_ok=True)

    message_path = data_dir / "message.txt"
    d1_path = data_dir / "d1.txt"
    d2_path = data_dir / "d2.txt"

    private_key, public_key = generate_keypair(bits)
    private_key_path = artifacts_dir / "private.json"
    public_key_path = artifacts_dir / "public.json"
    save_private_key(private_key_path, private_key)
    save_public_key(public_key_path, public_key)

    encrypted_path = artifacts_dir / "message.enc"
    decrypted_path = artifacts_dir / "message.dec"
    debug_json_path = artifacts_dir / "encrypt_debug.json"
    encrypt_file(message_path, public_key, encrypted_path, debug_json_path)
    decrypt_file(encrypted_path, private_key, decrypted_path)

    message = message_path.read_bytes()
    decrypted_equals_original = decrypted_path.read_bytes() == message
    debug = json.loads(debug_json_path.read_text(encoding="utf-8"))
    container_bytes = encrypted_path.read_bytes()

    sha_signature_path = artifacts_dir / "message.sha256.sig"
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
    crc_container = create_crc32_container(d1_bytes, private_key)
    save_signature(crc_signature_path, crc_container)
    crc_loaded = load_signature_container(crc_signature_path)
    crc_d1_valid = verify_crc32_container(d1_bytes, crc_loaded, public_key)
    crc_signature_der = crc_signature_path.read_bytes()

    d3_path = artifacts_dir / "d3.txt"
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

    _write_json(generated_dir / "report_data.json", data)
    (generated_dir / "report_data.md").write_text(_build_report_markdown(data), encoding="utf-8")
    (generated_dir / "verification_log.txt").write_text(_build_verification_log(data), encoding="utf-8")
    (generated_dir / "hex_dump.md").write_text(_build_hex_dump(data), encoding="utf-8")
    (generated_dir / "crc32_demo.md").write_text(_build_crc32_demo(data), encoding="utf-8")

    return data


def main() -> int:
    generate_report_materials()
    print("Generated report materials:")
    for filename in REPORT_FILES:
        print(f"- report/generated/{filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

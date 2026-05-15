# ЛР6: ГОСТ Р 34.10-2018

Учебный CLI-проект для формирования и проверки электронной цифровой подписи ГОСТ Р 34.10-2018.

Реализация включает:

- параметры эллиптической кривой варианта 8 из приложения Д;
- ручную арифметику точек эллиптической кривой;
- хэширование Стрибог через `gostcrypto`;
- ASN.1 DER контейнер подписи по структуре из приложения Г;
- CLI-команды `sign` и `verify`;
- генератор материалов для отчёта.

Коэффициент кривой `a` хранится в коде как `-1` для читаемости параметров варианта 8. В ASN.1 DER контейнере он записывается как `a mod p = p - 1`, потому что параметры конечного поля должны быть неотрицательными INTEGER.

## Подготовка окружения

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab6
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Формат ключей JSON

Закрытый ключ:

```json
{
  "curve_id": "gost3410-2018-var8",
  "p": 57896044628958718631213028275518411328476149599789770738757218840632915517411,
  "a": -1,
  "b": 44516423948019661825420813927965592341675839270849860441861020678502941837466,
  "q": 28948022314479359315606514137759205664236832023231628035871193493020981068937,
  "P": {
    "x": 2323576058601956664720966708045726308916627824741707729836708887517232685058,
    "y": 20772302011053991390127435262297715010367018383131467831609444907978987653753
  },
  "d": 123456789
}
```

Открытый ключ содержит те же параметры кривой и точку `Q = dP`.

## Подпись файла

```powershell
python -m src.main sign `
  --file data\message.txt `
  --private-key artifacts\report_run\private_demo.json `
  --signature artifacts\report_run\message.sig `
  --hash-alg streebog256
```

## Проверка подписи

```powershell
python -m src.main verify `
  --file data\message.txt `
  --signature artifacts\report_run\message.sig `
  --public-key artifacts\report_run\public_demo.json
```

Вывод:

- `VALID` и код возврата `0` при корректной подписи;
- `INVALID` и код возврата `1` при ошибке проверки.

## Генерация материалов отчёта

```powershell
python scripts\generate_report_materials.py
```

Команда создаёт:

- `report/generated/report_data.md`
- `report/generated/report_data.json`
- `report/generated/verification_log.txt`
- `report/generated/hex_dump.md`
- `report/generated/theory.md`
- `report/generated/control_questions.md`
- `report/generated/stand_commands.md`
- `report/generated/full_report_draft.md`

Временные ключи, сообщения и подписи записываются в `artifacts/report_run/`. Этот каталог предназначен для локального запуска и игнорируется Git.

## Команды для защиты

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

..\dumpasn1\dumpasn1.exe .\artifacts\report_run\message.sig
```

Для `dumpasn1` ожидается результат без ошибок и предупреждений: `0 warnings, 0 errors`.

## Тесты

```powershell
pytest -q
```

Тесты проверяют успешный путь `sign -> verify`, отказ проверки для изменённого сообщения, отказ для испорченной подписи и корректность сгенерированных отчётных материалов.

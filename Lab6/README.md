# ЛР6: ГОСТ Р 34.10-2018 (учебная реализация)

Минимальный учебный CLI-проект для:
- формирования подписи файла (`sign`);
- проверки подписи файла (`verify`).

Реализация включает ручную арифметику ЭК и отдельный модуль хэширования на `gostcrypto`.

## 1) Подготовка окружения (Windows, PowerShell)

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab6
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 2) Формат ключей JSON

`private.json`:

```json
{
  "curve_id": "edu-tiny-v1",
  "p": 17,
  "a": 2,
  "b": 2,
  "q": 19,
  "P": { "x": 5, "y": 1 },
  "d": 7
}
```

`public.json`:

```json
{
  "curve_id": "edu-tiny-v1",
  "p": 17,
  "a": 2,
  "b": 2,
  "q": 19,
  "P": { "x": 5, "y": 1 },
  "Q": { "x": 0, "y": 6 }
}
```

Примечания:
- `Q = d * P` на выбранной кривой.
- Сейчас в `src/config.py` стоит учебная placeholder-кривая.
- TODO в коде помечает места, где нужно вставить точные параметры варианта из приложения Д.

## 3) Подпись файла

```powershell
python -m src.main sign `
  --file data\message.txt `
  --private-key artifacts\private.json `
  --signature artifacts\message.sig `
  --hash-alg streebog256
```

## 4) Проверка подписи

```powershell
python -m src.main verify `
  --file data\message.txt `
  --signature artifacts\message.sig `
  --public-key artifacts\public.json
```

Вывод:
- `VALID` и код возврата `0` при корректной подписи;
- `INVALID` и код возврата `1` при ошибке проверки.

## 5) Запуск тестов

```powershell
pytest -q
```

Тесты (`tests/test_smoke.py`) проверяют:
- успешный путь `sign -> verify`;
- отказ проверки при изменённом файле;
- отказ проверки при испорченном файле подписи.

## 6) Какие файлы использовать в отчёте

- Основной листинг:
  - `src/config.py`
  - `src/ecc.py`
  - `src/hashing.py`
  - `src/sigfile.py`
  - `src/sign.py`
  - `src/main.py`
- Тестовый листинг:
  - `tests/test_smoke.py`
- Пример входных/выходных артефактов:
  - `private.json`, `public.json`, подписываемый файл, `.sig`-файл.

## 7) Текущее состояние формата подписи

Используется временный бинарный контейнер:

`magic + hash_alg + curve_id + r_len + r + s_len + s`

Модуль контейнера изолирован в `src/sigfile.py`.
TODO: заменить содержимое этого модуля на точный формат из приложения Г без изменения бизнес-логики `sign/verify`.

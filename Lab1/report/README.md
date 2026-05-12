# Материалы для отчета Lab1

Скрипт `scripts\generate_report_materials.py` генерирует данные, которые можно вставить в отчет по лабораторной работе: параметры RSA, значения AES, результаты проверки подписей, демонстрацию CRC32 и hex dump.

## Запуск из Windows PowerShell

```powershell
cd C:\Users\Georgul\Documents\8_sem\KMZI\Lab1
python scripts\generate_report_materials.py
```

Скрипт создает временные криптографические артефакты в папке:

```text
artifacts\report_run
```

Эта папка не предназначена для добавления в Git.

## Сгенерированные файлы

Файлы для отчета появляются в папке:

```text
report\generated
```

Для итогового отчета обычно нужны:

- `report\generated\report_data.md` - основной текстовый блок с параметрами и результатами.
- `report\generated\hex_dump.md` - hex dump ключевых значений.
- `report\generated\crc32_demo.md` - объяснение и значения для дополнительного задания CRC32.
- `report\generated\verification_log.txt` - краткий журнал проверок.
- `report\generated\report_data.json` - машинно-читаемые данные для повторной проверки.


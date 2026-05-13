# Команды для защиты

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
```

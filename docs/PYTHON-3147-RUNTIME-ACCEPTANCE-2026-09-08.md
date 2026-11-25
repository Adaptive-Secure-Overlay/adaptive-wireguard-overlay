# Принятие Python 3.14.7 для Development-WireGuard

## Итог

Отдельный пакет `.\Development-WireGuard` совместим с
установленным Python 3.14.7. Явный интерпретатор совпал с платформенной
матрицей по точному пути, версии и SHA-256. Обычная пользовательская команда
`python` уже разрешается в тот же файл, поэтому cutover не требовался и не
выполнялся.

Этот receipt относится только к локальному пакету WireGuard. Он не является
доказательством IPsec-диссертации, EVE-NG, kernel WireGuard или VPN deployment.

## Runtime

| Поле | Подтверждено |
| --- | --- |
| Exact executable | `<USER_HOME>\AppData\Local\Programs\Python\Python314\python.exe` |
| Version | `Python 3.14.7` |
| Full build | `3.14.7 (tags/v3.14.7:823f032, Aug 5 2026, 10:51:32) [MSC v.1944 64 bit (AMD64)]` |
| Architecture | `AMD64`, 64-bit |
| Expected SHA-256 | `4942B86A6597E5AEE0128DAA00050ED79BC21F6E709A78EB19CBFEB0C2F39AC9` |
| Observed SHA-256 | `4942B86A6597E5AEE0128DAA00050ED79BC21F6E709A78EB19CBFEB0C2F39AC9` |
| Hash match | `true` |
| Normal-user `python` | тот же exact executable, `Python 3.14.7` |
| Cutover required/performed | `false / false` |

## Focused checks

Обе проверки запущены явным executable с локальным `PYTHONPATH=src` и
`PYTHONDONTWRITEBYTECODE=1`:

- in-memory compile: `15/15`, exit code `0`;
- `unittest discover -s tests -p test_*.py -v`: `25/25`, exit code `0`.

Предыдущий пакетный manifest повторно проверен: `42/42`, SHA-256 самого
manifest — `ecd38db40fac915d0068be11dcfae1ef1221789ba6940f039fa9915e0272ee7a`.
Это подтверждает неизменность зафиксированных source/tests/config/docs из
checkpoint 2026-09-03.

## Сохранённые receipts

- `docs/VALIDATION-RESULT.md` — прежний локальный runtime Python 3.14.2;
- `docs/TRUST-REGISTRY-CHECKPOINT-20260903.json`;
- `docs/TRUST-REGISTRY-CHECKPOINT-20260903.sha256`.

Старые receipts и исходный код не удалялись и не изменялись. EVE-NG,
WireGuard/VPN, сеть, сервисы, PATH и рабочие среды не запускались и не
переключались. Выполнялись только чтение runtime metadata/hash, in-memory
compile и локальные unit-тесты; тестовые временные файлы очищены самим suite.

## Источники сопоставления

- `C:\Codex\Platform\PluginsSkills\python3147-migration\PYTHON_3147_PHASE1_MATRIX_2026-09-08.json`;
- `C:\Codex\Platform\Center\PYTHON_3147_GLOBAL_MIGRATION_2026-09-08.md`.

Статус: `accepted_no_cutover_required`.

# Закрытие аутентифицированного реестра узлов

## Результат

Локальный пакет `wg-handshake-overlay 0.2.0` закрывает исходный случай
`remote_public_key_substitution_without_signed_registry`: без загруженного
реестра и при несовпадении предъявленного ключа маршрут не создаётся, ключ
daemon не выдаётся, результат адаптера — `DROP`.

## Реализованный инвариант

```text
pinned Ed25519 public root
  -> SSHSIG verify in namespace wg-node-registry-v1
  -> strict canonical registry and monotonic version
  -> resolve every route member
  -> compare any presented key
  -> route establishment / daemon key release
```

Доверенный root задаётся вне загружаемого документа. Документ допускает только
строгую схему и канонический `node_id -> WireGuard public key`. Проверка
подписи выполняется установленным OpenSSH, собственной реализации Ed25519 в
проекте нет. Active/last-valid copies обновляются через same-directory temp,
`fsync` и atomic replace; recovery повторно проверяет подпись и выбирает
наибольшую валидную version.

Публичные конструкторы, позволявшие бы вручную создать «доверенный» binding
или route, отсутствуют. Возвращённый authenticated route повторно сверяет
текущие version и signed digest перед выдачей public key, поэтому старый
объект нельзя использовать после registry update.

## Негативная матрица

Подтверждены rejection до route/key use для:

- отсутствующего реестра и caller-supplied remote key;
- отсутствующей или повреждённой подписи;
- неизвестного signer key id;
- изменения WG key после подписи;
- неканонической записи и duplicate JSON member;
- равной version/replay и rollback на старую version;
- неизвестного route member;
- ручного создания trusted binding;
- stale authenticated route после valid update;
- ошибки перед atomic replace.

Все rejected update сохраняют active/last-valid hashes и текущую version.
Valid update и recovery из последней валидной копии проходят.

## Проверки

| Gate | Результат |
| --- | --- |
| `scripts/Test-TrustRegistry.ps1` | 9/9, exit 0 |
| adapter tests | 5/5, exit 0 |
| `scripts/validate-local.ps1` | 25/25, exit 0 |
| прежняя модель | 27/27, exit 0 |
| Python 3.11 syntax parse | 15/15 файлов |
| config/schema JSON | valid |
| secret-pattern scan | 0 совпадений |

Runtime: Python 3.14.2; OpenSSH_for_Windows_9.5p2. Сеть, EVE-NG, WireGuard,
firewall и привилегированные команды не использовались.

## Неподтверждённая граница

Отдельный владелец стенда должен проверить реальный kernel handshake,
capture/inject, отсутствие daemon send/WG activation во всех negative cases и
atomic reload в новом изолированном EVE-NG checkpoint. Точный контракт:
`docs/EVE-NG-TRUST-REGISTRY-TEST-CONTRACT.md`.

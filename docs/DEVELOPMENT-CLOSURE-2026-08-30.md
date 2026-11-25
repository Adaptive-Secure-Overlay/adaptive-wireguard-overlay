# Закрытие этапа разработки WireGuard

## Статус

Технический этап закрыт на локальном reference-пакете без расширения scope.
Направление оставлено в режиме завершения: новые функции, сетевые изменения,
привилегированные действия и EVE-NG-прогоны не начаты.

## Идентификаторы

- Governance checkpoint: `candidate-close-development-20260830-01`.
- Пакет: `wg-handshake-overlay 0.1.0`.
- Result schema: `1`.
- Validation checkpoint: `2026-08-30T16:28:06+03:00`.
- Runtime: `Python 3.14.2`.
- Git revision: отсутствует; `Development-WireGuard` не является отдельным
  Git-репозиторием. Целостность состояния фиксирует SHA-256 manifest
  `docs/DEVELOPMENT-CHECKPOINT-20260830.sha256`.

## Подтверждено локально

- `scripts/validate-local.ps1` завершился с exit code `0`.
- Выполнено `14/14` unit tests.
- Логическая матрица выполнена `27/27`: `bidir12=2`, `disjoint5=5`,
  `ring10=10`, `reverse5=10`.
- WG type 1/2/3 допускается только в handshake overlay.
- WG type 4 получает только `DIRECT_BYPASS` и повторно отклоняется при попытке
  доставки внутри overlay.
- Проверены framing, forward/reverse route, TTL, duplicate suppression,
  privacy view, fail-closed обработка, JSON/CSV модели и JSON-синтаксис
  конфигурации/schema.
- Локальная проверка не открывала сокеты и не вызывала `wg`, `nft`, `ip`,
  `tcpdump`, SSH или EVE-NG.
- Secret-pattern scan не обнаружил назначений private key, preshared key или
  password с ключевым материалом.

## Не подтверждено стендом

- Реальный Linux capture/inject/firewall backend не реализован в этом пакете.
- Kernel WireGuard, nftables/TPROXY/raw sockets и EVE-NG не запускались.
- Не получены стендовые packet capture, handshake, ping/data-plane,
  rekey, concurrent-start и timing evidence.
- `27/27` является результатом локальной in-memory модели, а не EVE-NG.
- Legacy checkpoint `20260821-115025` относится к прежней системе и не является
  WireGuard checkpoint.

## Материалы для диссертации

- Архитектура и граница эквивалентности:
  `.\Development-WireGuard\docs\ARCHITECTURE.md`.
- Контракт протокольного адаптера:
  `.\Development-WireGuard\docs\adapter-api.md`.
- Методика и критерии отдельного стендового эксперимента:
  `.\Development-WireGuard\docs\EVE-NG-TEST-CONTRACT.md`.
- Модель угроз и rollback boundary:
  `.\Development-WireGuard\docs\THREAT-MODEL-ROLLBACK.md`.
- Воспроизводимая локальная проверка:
  `.\Development-WireGuard\docs\LOCAL-VALIDATION.md`.
- Зафиксированный результат проверки:
  `.\Development-WireGuard\docs\VALIDATION-RESULT.md`.
- Машинная запись checkpoint:
  `.\Development-WireGuard\docs\DEVELOPMENT-CHECKPOINT-20260830.json`.
- Контрольные суммы передаваемого состояния:
  `.\Development-WireGuard\docs\DEVELOPMENT-CHECKPOINT-20260830.sha256`.
- Исходный код и тесты:
  `.\Development-WireGuard\src\wg_handshake_overlay` и
  `.\Development-WireGuard\tests`.

## Условие дальнейшего утверждения

Полной экспериментальной готовностью пакет можно считать только после
отдельно разрешённого изолированного прогона по `EVE-NG-TEST-CONTRACT.md` и
появления нового WireGuard checkpoint с schema-valid JSON evidence.

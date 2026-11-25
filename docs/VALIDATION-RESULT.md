# Результат локальной проверки

- Checkpoint: `candidate-trust-registry-20260903-01`
- Версия пакета: `wg-handshake-overlay 0.2.0`
- Время: `2026-09-03T13:32:04+03:00`
- Runtime: `Python 3.14.2`
- Проверка подписей: `OpenSSH_for_Windows_9.5p2`
- Команда: `pwsh -NoProfile -File scripts/validate-local.ps1`
- Результат: exit code `0`
- Unit tests: `25/25 OK`
- Trust-registry focus: `9/9 OK`
- Adapter focus: `5/5 OK`
- Модель: `27/27` соединений
- Python 3.11 syntax parse: `15/15` файлов
- Secret-pattern scan: `0` совпадений

Подтверждены два инварианта:

1. WG type 1/2/3 проходит через overlay, WG type 4 получает только
   `DIRECT_BYPASS` и принудительно отклоняется внутри overlay.
2. Ключ узла и маршрут нельзя получить из caller-supplied directory без
   валидного подписанного реестра. Подмена remote key, отсутствие/порча
   подписи, неизвестный signer, tampering, старая или равная version и
   повреждённый update отклоняются до `RouteCache.establish` и daemon send.

Valid higher-version update применяется атомарно; повреждённая active copy
восстанавливается из проверенной last-valid copy. Тестовые private signing
keys создавались только во временном каталоге и были удалены завершившимся
тестом.

Проверка была локальной и непривилегированной. Она не подтверждает kernel
WireGuard, capture/inject, nftables либо EVE-NG. На машине исполнен Python
3.14.2; совместимость с минимальным Python 3.11 проверена только парсером
синтаксиса, а не отдельным 3.11 runtime.

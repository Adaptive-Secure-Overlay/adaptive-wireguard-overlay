# Безопасность, границы и rollback

## Модель угроз

X1/X2 наблюдают транспорт overlay, но не получают ключи WireGuard: им доступны
только opaque blobs, служебные метаданные и соседний hop. Возможны malformed
или replay blob, попытка доставки не тому узлу, loop capture/inject, заполнение
очереди и потеря прямой линии A↔B. Недоступность data plane не разрешает
перенос type 4 через overlay: система завершает попытку fail-closed.

Отдельная угроза — caller-supplied каталог с подменённым remote public key.
Доверенный root не берётся из каталога: он закрепляется вне него. Missing/bad
signature, unknown signer, modification after signature, duplicate/equal/old
version, malformed update и unknown node отклоняются до route/key use.

## Обязательные меры

- Белый список `protocol == wireguard` и типов 1/2/3.
- Проверка размера, metadata, destination node и соответствия payload типу.
- Ограниченные очередь и TTL; при исчерпании — `DROP` с причиной.
- Reverse state ограничен по времени и `capture_id`.
- Anti-replay в overlay и loop-prevention при инжекте.
- Логи без payload, private key, PSK, паролей и полного конфиг-материала.
- При неопределённости служебный пакет не отправляется напрямую.
- Registry update подписан pinned Ed25519 root, имеет domain-bound SSHSIG
  namespace и строго возрастающую integer version.
- Active и last-valid copies обновляются через same-directory atomic replace;
  повреждённая копия восстанавливается только из другой валидной подписи.

## Rollback граница стенда

До привилегированного теста владелец имеет checkpoint изолированного стенда,
сохранённое исходное WG/firewall-состояние, проверенный ручной rollback и
доказательство scope правил на тестовый namespace/interface. При сбое он
останавливает именно свой тест, отменяет только одобренные временные правила,
восстанавливает checkpoint и прикладывает логи без секретов. Этот репозиторий
не выполняет автоматический rollback.

Локальный trust registry восстанавливает только свои файлы состояния; он не
меняет WG, firewall, интерфейсы или EVE-NG. Компрометация signing private key,
pinned root либо одновременное удаление обеих копий требует отдельного
операционного восстановления и не маскируется автоматическим fallback.

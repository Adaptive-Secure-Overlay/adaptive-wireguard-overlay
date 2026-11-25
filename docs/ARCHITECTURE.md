# Архитектура WireGuard handshake overlay

## Эквивалентность legacy

Legacy переносит через `A → X1 → X2 → B` только IKE, а ESP оставляет прямым.
WG-вариант переносит только WireGuard type 1/2/3; type 4 остаётся прямым.

```text
WG control:  A -> X1 -> X2 -> B
             A <- X1 <- X2 <- B
WG data:     A =============== B
```

Общими остаются route construction, hop sessions, opaque payload, reverse
route, TTL, anti-replay, privacy view и сценарный учёт. Не переносятся
strongSwan, UDP/500/4500, Non-ESP Marker, XFRM, ESP и charon injection.

## Компоненты локального пакета

- `parser.py` проверяет публичный WireGuard framing: type в первом байте,
  три нулевых reserved bytes, длины и открытые sender/receiver indexes.
- `trust_registry.py` проверяет подписанный каталог `node_id → WG public key`,
  монотонную версию и две атомарные локальные копии.
- `adapter.py` допускает в overlay только type 1/2/3, выдаёт daemon только ключ
  из текущего проверенного snapshot и повторно проверяет identity binding
  перед формированием безопасного `InjectionRequest`.
- `routing.py` хранит прямой и обратный маршруты с TTL и duplicate state;
  `AuthenticatedRoutePlanner` проверяет весь состав маршрута до вызова
  низкоуровневого `RouteCache.establish`.
- `engine.py` моделирует fail-closed forwarding без сокетов и команд ОС.
- `scenarios.py` воспроизводит логическую матрицу 27 соединений и выдаёт
  JSON/CSV доказательства локальной модели.

Полный `Route` — внутреннее состояние endpoint/orchestrator. Relay-visible
представление содержит только предыдущий и следующий hop; final endpoint в
privacy mode отсутствует. Реальная sealed-hop криптография остаётся функцией
существующего overlay core и не имитируется этим локальным reference model.

## Аутентифицированный реестр ключей

Доверенный корень — единственный OpenSSH Ed25519 public key и `key_id`,
закреплённые вне загружаемого каталога. Сам каталог не может заменить этот
корень. Подпись имеет формат SSHSIG и проверяется установленным OpenSSH
`ssh-keygen -Y verify` в отдельном namespace `wg-node-registry-v1`.
Собственная криптографическая реализация в Python отсутствует.

Подписывается только строгий объект:

```text
schema_version + registry_id + integer version + sorted node_id/public_key map
```

Канонические bytes формируются как UTF-8 JSON с отсортированными ключами,
без пробелов, NaN/Infinity, Unicode node identifiers и duplicate members.
WG public key обязан быть каноническим Base64 от 32 ненулевых bytes; один ключ
не может принадлежать двум node identifiers. Envelope допускает только
`sshsig-ed25519`, точный pinned `key_id` и ASCII-armored signature.

Обновление сначала полностью разбирается и проверяется в памяти. Под lock
повторно читается текущая версия; принимается только `new_version > current`.
Commit выполняется через временный файл в том же каталоге, `flush/fsync` и
`os.replace`. После commit тем же способом обновляется `registry.last-valid`.
При запуске обе копии проверяются, выбирается наибольшая валидная версия и
повреждённая или отставшая копия восстанавливается. Равные версии с разным
подписанным содержимым отклоняются fail-closed.

Порядок системной интеграции обязателен:

```text
signed registry verify/load
  -> resolve every route member
  -> compare any presented public-key directory
  -> AuthenticatedRoutePlanner.establish
  -> WgProxyAdapter gives daemon the verified destination public key
```

`RouteCache` и `HandshakeOverlayEngine` остаются key-free примитивами модели;
они не являются API выдачи public key. Интеграционный код, который связывает
node identity с ключом, обязан использовать `AuthenticatedRoutePlanner` и
`WgProxyAdapter` с одним загруженным `TrustedRegistryStore`.

Не реализованы online root rotation, threshold signatures и аппаратный
монотонный счётчик. Локальный attacker, способный одновременно удалить обе
копии state и заменить pinned root, находится вне этой границы; root и каталог
должны защищаться правами ОС и отдельным backup/checkpoint.

## Отделённый привилегированный backend

Перехват исходящих type 1/2/3, сохранение исходного IP/порта и инжект в kernel
WireGuard требуют отдельного Linux/EVE backend. Он намеренно не реализован и
не запускается в локальном пакете до ручного одобрения изолированного стенда.
Type 4 не может стать fallback-трафиком overlay ни при какой ошибке маршрута.

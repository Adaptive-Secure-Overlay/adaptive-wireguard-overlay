# Контракт интеграции WG-адаптера

Адаптер не строит маршрут и не содержит private keys WireGuard. Он получает
один уже загруженный `TrustedRegistryStore`, классифицирует датаграмму,
разрешает type 1/2/3 только для известных подписанных node identities и
передаёт daemon public key назначения исключительно из проверенного snapshot.

## Интерфейс общего daemon

```python
def send_protocol_datagram(
    *,
    protocol: str,
    peer_user: str,
    peer_public_key: str,
    payload: bytes,
    meta: dict[str, object],
) -> None:
    ...
```

Terminal delivery вызывает метод адаптера:

```python
def deliver_protocol_datagram(
    *,
    protocol: str,
    payload: bytes,
    meta: dict[str, object],
) -> InjectionRequest:
    ...
```

`protocol` строго равен `wireguard`; `peer_user` и `peer_public_key` берутся из
одной проверенной версии реестра. Caller может передать ожидаемый source/dst
public key, но любое отличие от подписанного binding даёт `DROP` до вызова
daemon. `meta` дополнительно содержит `registry_id`, `registry_version` и
fingerprints обоих bindings, но не private key и не полный каталог.

## Классификация

У WireGuard первый байт — message type, следующие три байта зарезервированы и
равны нулю. Type 1 — initiation, type 2 — response, type 3 — cookie reply,
type 4 — transport. Type 4 никогда не передаётся в daemon и никогда не
принимается terminal delivery.

Перед инжектом адаптер повторно проверяет framing, длину, тип, обязательные
metadata, соответствие `wg_message_type`, текущую registry version и оба
identity fingerprints. Ошибка означает `DROP`; прямого fallback для type 1/2/3
нет. Обновление registry во время полёта может отклонить пакет старой версии;
координация rollout является обязанностью будущего backend.

Route construction с public-key binding выполняется только через
`AuthenticatedRoutePlanner`: он разрешает все node IDs и сравнивает переданный
каталог до вызова `RouteCache.establish`. Direct `RouteCache` остаётся
низкоуровневой key-free моделью и не выдаёт ключи маршрутизатору.

Логи могут содержать `capture_id`, тип, длину и причину, но не raw datagram,
WG private key, PSK, пароль либо полный конфиг.
